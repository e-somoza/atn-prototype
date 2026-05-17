// Agent Trust Handshake (ATH) state machine
// Implements the four-message protocol: HELLO, OFFER, ACCEPT, RECEIPT
// Maps to §"The Agent Trust Handshake (ATH)" of the draft

import { KeyObject } from "node:crypto";
import { randomUUID } from "node:crypto";

import {
  AthAccept,
  AthArtifactRefs,
  AthHello,
  AthOffer,
  AthReject,
  Capability,
  CapabilityManifest,
  DelegationChain,
  NegotiatedScope,
  ProvenanceAttestation,
  SessionReceipt,
} from "./types.js";
import { intersectCapabilities } from "./intersection.js";
import { nonce, nowISO, sha256Prefixed, signJWS, verifyJWS } from "./crypto.js";

const SUPPORTED_VERSIONS = ["ath1"];

export interface AgentArtifacts {
  capabilityManifest: CapabilityManifest;
  delegationChain: DelegationChain;
  provenanceAttestation: ProvenanceAttestation;
}

export interface AgentIdentity {
  agentId: string; // stable identifier (key thumbprint)
  publicKey: KeyObject;
  privateKey: KeyObject;
  artifacts: AgentArtifacts;
}

function digestArtifact(obj: object): string {
  return sha256Prefixed(JSON.stringify(obj));
}

function artifactRefs(artifacts: AgentArtifacts): AthArtifactRefs {
  return {
    capability: {
      url: `https://example.com/.well-known/atn/capability/${artifacts.capabilityManifest.agent_id}.json`,
      digest: digestArtifact(artifacts.capabilityManifest),
    },
    delegation: {
      url: `https://example.com/.well-known/atn/delegation/${artifacts.delegationChain.agent_id}.json`,
      digest: digestArtifact(artifacts.delegationChain),
    },
    provenance: {
      url: `https://example.com/.well-known/atn/provenance/${artifacts.provenanceAttestation.agent_id}.json`,
      digest: digestArtifact(artifacts.provenanceAttestation),
    },
  };
}

export class Initiator {
  private hello?: AthHello;
  private offer?: AthOffer;

  constructor(public identity: AgentIdentity) {}

  buildHello(requestedCapabilityIds: string[], durationSeconds: number, purpose?: string): { hello: AthHello; signed: string } {
    const hello: AthHello = {
      v: "ath1",
      type: "hello",
      supported_versions: SUPPORTED_VERSIONS,
      initiator: {
        agent_id: this.identity.agentId,
        artifacts: artifactRefs(this.identity.artifacts),
      },
      requested_scope: {
        capability_ids: requestedCapabilityIds,
        duration_seconds: durationSeconds,
        purpose,
      },
      nonce: nonce(),
      timestamp: nowISO(),
    };
    this.hello = hello;
    return { hello, signed: signJWS(hello, this.identity.privateKey) };
  }

  receiveOffer(signedOffer: string, responderPublicKey: KeyObject): AthOffer | null {
    const offer = verifyJWS<AthOffer>(signedOffer, responderPublicKey);
    if (!offer || offer.type !== "offer") return null;
    if (!this.hello) return null;
    if (offer.in_reply_to_nonce !== this.hello.nonce) return null;
    // Downgrade-attack check: the signed offer must echo our supported_versions
    if (JSON.stringify(offer.supported_versions_echo) !== JSON.stringify(this.hello.supported_versions)) return null;
    if (!SUPPORTED_VERSIONS.includes(offer.selected_version)) return null;
    this.offer = offer;
    return offer;
  }

  buildAccept(): { accept: AthAccept; signed: string } | null {
    if (!this.offer) return null;
    const accept: AthAccept = {
      v: "ath1",
      type: "accept",
      agreed_scope: this.offer.offered_scope,
      nonce: nonce(),
      in_reply_to_nonce: this.offer.nonce,
      timestamp: nowISO(),
    };
    return { accept, signed: signJWS(accept, this.identity.privateKey) };
  }

  countersign(receipt: SessionReceipt): string {
    return signJWS(receipt, this.identity.privateKey);
  }
}

export class Responder {
  constructor(public identity: AgentIdentity) {}

  handleHello(
    signedHello: string,
    initiatorPublicKey: KeyObject,
    initiatorArtifacts: AgentArtifacts,
  ): { signed: string; offer: AthOffer } | { rejected: AthReject } {
    const hello = verifyJWS<AthHello>(signedHello, initiatorPublicKey);
    if (!hello || hello.type !== "hello") {
      return {
        rejected: {
          v: "ath1",
          type: "reject",
          error_code: "artifact_invalid",
          detail: "ATH_HELLO signature failed",
          in_reply_to_nonce: "unknown",
          timestamp: nowISO(),
        },
      };
    }

    // Version negotiation
    const common = hello.supported_versions.filter((v) => SUPPORTED_VERSIONS.includes(v));
    if (common.length === 0) {
      return {
        rejected: {
          v: "ath1",
          type: "reject",
          error_code: "version_mismatch",
          in_reply_to_nonce: hello.nonce,
          timestamp: nowISO(),
        },
      };
    }
    const selected = common.sort().reverse()[0];

    // Verify initiator artifact digests match what was advertised
    if (digestArtifact(initiatorArtifacts.capabilityManifest) !== hello.initiator.artifacts.capability.digest) {
      return {
        rejected: {
          v: "ath1",
          type: "reject",
          error_code: "artifact_invalid",
          detail: "capability manifest digest mismatch",
          in_reply_to_nonce: hello.nonce,
          timestamp: nowISO(),
        },
      };
    }

    // Filter responder's own capabilities to the IDs requested
    const responderCaps = this.identity.artifacts.capabilityManifest.capabilities.filter((c) =>
      hello.requested_scope.capability_ids.includes(c.id),
    );

    // Compute intersection
    const initiatorRequestedCaps = initiatorArtifacts.capabilityManifest.capabilities.filter((c) =>
      hello.requested_scope.capability_ids.includes(c.id),
    );

    const negotiated = intersectCapabilities({
      initiatorCapabilities: initiatorRequestedCaps,
      responderCapabilities: responderCaps,
      initiatorRefusals: initiatorArtifacts.capabilityManifest.refusals,
      responderRefusals: this.identity.artifacts.capabilityManifest.refusals,
    });

    if (negotiated.length === 0) {
      return {
        rejected: {
          v: "ath1",
          type: "reject",
          error_code: "scope_unsatisfiable",
          in_reply_to_nonce: hello.nonce,
          timestamp: nowISO(),
        },
      };
    }

    const offeredScope: NegotiatedScope = {
      capabilities: negotiated,
      duration_seconds: hello.requested_scope.duration_seconds,
      purpose: hello.requested_scope.purpose,
    };

    const offer: AthOffer = {
      v: "ath1",
      type: "offer",
      selected_version: selected,
      supported_versions_echo: hello.supported_versions,
      responder: {
        agent_id: this.identity.agentId,
        artifacts: artifactRefs(this.identity.artifacts),
      },
      offered_scope: offeredScope,
      nonce: nonce(),
      in_reply_to_nonce: hello.nonce,
      timestamp: nowISO(),
    };
    return { signed: signJWS(offer, this.identity.privateKey), offer };
  }

  handleAccept(
    signedAccept: string,
    initiatorPublicKey: KeyObject,
    initiatorId: string,
    initiatorArtifacts: AgentArtifacts,
  ): { signed: string; receipt: SessionReceipt } | null {
    const accept = verifyJWS<AthAccept>(signedAccept, initiatorPublicKey);
    if (!accept || accept.type !== "accept") return null;

    const now = new Date();
    const expires = new Date(now.getTime() + accept.agreed_scope.duration_seconds * 1000);

    const receipt: SessionReceipt = {
      v: "ath1",
      type: "receipt",
      session_id: randomUUID(),
      initiator_id: initiatorId,
      responder_id: this.identity.agentId,
      agreed_scope: accept.agreed_scope,
      artifact_digests: {
        initiator_capability: digestArtifact(initiatorArtifacts.capabilityManifest),
        initiator_delegation: digestArtifact(initiatorArtifacts.delegationChain),
        initiator_provenance: digestArtifact(initiatorArtifacts.provenanceAttestation),
        responder_capability: digestArtifact(this.identity.artifacts.capabilityManifest),
        responder_delegation: digestArtifact(this.identity.artifacts.delegationChain),
        responder_provenance: digestArtifact(this.identity.artifacts.provenanceAttestation),
      },
      issued_at: now.toISOString(),
      expires_at: expires.toISOString(),
    };

    return { signed: signJWS(receipt, this.identity.privateKey), receipt };
  }
}
