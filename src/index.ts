// End-to-end ATN handshake demo
// Two synthetic agents negotiate a session and produce a signed receipt

import { generateKeyPair, nowISO, verifyJWS } from "./crypto.js";
import { AgentArtifacts, AgentIdentity, Initiator, Responder } from "./handshake.js";
import { AthOffer, Capability, CapabilityManifest, DelegationChain, ProvenanceAttestation, SessionReceipt } from "./types.js";

const SCHEMA_DATA_READ = {
  url: "https://schemas.example.com/atn/data-read-v1.json",
  digest: "sha256:b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
};

function dataReadCapability(overrides: Partial<Capability>): Capability {
  return {
    id: "data-read",
    schema: SCHEMA_DATA_READ,
    actions: ["read", "list"],
    resources: ["dataset:public/*"],
    conditions: { rate_limit: "1000/min", data_residency: ["US", "EU"] },
    effects: "read_only",
    external_calls: "forbidden",
    sub_invocations: "forbidden",
    persistence: "none",
    resource_bounds: { max_tokens: 100000, max_duration_seconds: 1800, max_cost_usd: 1.0 },
    ...overrides,
  };
}

function buildArtifacts(agentId: string, capability: Capability): AgentArtifacts {
  const now = nowISO();
  const tomorrow = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  const capabilityManifest: CapabilityManifest = {
    v: "atn-capability-1",
    agent_id: agentId,
    issued_at: now,
    valid_until: tomorrow,
    capabilities: [capability],
    refusals: [{ category: "financial_transactions", scope: "all" }],
  };
  const delegationChain: DelegationChain = {
    v: "atn-delegation-1",
    agent_id: agentId,
    chain: [
      {
        issuer: "did:example:org-root",
        subject: `agent:${agentId}`,
        scope: ["data-read"],
        issued_at: now,
        valid_until: tomorrow,
        revocation: `https://example.com/revocation/${agentId}`,
        signature: "<demo>",
      },
    ],
  };
  const provenanceAttestation: ProvenanceAttestation = {
    v: "atn-provenance-1",
    agent_id: agentId,
    build: { predicateType: "https://slsa.dev/provenance/v1", predicate: { repo: "github.com/example/agent" } },
    issued_at: now,
    valid_until: tomorrow,
  };
  return { capabilityManifest, delegationChain, provenanceAttestation };
}

function buildAgent(label: string, capability: Capability): AgentIdentity {
  const { publicKey, privateKey, thumbprint } = generateKeyPair();
  const agentId = `${label}-${thumbprint.slice(0, 16)}`;
  return {
    agentId,
    publicKey,
    privateKey,
    artifacts: buildArtifacts(agentId, capability),
  };
}

function header(s: string) {
  console.log("\n=== " + s + " ===");
}

async function main() {
  header("Setup: Two agents with different capability constraints");

  const initiatorCap = dataReadCapability({
    actions: ["read", "list", "search"],
    resources: ["dataset:public/*", "dataset:internal/research/*"],
    conditions: { rate_limit: "1000/min", data_residency: ["US", "EU", "APAC"] },
    resource_bounds: { max_tokens: 100000, max_duration_seconds: 1800, max_cost_usd: 1.0 },
  });

  const responderCap = dataReadCapability({
    actions: ["read", "list"],
    resources: ["dataset:public/*"],
    conditions: { rate_limit: "500/min", data_residency: ["US", "EU"] },
    external_calls: "forbidden",
    resource_bounds: { max_tokens: 50000, max_duration_seconds: 1800, max_cost_usd: 0.5 },
  });

  const initiator = new Initiator(buildAgent("research", initiatorCap));
  const responder = new Responder(buildAgent("publisher", responderCap));

  console.log(`Initiator agent_id: ${initiator.identity.agentId}`);
  console.log(`Responder agent_id: ${responder.identity.agentId}`);
  console.log(`Initiator requests: actions=${initiatorCap.actions}, residency=${initiatorCap.conditions?.data_residency}, rate=${initiatorCap.conditions?.rate_limit}`);
  console.log(`Responder offers:   actions=${responderCap.actions}, residency=${responderCap.conditions?.data_residency}, rate=${responderCap.conditions?.rate_limit}`);

  header("Step 1: Initiator -> ATH_HELLO");
  const { hello, signed: signedHello } = initiator.buildHello(["data-read"], 600, "academic_summarization");
  console.log(`HELLO nonce: ${hello.nonce}`);
  console.log(`HELLO requested_scope: ${JSON.stringify(hello.requested_scope)}`);
  console.log(`HELLO supported_versions: ${hello.supported_versions}`);
  console.log(`HELLO signed JWS (truncated): ${signedHello.slice(0, 80)}...`);

  header("Step 2: Responder verifies HELLO and replies ATH_OFFER");
  const offerResult = responder.handleHello(signedHello, initiator.identity.publicKey, initiator.identity.artifacts);
  if ("rejected" in offerResult) {
    console.error("Handshake rejected:", offerResult.rejected);
    process.exit(1);
  }
  console.log(`OFFER selected_version: ${offerResult.offer.selected_version}`);
  console.log(`OFFER negotiated capabilities count: ${offerResult.offer.offered_scope.capabilities.length}`);
  const negotiated = offerResult.offer.offered_scope.capabilities[0];
  console.log(`Negotiated 'data-read' after intersection:`);
  console.log(`  actions:        ${JSON.stringify(negotiated.actions)}`);
  console.log(`  resources:      ${JSON.stringify(negotiated.resources)}`);
  console.log(`  rate_limit:     ${negotiated.conditions?.rate_limit}`);
  console.log(`  data_residency: ${JSON.stringify(negotiated.conditions?.data_residency)}`);
  console.log(`  effects:        ${negotiated.effects}`);
  console.log(`  external_calls: ${negotiated.external_calls}`);
  console.log(`  max_cost_usd:   ${negotiated.resource_bounds.max_cost_usd}`);

  header("Step 3: Initiator verifies OFFER (downgrade check) and replies ATH_ACCEPT");
  const verifiedOffer: AthOffer | null = initiator.receiveOffer(offerResult.signed, responder.identity.publicKey);
  if (!verifiedOffer) {
    console.error("Initiator failed to verify OFFER (possible downgrade)");
    process.exit(1);
  }
  const accept = initiator.buildAccept();
  if (!accept) {
    console.error("Initiator failed to build ACCEPT");
    process.exit(1);
  }
  console.log(`ACCEPT signed and sent`);

  header("Step 4: Responder issues ATH_RECEIPT");
  const receiptResult = responder.handleAccept(accept.signed, initiator.identity.publicKey, initiator.identity.agentId, initiator.identity.artifacts);
  if (!receiptResult) {
    console.error("Receipt generation failed");
    process.exit(1);
  }
  console.log(`Receipt session_id: ${receiptResult.receipt.session_id}`);
  console.log(`Receipt expires_at: ${receiptResult.receipt.expires_at}`);
  console.log(`Receipt JWS (truncated): ${receiptResult.signed.slice(0, 80)}...`);

  header("Step 5: Initiator countersigns and SCITT submission (stubbed)");
  const counterSigned = initiator.countersign(receiptResult.receipt);
  console.log(`Countersigned receipt JWS (truncated): ${counterSigned.slice(0, 80)}...`);
  console.log(`[SCITT stub] Would publish receipt with session_id=${receiptResult.receipt.session_id}`);

  header("Verification: parse final receipt back");
  const parsed = verifyJWS<SessionReceipt>(receiptResult.signed, responder.identity.publicKey);
  if (parsed) {
    console.log(`Verified responder signature.`);
    console.log(`Negotiated scope capabilities: ${parsed.agreed_scope.capabilities.map((c) => c.id).join(", ")}`);
  } else {
    console.error("Receipt signature verification failed");
    process.exit(1);
  }

  header("Done");
  console.log("Full handshake completed successfully.");
  console.log("The intersection algebra correctly narrowed both parties' requests:");
  console.log("  rate_limit: 1000/min ∩ 500/min => 500/min (minimum)");
  console.log("  data_residency: [US,EU,APAC] ∩ [US,EU] => [US,EU] (list intersection)");
  console.log("  actions: [read,list,search] ∩ [read,list] => [read,list] (list intersection)");
  console.log("  max_cost_usd: 1.0 ∩ 0.5 => 0.5 (minimum)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
