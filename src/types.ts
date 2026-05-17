// ATN reference types
// Maps to draft-somoza-atn-agent-trust-negotiation-00

export type Effects = "none" | "read_only" | "idempotent" | "mutating";
export type ExternalCalls = "forbidden" | "listed_only" | "free";
export type SubInvocations = "forbidden" | "same_scope" | "fresh_handshake_required";
export type Persistence = "none" | "session_only" | "durable";

// Orderings for "most restrictive wins" computations
export const EFFECTS_ORDER: Effects[] = ["none", "read_only", "idempotent", "mutating"];
export const EXTERNAL_CALLS_ORDER: ExternalCalls[] = ["forbidden", "listed_only", "free"];
export const SUB_INVOCATIONS_ORDER: SubInvocations[] = ["forbidden", "same_scope", "fresh_handshake_required"];
export const PERSISTENCE_ORDER: Persistence[] = ["none", "session_only", "durable"];

export interface SchemaRef {
  url: string;
  digest: string; // "sha256:..."
}

export interface ResourceBounds {
  max_tokens?: number;
  max_duration_seconds?: number;
  max_cost_usd?: number;
}

export interface Conditions {
  rate_limit?: string; // "N/min" or "N/sec"
  data_residency?: string[];
  time_window?: string; // "HH:MM-HH:MM UTC"
  max_response_size_bytes?: number;
  [k: string]: unknown; // schema-defined extensions
}

export interface Preconditions {
  counterparty_provenance?: "required" | "optional" | "forbidden";
  counterparty_delegation?: "required" | "optional" | "forbidden";
  transport?: string;
  human_approval?: "required" | "optional";
  approval_token_issuer?: string;
  [k: string]: unknown;
}

export interface Capability {
  id: string;
  schema: SchemaRef;
  actions: string[];
  resources: string[];
  conditions?: Conditions;
  effects: Effects;
  external_calls: ExternalCalls;
  sub_invocations: SubInvocations;
  persistence: Persistence;
  resource_bounds: ResourceBounds;
  preconditions?: Preconditions;
}

export interface Refusal {
  category?: string;
  id?: string;
  scope?: string;
}

export interface CapabilityManifest {
  v: "atn-capability-1";
  agent_id: string;
  issued_at: string;
  valid_until: string;
  capabilities: Capability[];
  refusals: Refusal[];
}

export interface DelegationLink {
  issuer: string;
  subject: string;
  scope: string[];
  issued_at: string;
  valid_until: string;
  revocation: string;
  signature: string; // JWS
}

export interface DelegationChain {
  v: "atn-delegation-1";
  agent_id: string;
  chain: DelegationLink[];
}

export interface ProvenanceAttestation {
  v: "atn-provenance-1";
  agent_id: string;
  build?: { predicateType: string; predicate: unknown };
  model?: { model_id: string; model_version_sha256: string; system_prompt_sha256?: string };
  runtime?: { evidence_type: "RATS"; evidence: unknown; verifier: string };
  issued_at: string;
  valid_until: string;
}

export interface SessionReceipt {
  v: "ath1";
  type: "receipt";
  session_id: string;
  initiator_id: string;
  responder_id: string;
  agreed_scope: NegotiatedScope;
  artifact_digests: Record<string, string>;
  scitt_log_pointer?: string;
  issued_at: string;
  expires_at: string;
}

// Negotiated scope after intersection
export interface NegotiatedScope {
  capabilities: Capability[];
  duration_seconds: number;
  purpose?: string;
}

// Handshake messages
export interface AthArtifactRefs {
  capability: { url: string; digest: string };
  delegation: { url: string; digest: string };
  provenance: { url: string; digest: string };
}

export interface AthHello {
  v: "ath1";
  type: "hello";
  supported_versions: string[];
  initiator: {
    agent_id: string;
    artifacts: AthArtifactRefs;
  };
  requested_scope: {
    capability_ids: string[];
    duration_seconds: number;
    purpose?: string;
  };
  nonce: string;
  timestamp: string;
}

export interface AthOffer {
  v: "ath1";
  type: "offer";
  selected_version: string;
  supported_versions_echo: string[]; // signed, prevents downgrade
  responder: {
    agent_id: string;
    artifacts: AthArtifactRefs;
  };
  offered_scope: NegotiatedScope;
  nonce: string;
  in_reply_to_nonce: string;
  timestamp: string;
}

export interface AthAccept {
  v: "ath1";
  type: "accept";
  agreed_scope: NegotiatedScope;
  nonce: string;
  in_reply_to_nonce: string;
  timestamp: string;
}

export interface AthReject {
  v: "ath1";
  type: "reject";
  error_code: "version_mismatch" | "scope_unsatisfiable" | "artifact_invalid" | "refusal_match";
  detail?: string;
  in_reply_to_nonce: string;
  timestamp: string;
}

// Signed envelope: a JWS over any of the above
export interface SignedEnvelope {
  payload: string; // base64url of JSON
  protected: string; // base64url of header
  signature: string; // base64url
}
