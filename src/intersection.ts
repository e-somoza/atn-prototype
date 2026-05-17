// Capability Intersection Algebra
// Implements the algorithm from §"Capability Intersection Algebra" of
// draft-somoza-atn-agent-trust-negotiation-00

import {
  Capability,
  Conditions,
  Effects,
  EFFECTS_ORDER,
  ExternalCalls,
  EXTERNAL_CALLS_ORDER,
  Persistence,
  PERSISTENCE_ORDER,
  Refusal,
  ResourceBounds,
  SubInvocations,
  SUB_INVOCATIONS_ORDER,
} from "./types.js";

function intersectLists(a: string[] = [], b: string[] = []): string[] {
  const setB = new Set(b);
  return a.filter((x) => setB.has(x));
}

function minNumeric(a: number | undefined, b: number | undefined): number | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return Math.min(a, b);
}

function parseRate(s: string | undefined): { count: number; window: string } | undefined {
  if (!s) return undefined;
  const m = s.match(/^(\d+)\/(\w+)$/);
  if (!m) return undefined;
  return { count: parseInt(m[1], 10), window: m[2] };
}

function intersectRateLimit(a: string | undefined, b: string | undefined): string | undefined {
  const pa = parseRate(a);
  const pb = parseRate(b);
  if (!pa) return b;
  if (!pb) return a;
  // For demo, require same window; production code normalizes
  if (pa.window !== pb.window) return undefined;
  return `${Math.min(pa.count, pb.count)}/${pa.window}`;
}

function intersectTimeWindow(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b) return a;
  // Demo: take string equality; production code parses and intersects
  return a === b ? a : undefined;
}

function intersectConditions(a: Conditions = {}, b: Conditions = {}): Conditions | undefined {
  const out: Conditions = {};
  const rate = intersectRateLimit(a.rate_limit, b.rate_limit);
  if (rate !== undefined) out.rate_limit = rate;

  const residency = intersectLists(a.data_residency, b.data_residency);
  if (a.data_residency || b.data_residency) {
    if (residency.length === 0) return undefined; // empty list drops capability
    out.data_residency = residency;
  }

  const tw = intersectTimeWindow(a.time_window, b.time_window);
  if (a.time_window || b.time_window) {
    if (tw === undefined) return undefined;
    out.time_window = tw;
  }

  const maxSize = minNumeric(a.max_response_size_bytes, b.max_response_size_bytes);
  if (maxSize !== undefined) out.max_response_size_bytes = maxSize;

  return out;
}

function mostRestrictive<T extends string>(a: T, b: T, ordering: T[]): T {
  const ai = ordering.indexOf(a);
  const bi = ordering.indexOf(b);
  if (ai === -1 || bi === -1) throw new Error(`Unknown value in ordering: ${a} or ${b}`);
  return ordering[Math.min(ai, bi)];
}

function intersectResourceBounds(a: ResourceBounds, b: ResourceBounds): ResourceBounds {
  return {
    max_tokens: minNumeric(a.max_tokens, b.max_tokens),
    max_duration_seconds: minNumeric(a.max_duration_seconds, b.max_duration_seconds),
    max_cost_usd: minNumeric(a.max_cost_usd, b.max_cost_usd),
  };
}

function unionPreconditions(a: Capability["preconditions"], b: Capability["preconditions"]) {
  if (!a) return b;
  if (!b) return a;
  return { ...a, ...b };
}

function refusalMatches(refusal: Refusal, cap: Capability): boolean {
  if (refusal.id && refusal.id === cap.id) return true;
  if (refusal.category) {
    // Loose match: refusal categories can match capability ids or schema-defined categories
    if (cap.id === refusal.category) return true;
  }
  return false;
}

function anyRefusalMatches(refusals: Refusal[], cap: Capability): boolean {
  return refusals.some((r) => refusalMatches(r, cap));
}

export interface IntersectionInputs {
  initiatorCapability: Capability;
  responderCapability: Capability;
  initiatorRefusals: Refusal[];
  responderRefusals: Refusal[];
}

export function intersectCapability(input: IntersectionInputs): Capability | null {
  const { initiatorCapability: A, responderCapability: B, initiatorRefusals, responderRefusals } = input;

  // Identity rule: same id, same schema (url + digest), no refusal match
  if (A.id !== B.id) return null;
  if (A.schema.url !== B.schema.url || A.schema.digest !== B.schema.digest) return null;
  if (anyRefusalMatches(initiatorRefusals, A)) return null;
  if (anyRefusalMatches(responderRefusals, B)) return null;

  // Per-dimension combinators
  const actions = intersectLists(A.actions, B.actions);
  if (actions.length === 0) return null;

  const resources = intersectLists(A.resources, B.resources);
  if (resources.length === 0) return null;

  const conditions = intersectConditions(A.conditions, B.conditions);
  if (conditions === undefined) return null; // empty residency or time-window mismatch drops

  return {
    id: A.id,
    schema: A.schema,
    actions,
    resources,
    conditions,
    effects: mostRestrictive<Effects>(A.effects, B.effects, EFFECTS_ORDER),
    external_calls: mostRestrictive<ExternalCalls>(A.external_calls, B.external_calls, EXTERNAL_CALLS_ORDER),
    sub_invocations: mostRestrictive<SubInvocations>(A.sub_invocations, B.sub_invocations, SUB_INVOCATIONS_ORDER),
    persistence: mostRestrictive<Persistence>(A.persistence, B.persistence, PERSISTENCE_ORDER),
    resource_bounds: intersectResourceBounds(A.resource_bounds, B.resource_bounds),
    preconditions: unionPreconditions(A.preconditions, B.preconditions),
  };
}

export interface ManifestIntersectionInputs {
  initiatorCapabilities: Capability[];
  responderCapabilities: Capability[];
  initiatorRefusals: Refusal[];
  responderRefusals: Refusal[];
}

export function intersectCapabilities(input: ManifestIntersectionInputs): Capability[] {
  const out: Capability[] = [];
  for (const initCap of input.initiatorCapabilities) {
    const respMatch = input.responderCapabilities.find(
      (r) => r.id === initCap.id && r.schema.url === initCap.schema.url && r.schema.digest === initCap.schema.digest,
    );
    if (!respMatch) continue;
    const intersected = intersectCapability({
      initiatorCapability: initCap,
      responderCapability: respMatch,
      initiatorRefusals: input.initiatorRefusals,
      responderRefusals: input.responderRefusals,
    });
    if (intersected) out.push(intersected);
  }
  return out;
}
