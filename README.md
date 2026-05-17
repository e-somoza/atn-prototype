# atn-prototype
  Reference prototype for Agent Trust Negotiation (ATN). Peer-to-peer trust handshake protocol for AI agents with capability negotiation, delegation, provenance, and SCITT-anchored receipts. Companion to IETF draft-somoza-atn-agent-trust-negotiation.
# ATN Reference Implementation (Prototype)

This is a reference prototype for the Agent Trust Negotiation protocol described in `draft-somoza-atn-agent-trust-negotiation-00`. It is not production code. It exists to demonstrate that the specification is implementable and that the capability intersection algebra and handshake state machine behave as specified.

## What this demonstrates

1. The four ATN artifacts as TypeScript types: Capability Manifest, Delegation Chain, Provenance Attestation, Session Receipt.
2. The capability intersection algorithm specified in the draft.
3. The four-message handshake: ATH_HELLO, ATH_OFFER, ATH_ACCEPT, ATH_RECEIPT.
4. Ed25519 signing and verification of artifacts and messages.
5. Digest binding between artifact references and document content.
6. Refusal override semantics.

## What this does NOT demonstrate

1. Real DNS resolution (stubbed).
2. Real HTTPS fetches of artifacts (stubbed; artifacts passed in-memory).
3. SCITT log submission (stubbed; logged to stdout).
4. Full RATS integration (only the artifact structure).
5. Production error handling, retries, rate limits.

## How to run

Requires Node.js 20 or later.

```
npm install
npm start
```

Output shows a complete handshake between two synthetic agents with mismatched capability requests, demonstrates that the intersection algorithm narrows the scope correctly, and prints a signed Session Receipt.

## Files

- `src/types.ts`: type definitions for all ATN artifacts and messages.
- `src/crypto.ts`: Ed25519 key generation, JWS signing, JWS verification, SHA-256 digest.
- `src/intersection.ts`: the capability intersection algebra from Section 9 of the draft.
- `src/handshake.ts`: the Initiator and Responder state machines.
- `src/index.ts`: end-to-end demo.

## Mapping to the specification

| Draft section | File |
|---|---|
| Capability Manifest (§ Capability Manifest) | `types.ts`, `intersection.ts` |
| Delegation Chain (§ Delegation Chain) | `types.ts` |
| Provenance Attestation (§ Provenance Attestation) | `types.ts` |
| Session Receipt (§ ATH_RECEIPT) | `types.ts`, `handshake.ts` |
| Capability Intersection Algebra | `intersection.ts` |
| ATH state machine | `handshake.ts` |
| Algorithm: Ed25519 default | `crypto.ts` |

## License

CC0 1.0 Universal. Public domain. Use freely.
