/**
 * KYA-OS Entity Card — v1.1 profile helpers
 *
 * Reference helpers for the typed, DID-anchored entity card. See
 * `SPEC-ENTITY-CARD.md` and `schemas/kya-os-card.schema.json`. Three moves, each in a
 * focused submodule re-exported here:
 *   - buildCard   (./build):   EMIT this entity's card from its identity + declared facts.
 *   - emit        (./emit):    PROJECT the card onto every discovery rail (DID service entry,
 *                              MCP `_meta`, catalog, A2A extension, NANDA AgentFacts).
 *   - resolveCard (./resolve): DISCOVER another entity's card (multi-surface, via SafeFetch).
 *   - verifyCard  (./verify):  VERIFY the card's claims — RECOMPUTING the conformance
 *                              level rather than trusting whatever the card declares.
 *   - cimd        (./cimd):    BIND the L1 CIMD on-ramp — `client_id` ⇄ `did:web`, DID-keyed
 *                              JWKS, and the fail-closed origin/`alsoKnownAs` substitution graft.
 *   - proof       (./proof):   MINT + VERIFY the stateless per-request holder-of-key proof
 *                              (`org.kya-os/proof@1`) — sender-constrained, fail-closed.
 *   - delegation  (./delegation): VALIDATE the W3C VC 2.0 + ZCAP-LD delegation chain — CRISP
 *                              attenuation + continuity, `responsibleParty`/leaf-invoker, fail-closed.
 *   - builder     (./builder):  the fluent `card()` chain — the 10-minute path to a valid card.
 *   - middleware  (./middleware): `withKyaOsCard` (mount the discovery artifacts) + `requireProof`
 *                              (the per-request holder-of-key guard, 401-shaped on fail).
 *
 * All cryptographic verification is injected via pluggable seams (the same pattern
 * `validateLevel2` already uses for its `signatureVerifier`), so `@kya-os/mcp` stays
 * free of any runtime (mcp-i-core) dependency. The conformance LEVEL is derived in
 * `./verify`, never baked into a function name.
 *
 * The card shape is defined once as a zod schema in `./schema` (mirroring the
 * published `schemas/kya-os-card.schema.json`); types are `z.infer`-derived.
 */

export * from './schema.js';
export * from './build.js';
export * from './emit.js';
export * from './resolve.js';
export * from './verify.js';
export * from './cimd.js';
export * from './proof/index.js';
export * from './delegation.js';
export * from './builder.js';
export * from './middleware.js';
export * from './revocation.js';

// The SSRF-hardened fetch is the card's production wiring for resolveCard / status-list
// resolution — export it (and the address classifier) so consumers can actually reach it,
// not just the mocked-transport unit tests.
export {
  createSafeFetch,
  fetchTransport,
  isBlockedAddress,
  type SafeFetch,
  type SafeFetchOptions,
  type SafeFetchResponse,
  type SafeFetchTransport,
  type TransportInit,
  type DnsLookup,
  type DnsAddress,
} from '../utils/safe-fetch.js';
