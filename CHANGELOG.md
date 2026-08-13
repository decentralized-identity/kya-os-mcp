# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- **Multibase verification-method keys.** Both delegation signature paths
  (Data Integrity and VC-JWT) now accept verification methods that publish
  `publicKeyMultibase` (base58btc Ed25519, with or without the 0xed01
  multicodec prefix) or legacy `publicKeyBase58`, synthesizing the OKP JWK at
  the point of use — did:cheqd issuers verify end-to-end without a
  JWK-rewriting resolver. Fail-closed: anything not provably a 32-byte
  Ed25519 key still denies.
- **`StatusListCredential` DLR artifact type.** `prepareCheqdDlrResource`
  now anchors status lists: the artifact's `content` is the WHOLE SIGNED
  StatusList2021 credential (hash-what-you-publish — the canonical bytes
  anchored on-chain are exactly the credential a verifier fetches), so
  content hashes remain byte-compatible with resources already anchored via
  the DEF CON demo's vendored publisher. Anchor-fitness is enforced by the
  new method-agnostic `assertAnchorableStatusListCredential` guard in
  `utils/statuslist-bits` (refuses unsigned or bitstring-less lists).

### Changed

- **Status-list reading mechanics consolidated into `utils/statuslist-bits`.**
  Canonical index parsing, the 16 MiB inflation cap, multibase/base64url
  payload decoding, and the MSB-first bit read previously existed as separate
  copies in the delegation readers (`bitstring.ts`, `statuslist-manager.ts`)
  and the card revocation reader (`card/revocation.ts`) — held in sync only by
  source comments. One shared implementation now serves both seams; each
  seam's policy (throw → `status_unresolvable` vs `FAIL_CLOSED`, freshness)
  is unchanged. Behavior-preserving: every existing test passes unmodified.

### Deprecated

- **`RevocationChecker` (card module).** Renamed to
  `BitstringRevocationChecker` — the old name collided with the
  delegation-side `RevocationChecker` interface (`chain-enforcement.ts`), two
  identically named exports answering different questions. The old name
  remains as a deprecated alias until 2.0.

## [1.13.0] - 2026-08-12

### Security

- **Delegation verifier: revocation status and expiry are now evaluated on
  every verification.** The per-instance cache previously stored the entire
  verdict for `cacheTtl` (default 60 s), so a cache hit skipped the
  credential-status check — a revoked credential kept verifying (and, on the
  Data Integrity path, an expired one) until the entry lapsed. The cache now
  holds only the signature/DID-validity result; basic checks and revocation
  status run on every call, with signature and status still checked in
  parallel. Warm-path latency now includes one status read — freshness policy
  belongs in your `StatusListResolver`, never in the verdict. The `cached`
  result flag now means "signature served from cache".

### Added

- **`withStatusCache(resolver, { maxStalenessMs, maxEntries? })`** — wraps any
  `StatusListResolver` to cache status *bits* for an explicitly declared
  staleness bound: the deployment names its revocation SLA instead of
  inheriting a silent verdict cache. Throws are never cached (fail-closed
  retry); `maxStalenessMs: 0` is a pass-through.
- **`delegation.verificationCache` middleware config** (`{ ttlMs, maxEntries }`)
  tuning the signature-verification cache; `ttlMs: 0` disables signature
  caching (immediate issuer key-rotation pickup). Constructor `cacheTtl: 0`
  is now honored (`??`, previously swallowed by `||`), and
  `createDelegationVerifier` gains `maxCacheSize` parity.

## [1.12.0] - 2026-08-04

### Added

- **MCP `2026-07-28` extension binding: `org.kya-os/decentralized-authority`.**
  Per-request admission via `requireExtension`, capability declaration via
  `buildExtensionsEntry`, and a hand-rolled `server/discover` advertisement
  (SEP-2133). Required mode rejects a non-declaring client with the core
  `-32021` error carrying the `requiredCapabilities` member; discovery and ping
  are exempt from the gate.
- **Audit operator read/replay contract and a reference recorder.**

### Changed

- **Terminal proof-key naming.** Role-named `_meta` carriers
  `org.kya-os/request-proof` and `org.kya-os/response-proof`, with the profile
  version carried in the `org.kya-os/proof.v1` profile id. The legacy keys and
  `prf` value (`org.kya-os/proof@1`, `org.kya-os/proof`) are read-accepted for
  one major version, so existing producers and verifiers keep working.

## [1.11.0] - 2026-07-22

### Added

- **Verifiable auditability protocol and `@kya-os/mcp/audit`.** Adds strict,
  versioned, privacy-minimal events; an authoritative recorder with signed
  append receipts, atomic compare-and-append, logical-ledger idempotency, and
  epoch transitions; producer delivery modes and source high-water evidence;
  RFC 9162 Merkle checkpoints, inclusion/consistency proofs, independent
  observation, and supporting anchors; encrypted evidence lifecycle; pure
  historical verification; signed replay bundles; rebuildable projections; and
  the `kya-audit` offline verification CLI.
- **Provider contract kit.** `@kya-os/mcp/audit/testing` supplies executable,
  framework-neutral journal, evidence, observer, and anchor contracts. Memory
  reference providers cover concurrency, stale heads, duplicates, snapshots,
  legal holds, disposal, observation conflicts, and role separation.
- **MCP audit instrumentation and capability discovery.** Typed lifecycle events
  cover calls, errors, denials, step-up/authorization challenges, handshake
  rejection, replay rejection, consent/credential/key/config/policy changes,
  checkpoints, evidence, projections, exports, retention, and administration.
- **Audit schemas and conformance.** Publishes JSON Schemas for all portable
  audit artifacts, an `audit-integrity` vector category, independent Python
  verification of audit JCS/domain-separated hashes/RFC 9162 proofs, an
  end-to-end walkthrough, and the normative `AUDITABILITY.md` operations guide.

### Fixed

- **Entity Card spec corrections from working-group review.** Three defects raised
  against SPEC-ENTITY-CARD.md are resolved. (1) The Status section said the
  `org.kya-os/proof@1` and legacy proofs share one `_meta` key discriminated by
  `prf`; they ride separate keys (`org.kya-os/proof@1` vs `org.kya-os/proof`), as
  §8.1 and the implementation always had it, and the Status text now matches.
  (2) §8.3 now specifies the exact pre-signing transformation for `requestHash`:
  the `_meta` member of `params` (the proof's own carrier) is removed before JCS
  canonicalization, on both the mint and verify sides. Without that rule the
  definition was circular for MCP requests, where the proof travels inside
  `params._meta`. (3) Terminology now distinguishes the self-contained proof
  object from stateful replay prevention: a verifier still needs a nonce store
  and fails closed (`nonce_seam_missing`) without one, so the spec no longer
  describes verification as stateless.
- **`computeRequestHash` applies the §8.3 transformation itself.** The card
  hasher removes `params._meta` before canonicalizing, so a verifier handed the
  raw inbound request (proof still attached) recomputes the hash the minter
  signed instead of failing on a self-referential body. Requests without
  `params._meta` hash byte-identically to before; all golden vectors are
  unchanged.
- Historical proof verification no longer consumes live nonce state or applies
  present-time freshness rules, and protected JWS `kid` values are bound to the
  expected verification key.
- Failed child-delegation registration can no longer leave an orphan graph node,
  and cached VC results cannot be reused across differing trust/status inputs.

### Changed

- **SPEC-ENTITY-CARD.md editorial pass.** Tightened the abstract and framing
  sections, replaced em dashes with plain punctuation throughout, clarified that
  a declared capability name conveys no authority (authority travels only in the
  delegation chain), noted that a verifying resource should assert itself as the
  expected `invocationTarget` when evaluating a chain, and updated the
  reference-implementation version pointer.
- **The delegation profile moved into the core specification's delegation
  chapter.** Working-group review made the case that an extended description of
  delegation does not belong in the Entity Card specification: the card asserts
  locators, so the card document should point at the delegation profile rather
  than contain it. SPEC-ENTITY-CARD.md section 10 is now a compact section
  holding only what card verification consumes directly (the two recomputed
  accountability equalities, the meaning of the `revocation` field, and the
  KYC/KYB surface). The full profile (the VC 2.0 + ZCAP-LD credential shape,
  delegate rules, attenuation invariants, Bitstring revocation mechanics, and
  the KYC/KYB shape) now lives in SPEC.md section 6.10, beside the legacy
  credential shape it succeeds, so delegation has one home. The chain
  attenuation rules are now called attenuation invariants to end a naming
  collision with the CRISP constraint envelope of SPEC.md section 6.3. Content
  moved verbatim; wire shapes, schemas, and all other section numbering are
  unchanged, and every cross-reference was updated. A candidate card field
  naming the access-control mechanisms an entity supports is recorded as an
  open coordination item (section 15.7).
- Proof generation now uses a fresh cryptographic nonce for every proof artifact
  while preserving the session nonce as session-establishment evidence.
- Canonical JSON handling is shared and strict RFC 8785, rejecting unsafe
  integers, cycles, sparse arrays, accessors, and unsupported values before
  hashing or signing.
- Delegation graph registration supports atomic parent validation, status-list
  history is retained for historical decisions, and VC verification cache keys
  bind all decision inputs.
- Replayed handshake nonces now report the precise `nonce_replay` protocol code,
  allowing audit instrumentation to classify replay rejection independently.

## [1.10.1] - 2026-07-08

### Fixed

- **Cloudflare Worker / workerd bundle compatibility.** `safe-fetch-transports`
  statically imported `node:dns/promises` and `node:https` at the module top
  level, so anything that builds a `SafeFetch` — including the Entity Card /
  VC-JWT verification path (card resolution + status-list revocation) — required
  those node built-ins at bundle time and broke workerd builds. They now load
  **lazily** (only when a node code path actually runs), so the module bundles
  cleanly for workerd / browser. `selectDefaultTransport` transparently falls
  back to `fetchTransport` where `node:https` is absent. The SSRF policy
  (resolve-and-pin, private-range denial, redirect + size + timeout guards) is
  unchanged; a Worker injects its own DNS seam (or uses trusted origins +
  `fetchTransport`) to avoid `node:dns` at runtime.

## [1.10.0] - 2026-07-08

### Added

- **`ProofGenerator` accepts a non-extractable signing key.**
  `ProofAgentIdentity.privateKey` and `KyaOsIdentityConfig.privateKey` now
  accept a `CryptoKey` handle in addition to a base64 private-key string. A
  non-extractable WebCrypto key (e.g. a passkey-PRF-derived or HSM/KMS-fronted
  key) can now produce `org.kya-os/proof` proofs without the secret ever being
  materialized by the caller — realizing the signer-hook model the spec already
  describes (§4.5) — end-to-end through `withKyaOs`. Both key forms yield an
  equally valid, verifier-accepted proof. Backward-compatible: existing string
  keys are unaffected (the string path is byte-for-byte unchanged); the only
  source-level impact is that external code which reads `.privateKey` expecting
  a `string` now sees a `string | CryptoKey` union.

## [1.9.0] - 2026-07-07

Entity Card (`@kya-os/mcp/card`) — a typed, DID-anchored, per-request
holder-of-key identity layer that rides existing rails (MCP server-card `_meta`,
A2A extension, NANDA AgentFacts) instead of a new well-known doc. Additive.

First npm release since 1.7.0 (the prepared 1.8.0 was never published). See the
BREAKING status-list note below — persisted 1.x status lists MUST be
regenerated on upgrade.

### Added

- **`./card`** — the `card()` builder, `withKyaOsCard` / `requireProof`
  middleware, and `buildCard` / `resolveCard` / `verifyCard`. Conformance is
  recomputed on verify, never self-claimed.
- **Stateless proof (`org.kya-os/proof@1`)** and a **VC 2.0 / ZCAP-LD**
  delegation profile with Bitstring Status List v1.0 revocation. Both run
  alongside the legacy session proof + delegation for all of 1.x; the legacy
  paths drop at 2.0.
- **CIMD L1 on-ramp** — `client_id ⇄ did:web`, so an OAuth `private_key_jwt`
  doubles as a DID-key proof (RFC 9449 `cnf.jkt` sender-constrains it).
- Conformance vectors + a cross-language verifier folded into the existing
  `conformance/` harness (new `card-proof` / `entity-card` categories).
- **Proof crypto agility (`ES256`)** — the per-request proof now accepts an
  ALLOW-LIST of two signing algorithms, `EdDSA` (Ed25519) and `ES256` (ECDSA
  P-256, FIPS-eligible via HSM/KMS), never negotiated. `alg` is a signed covered
  claim and the resolved key type MUST match it (`alg_key_mismatch`), so adding a
  second curve introduces no algorithm-confusion surface. `es256SignerFromJwk`
  ships alongside `ed25519SignerFromJwk`; the RFC 9421 sibling carries the
  matching `ecdsa-p256-sha256` label. (CIMD DID-keyed JWKS extraction stays
  Ed25519-only for now — a P-256 verifier supplies its own `resolveDidKeys`.)
- **VC-JWT verification (`./delegation`)** — `DelegationCredentialVerifier.verifyDelegationJwt()`
  verifies the JWT serialization of a Verifiable Credential (compact JWS, where
  the envelope signature over `header.payload` IS the proof — no embedded
  `proof` block), so credentials minted by browser / passkey wallets verify
  without a hand-rolled path. `algorithms` is pinned to `EdDSA`, and the
  credential `issuer` must equal the signed `iss`. Additive; the Data Integrity
  path is unchanged.
- **Multi-key did:web documents** — `buildDidWebDocument` now accepts
  `Identity | Identity[]`, emitting one verification method per key under a
  single controller DID. This is the basis for multi-device identity: a device
  is added or removed by adding or removing a verification method, and a
  verifier selects the signing key by `kid`. Backward-compatible — a lone
  identity yields the same single-method document as before.

### Changed — BREAKING for persisted status lists

- **Status-list bit order corrected to W3C MSB-first.** `BitstringManager`
  (StatusList2021 / Bitstring Status List) now reads and writes bits
  most-significant-first (`0x80 >> i`), matching the W3C spec and the Digital
  Bazaar reference — and the Entity Card revocation reader — so both code paths
  read an identical `encodedList` to the same verdict. The prior LSB-first order
  was self-consistent but non-interoperable with any standard tool.
  - **⚠️ MIGRATION — READ THIS.** A status list generated by a 1.x release is
    encoded LSB-first. Read by this release it is **misread silently**: a
    **revoked credential can read as LIVE** (the bit mirrors within its byte, so
    e.g. revoked index 42 → clear, and phantom index 45 → revoked). The W3C
    credential carries no bit-order/version field, so old lists **cannot be
    auto-detected**. You MUST **regenerate every persisted status list** on
    upgrade; do not read 1.x-encoded lists with this release. (Tracking a
    KYA-OS-side encoding-version marker + a bit-reverse migration helper as a
    follow-up so future changes are detectable.)
- **Fail-closed hardening.** `isIndexSet` / `BitstringManager.getBit` now throw
  on an out-of-range or `NaN` index (were fail-open), `BitstringManager.decode`
  caps the inflated bitstring at 16 MiB (decompression-bomb guard), and the card
  `statusListIndex` must be a canonical decimal (a whitespace/hex value no longer
  silently reads bit 0). IPv6 NAT64 / 6to4 / Teredo / site-local addresses are
  now treated as non-public by the SSRF guard.

## [1.7.0] - 2026-06-17

Durable consent persistence. Pluggable `GrantStore` / `PendingFlowStore` /
`SessionStore` seams so consent, grant, and PKCE state survive restarts and
resolve across load-balanced instances — the holder-of-key (`getByAgent`)
no-paste retry, with session-bearer (`getBySession`) as a fallback. The detached
proof is namespaced under `_meta["org.kya-os/proof"]` and still dual-emitted
under the legacy bare key (ON for all of 1.x, dropped at 2.0). Additive over
1.6.x, with one documented behavioral change: a `strict` verifier now ignores
MCP-reserved foreign `_meta` keys instead of rejecting them.

### Added

- **Durable consent persistence (optional, in-memory defaults — no breaking
  change).** New pluggable seams so consent / grant / PKCE state survives
  restarts and resolves across load-balanced instances: `grantStore` (the
  no-paste retry — holder-of-key `getByAgent` first, then session-bearer
  `getBySession`), `PendingFlowStore` (durable OAuth/OIDC PKCE state with an
  atomic `consume()`), and an optional `SessionStore`. The detached proof is now
  namespaced under `_meta["org.kya-os/proof"]`; the legacy bare `proof` key is
  still accepted on verify and (by default) still emitted — toggle with
  `emitLegacyProofKey`. The legacy mirror stays **ON by default for the entire
  1.x line** (a pre-1.1 reader of bare `_meta.proof` would otherwise silently get
  no proof; the cost is ~1.5 KB of `_meta`, which is outside the response hash)
  and will be **dropped at 2.0**.

### Changed

- **BEHAVIORAL — `strict` `metaPolicy` now IGNORES foreign `_meta` keys instead
  of rejecting them.** Previously a `strict` verifier rejected any `_meta` key
  other than the proof. Under MCP 2026-07-28 (SEP-414) `_meta` legitimately
  carries reserved `io.modelcontextprotocol/*` and W3C trace-context keys
  (`traceparent`/`tracestate`/`baggage`), so `strict` now ignores every
  non-KYA-OS key (never hashed, trusted, or rejected) and `allow-extensions`
  additionally surfaces them. The zero-trust boundary is unchanged — only the
  KYA-OS proof key is ever hashed or trusted. **Migration:** anyone relying on
  `strict` to REJECT foreign `_meta` keys must now enforce that themselves; the
  verifier no longer fails on them.

### Fixed

- **Appendix A error codes corrected** to match `src/errors.ts`, the single
  source of truth. The table listed prefixed codes (`KYA_OS_EHANDSHAKE`,
  `KYA_OS_EPROOF`, ...) that no part of the codebase emits; the runtime,
  middleware, and session manager all return bare snake_case codes
  (`handshake_failed`, `invalid_proof`, ...). Documentation only — no behaviour
  change.

## [1.6.1] - 2026-06-10

Releases the schema-host migration already merged on `main` (it was unshipped:
`1.6.0` still carried the prior host). Schema-only; no code or API changes.

### Changed

- **Schema `$id` and JSON-LD `@context` hosts migrated** to the DIF-registered
  `schema.kya-os.org` — now live. All five shipped JSON Schemas
  (`schemas/*.json`), the spec's context references, and the
  `DELEGATION_CREDENTIAL_CONTEXT` constant resolve under `schema.kya-os.org`.
  The prior `schema.kya-os.ai` host served the same documents during the
  migration window; no `$id` is 301-redirected. Consumers that pinned a
  `schema.kya-os.ai` `$id` should update to `schema.kya-os.org`.

## [1.6.0] - 2026-06-03

Advances the E3 verifier-consolidation groundwork and hardens the delegation
gate: an isomorphic WebCrypto provider so the proof verifier can run on edge
runtimes without `node:crypto`, the delegation chain-enforcement rules lifted
into a framework-agnostic core reusable by any host, and holder-of-key binding
enforced at the inbound gate. Additive over 1.5.x.

### Added

- `./authz` authorization seam: a neutral, method-agnostic
  `AuthorizationServerAdapter` port with a shared dispatch predicate, an
  `AuthorizationServerRegistry` that routes a tool's protection to one adapter,
  and a generic-OIDC reference adapter under `authz/oidc/` (mandatory S256 PKCE,
  RFC 8707 resource binding, injectable fetch seam — no named vendor IdP, per
  the donation's vendor-neutrality). The `AuthorizationRequirement` union
  (`oauth`/`mdl`/`idv`/`credential`/`none`) anticipates further adapters as
  siblings of `oidc/`.
- `AccountabilityContext` projection (agent → accountable-admin → user →
  intent) that feeds the policy principal's `responsibleParty`; `orgRootDid` is
  a forward-compatible slot pending the organization root identity.
- A deterministic, network-free in-memory OIDC example exercising the full
  authorization path. Additive; no new runtime dependency (zod, jose, Web
  Crypto only).
- `GrantStore` provider + `MemoryGrantStore` reference implementation: the
  post-approval counterpart to `ResumeTokenStore`. A grant binds to the agent
  DID (durable authority) and optionally to a session (the confused-deputy-safe,
  no-paste retry convenience — a grant bound to one session is never returned to
  another). Soft revocation, TTL cleanup, lookup by agent or session. The memory
  impl is the dev/reference store; production injects Redis / a Durable Object /
  a database behind the same interface (mirroring `NonceCacheProvider`).
- **Holder-of-key binding** at the inbound gate (spec §11.8). A delegation
  credential is a bearer token, so the caller must now prove possession of the
  delegation subject's key on the request itself. For a `did:key` subject the
  DID encodes the public key, so binding needs no new credential fields and no
  new crypto: `assertHolderBinding` verifies the request proof against the key
  derived from the subject DID — a stolen-credential replay fails signature
  binding, a tampered request fails content binding, and a proof minted for
  another server fails audience binding (RFC 8707). The client half
  (`generateRequestProof`, request-only with a fresh nonce per call) and the PEP
  half (`assertHolderBinding`) ship in `delegation/holder-binding`. Opt-in.
- Framework-agnostic delegation **chain-enforcement core**
  (`validateDelegationChain`, with the injected `DelegationCredentialVerifierPort`
  and `RevocationChecker` ports, plus `validateScopeAttenuation` /
  `getDelegationScopes`), lifted out of the `with-kya-os` middleware closure so
  the leaf→root chain walk, scope attenuation, audience / confused-deputy
  binding (§11.6), and ancestor-revocation rules run identically in any host
  (MCP middleware, an HTTP PEP, the conformance harness) instead of a
  per-transport fork. Dependencies are injected as ports; nothing imports a
  transport. Includes the correctness fix behind the new graph-backed
  `RevocationChecker` (reference adapter `CascadingRevocationManager`): a
  cascade-revoked ancestor is now caught even when the leaf's own StatusList bit
  never flipped. Exported from `@kya-os/mcp/delegation`.
- `NoopFetchProvider` — the offline `FetchProvider` fallback (used when the
  runtime exposes no global `fetch`) extracted from an inline literal into a
  named, exported class alongside `RuntimeFetchProvider`, and reused at the
  holder-binding gate.
- `WebCryptoProvider` — an isomorphic `CryptoProvider` backed by the WebCrypto
  API (`globalThis.crypto.subtle`, Ed25519), so an edge runtime (Cloudflare
  Workers, Deno, browsers, Node 20+) can drive `ProofVerifier` without
  `node:crypto`. Mirrors `NodeCryptoProvider`'s key formats exactly — raw
  32-byte Ed25519 keys, base64-encoded; `sha256:<hex>` digests — so the two are
  drop-in interchangeable: a proof signed under one verifies under the other,
  with byte-identical signatures. Exported from `@kya-os/mcp/providers`.

## [1.5.0] - 2026-06-01

Exposes the policy-request projection as a reusable primitive and adds a
dedicated `./policy` entry point, so hosts beyond the bundled middleware (for
example a gateway) can build a `PolicyRequest` from their own resolved facts
without copying internal logic. Additive over 1.4.x.

### Added

- **`buildPolicyRequest(input)` projection helper.** Pure, transport-agnostic
  assembly of resolved facts — principal, delegated scopes, risk, scope-match,
  and optional approvals / budget — into the canonical `PolicyRequest` a
  `PolicyEngine` evaluates. Lets any host present an identical request contract
  to the engine instead of re-deriving the shape.
- **`./policy` subpath export.** The policy seam (`PolicyRequest`,
  `PolicyDecision`, `PolicyEngine`, `DefaultPolicyEngine`, `RiskClassifier`,
  `buildPolicyRequest`) is now importable directly from `@kya-os/mcp/policy`,
  alongside the existing re-export from the package root.

### Changed

- The bundled per-action policy gate now builds its `PolicyRequest` via
  `buildPolicyRequest` rather than an inline literal. No behavior change.

## [1.4.0] - 2026-05-31

Ports the KYA-OS authorization primitives developed upstream (xmcp-i) into
`@kya-os/mcp`: a per-action policy / step-up gate, scope-matcher enforcement,
signed `needs_authorization` challenges with verifier content binding, and
shipped runtime providers. Additive over 1.3.x except where noted under
**Changed** and **Removed**.

### Added

- **Signed `needs_authorization` challenge.** The delegation challenge returned
  when a protected tool is invoked without a credential now carries a signed
  detached-JWS proof in `_meta` (`outcome: 'needs_authorization'`). The proof
  binds a `responseHash` over the challenge content — including the
  `authorizationUrl`. A verifier that recomputes the response hash over the
  content it received — via the new `ProofVerifier` content binding (below) —
  detects a tampered / MITM-swapped consent URL; the signature alone proves
  authenticity, not content-match. The challenge content/shape is unchanged; attachment
  is best-effort (no-ops when no session can be resolved). The proof `outcome`
  enum widened to include `'needs_authorization'` across `ProofMeta`,
  `ProofOptions`, `validateDetachedProof`, and the `detached-proof` JSON Schema.
  Success proofs are byte-identical (unaffected).
- **`wrapWithDelegation` `formatChallenge` hook.** An optional config callback
  that renders the `needs_authorization` challenge content (e.g. a clickable
  markdown consent link for LLM / chat-style MCP clients) **before** the proof is
  signed — so the challenge `responseHash` binds exactly what the client
  receives, keeping the `authorizationUrl` tamper-evident regardless of
  presentation. Defaults to the structured JSON challenge. The consent-basic /
  consent-full examples now render their consent link via this hook instead of
  rewriting the response after signing (which had left the proof bound to stale
  content).
- **`ProofVerifier` content binding.** `verifyProof(proof, jwk, { request, response })`
  recomputes `requestHash`/`responseHash` over the request/response the verifier
  actually received — via a shared `computeCanonicalHashes` (single source of
  truth with the signer, so they can't drift) — and fails `CONTENT_BINDING_MISMATCH`
  on divergence. This is what realizes substitution detection (the signed
  challenge's anti-MITM, and content-binding for any proof); the signature alone
  proves only authenticity. New `CONTENT_BINDING_MISMATCH` proof-verification
  error code.
- **Concrete `SystemClockProvider` + `RuntimeFetchProvider`.** The package now
  ships a wall-clock `ClockProvider` and a network-capable `FetchProvider`
  (did:key resolved locally, did:web over HTTPS, StatusList2021 fetch) so a
  consumer no longer hand-rolls them to drive `ProofVerifier`. `RuntimeFetchProvider`
  is the default the middleware uses and replaces the prior internal stub (whose
  `resolveDID` returned `null`); it refuses private-network targets by default
  (see **Security**). The verify-proof / anti-MITM examples now consume both.
- **Per-action policy / step-up gate (`withPolicyGate`).** A new opt-in
  middleware wrapper that classifies an action's risk (reversibility, blast
  radius, severity) and consults a pluggable Policy-as-Code `PolicyEngine`:
  `allow` runs the handler, `deny` returns a `policy_denied` error, and
  `step_up` returns a `needs_approval` error until N-of-M signed `ApprovalGrant`s
  — each bound to the request hash (TOCTOU-safe) — are supplied. Ships a
  fail-closed `DefaultPolicyEngine` and a built-in `RiskClassifier`; OPA/Rego and
  Cedar adapters are intended follow-ups. Composes after `wrapWithDelegation`;
  no behavior change unless adopted.
- **`PolicyEngine` PaC port + `policy/` subsystem** (`PolicyRequest`,
  `PolicyDecision`, `RiskClassifier`, `DefaultPolicyEngine`, `ApprovalGrant`,
  `verifyApprovalQuorum`), exported from the package root.
- **`needs_approval` error** (`NeedsApprovalError`, `createNeedsApprovalError`,
  `isNeedsApprovalError`) and the `policy_denied` error code.
- **`bytesToBase64` / `base64ToBytes`** are now re-exported from the package root
  (standard-base64 byte helpers, alongside the existing base64url variants).
- **`AuditLogProvider` — pluggable sink for audit-record retention.** A new
  provider (abstract base + `MemoryAuditLogProvider` / `NoopAuditLogProvider`
  defaults, exported from the root and `./providers`) for persisting the frozen
  `audit.v1` record of each verified tool call. Wire it via `KyaOsConfig.auditLog`
  (default: no-op); `createKyaOsMiddleware` emits a record after each proofed
  call, and a sink failure never breaks the tool response. `buildAuditRecord(ctx)`
  exposes the context→record mapping. Records carry only DID/key id, session,
  audience, scope, request/response hashes, and the verification result — never
  key material or nonces. The storage backend is operator-provided (durable,
  append-only); the package stays storage-agnostic, like the other providers.
- **Delegation scope on audit records.** Delegation-protected tools record the
  scope they were authorized under: `wrapWithDelegation` threads its `scopeId`
  through a new optional `KyaOsCallContext` (3rd handler argument) into the proof
  meta, so the audit record's `scope` reflects it (was `'-'`). The argument is
  optional and backward-compatible; tool handlers that ignore it are unaffected.

### Changed

- **`ProofMeta.responseHash` is now optional** (`string | undefined`). Denial /
  step-up proofs carry no response, so code reading `responseHash` must treat it
  as possibly-absent. `validateDetachedProof` and the `detached-proof` JSON
  Schema no longer require it (and now permit `outcome`/`reason`).
- **`CrispScope` `prefix`/`regex` matchers are now enforced** (previously inert —
  only exact membership in the flat `scopes[]` was checked). A credential
  declaring a non-exact matcher now grants its pattern set, with ReDoS-safe regex
  evaluation; flat `scopes[]` remain exact-match (unchanged). **Behavioral
  change** for any credential that declared a `prefix`/`regex` matcher: it now
  grants where it previously granted nothing, and a one-time warning is logged on
  first non-exact use. Re-delegations may not introduce crisp matchers absent
  from the parent.
- **`withPolicyGate`'s `scopeMatched` defaults to `false`** (fail-closed): compose
  it after `wrapWithDelegation` and pass `scopeMatched: true`, or it denies.
  `withPolicyGate` is an optional member of the `KyaOsMiddleware` interface
  (additive; structural implementers/mocks are not broken). New in this release,
  so no prior consumer is affected.
- **Bundled examples now consume the built `@kya-os/mcp` package** rather than
  reaching into `src/` via relative paths. Nested example packages (consent-basic,
  consent-full, context7, brave-search) link the local build via `file:../..`;
  root-tree examples (node-server, verify-proof, outbound-delegation, statuslist)
  resolve it by package self-reference. Fixes the context7 example, which had
  pinned a stale published `@kya-os/mcp@^1.3.0` (pre-`withKyaOs` rename).

### Spec

- **§4.2 — normative MUST on key generation.** An agent's key pair MUST be
  generated by the agent or its designated custodian; the secret key MUST NOT be
  generated by, transmitted to, or escrowed with any registration, DID,
  directory, or reputation service (which receive only the public key). Carves
  out agent-side proxy/HSM custody (§11.0). Closes the key-escrow / IBE-style
  concern where a directory service implicitly holds agents' secret keys.
- **§6.6 — revocation needs no global list.** Clarified that a verifier checks
  revocation only for the resources it gates and MAY hold revocation state
  locally; `StatusList2021` is the interoperable publish format, not a required
  public certificate-revocation list.
- **§11.0 — "L2+ is not OAuth-style client registration."** Direct (Level 2+)
  verification still gates on the presented delegation chain, not the agent's
  identity alone — inverting the OAuth Dynamic Client Registration pattern.
- **§12.5 — per-delegation keys (delegate unlinkability).** Non-normative
  pattern: delegate to a fresh one-off public key per delegation to prevent
  cross-delegation correlation through a shared subject DID.
- **§2 — reputation scope.** The Responsible Party definition now states that
  reputation and accountability signals are scoped primarily to the Responsible
  Party, not an agent's ephemeral identity.
- **Terminology.** Standardized on _secret key_ (synonymous with _private key_,
  retained in PKCS#8 / JWK references); fixed the one residual _private key_
  usage in §7.

### Security

- **Malformed delegation input no longer crashes.** A malformed `_kyaos_delegation`
  (non-object, missing `credentialSubject.delegation`, or even a throwing
  getter/Proxy accessor) previously surfaced as a JSON-RPC internal error (`-32603`);
  it now returns a clean, signed `delegation_invalid` denial. `validateDelegationChain`
  shape-checks the leaf and returns `{ valid, reason }` (honouring the
  `verify*`/`validate*` never-throw contract); `extractDelegationFromVC` fails
  with a clear error instead of a cryptic `TypeError`; the middleware try/catch is
  now a pure backstop that logs the detail server-side and returns a generic
  reason (no internal/stack detail leaks to the client). The invalid-VC-JWT path
  is now signed as well.
- **Log-injection / reflection hardening.** Caller-derived values (credential
  ids, scopes) interpolated into delegation-failure reasons and logs are now
  stripped of control characters and length-capped before emission, so a hostile
  credential cannot forge log lines, corrupt a terminal, or reflect raw control
  bytes into a client response.
- **`RuntimeFetchProvider` refuses private-network targets by default (SSRF).**
  did:web resolution and StatusList2021 fetches reject loopback / link-local /
  RFC-1918 IP-literal hosts (e.g. `did:web:169.254.169.254`, the cloud-metadata
  endpoint) unless constructed with `{ allowPrivateNetworkHosts: true }`. This
  is best-effort defense-in-depth for IP literals — not DNS rebinding; run
  verifiers behind an egress allowlist (`SECURITY.md`).
- **Signed proofs are now emitted on denial and step-up.** Delegation/scope
  denials and policy step-ups previously produced no proof; they now attach a
  signed detached-JWS proof (`outcome: 'denied' | 'step_up_required'`, no
  `responseHash`), so rejected privileged attempts are non-repudiably auditable.
- **Fail-closed policy default.** Unclassified ("unknown") high-risk actions are
  denied by the `DefaultPolicyEngine` rather than forwarded.
- **Denial/step-up proofs are verifiable end-to-end.** `validateDetachedProof`
  and `ProofVerifier` accept response-less proofs (the earlier fix only corrected
  canonical-payload reconstruction); added a real-crypto end-to-end test.
- **Crisp-scope attenuation.** Re-delegations cannot widen authority via crisp
  matchers absent from the parent — closes a privilege-escalation path that
  enforcing the matcher would otherwise have opened.
- **ReDoS hardening.** The `regex` matcher rejects nested-quantifier patterns and
  bounds input length. This is a conservative guard, **not** a guarantee — prefer
  `exact`/`prefix` for untrusted issuers, or evaluate via a linear-time engine.
  The `prefix` matcher refuses an empty/`*`-only base (no universal grant).

### Removed

- **BREAKING: removed the three unsafe delegation opt-outs.** The
  secure-by-default behavior they bypassed is now unconditional and cannot be
  disabled:
  - `delegation.requireAudienceOnRedelegation` — audience binding on every
    non-root credential in a chain is now mandatory (`SPEC.md` §11.6).
  - `delegation.allowLegacyUnsafeDelegation` — full delegation-chain resolution
    and `credentialStatus` / StatusList revocation checks are always enforced;
    parent-linked credentials without a `resolveDelegationChain` handler, and
    `credentialStatus` without a `statusListResolver`, are rejected.
  - `VerifyDelegationVCOptions.allowNonDelegationSubjectFields` — the
    `credentialSubject` shape check (only `id` + `delegation`) is always
    enforced (`SPEC.md` §6.2; conformance L3.5a).

  The associated one-time `console.warn` notices are removed along with the
  flags. Migration guidance: `SECURITY.md` → Mandatory Delegation Protections.
  Consumers that did not set these flags are unaffected — the reference issuer
  and all bundled examples already emit conformant credentials.

### Known limitations (policy gate — experimental, non-normative)

- Step-up approval grants are **not yet single-use or expiry-bound** (replayable
  for the same action); a server-issued single-use challenge is a planned follow-up.
- The default approval-signature verifier **rejects all** — integrators must supply
  a real verifier; `isValidApprovalSignature: async () => true` is test-only.
- `policy_denied` / `needs_approval`, the step-up flow, and the now-normative
  `CrispScope` matcher semantics are **not yet documented in `SPEC.md` /
  `CONFORMANCE.md`** (tracked as follow-ups).

## [1.3.2] - 2026-05-26

### Security

- **Verifier rejects claim-contaminated delegation credentials.** A
  `DelegationCredential` whose `credentialSubject` carries properties beyond
  `id` and `delegation` is now rejected by default — claim-bearing fields in a
  permission credential separate designation from authorization (the
  confused-deputy class, `SPEC.md` §6.2 / §11.6). The reference verifier exposes
  `allowNonDelegationSubjectFields` (default `false`) as an audited opt-out that
  logs a one-time per-process warning. Spec-conformant issuers are unaffected;
  the reference issuer already emits `{ id, delegation }` subjects. New
  conformance requirement L3.5a. (#67)

### Changed

- **Schema `$id` and JSON-LD `@context` hosts migrated** off the
  `modelcontextprotocol-identity.io` trademark domain to the foundation-owned
  `schema.kya-os.ai`. All five shipped JSON Schemas (`schemas/*.json`), the
  spec's context references, and the `DELEGATION_CREDENTIAL_CONTEXT` constant
  now resolve under `schema.kya-os.ai`; schemas are served identically at both
  hosts during the migration window (no `$id` is 301-redirected). (#65)

## [1.3.1] - 2026-05-26

> These entries accreted across the 1.2.0 → 1.3.1 donation cutover and were
> published without strict per-version sectioning. They are grouped here for
> completeness; see `npm view @kya-os/mcp time` and git history for exact ship
> points. A clean per-version backfill is tracked separately.

### Added

- Export the byte-variant base64url helpers (`base64urlEncodeFromBytes`, `base64urlDecodeToBytes`) from the package entry point. They existed in `src/utils/base64.ts` but were not on the public API; downstream consumers need them for DID/JWK key encoding.

### Docs

- Tightened two capability-language hits inside the spec that survived the Responsible Party rename: §8.2 `DelegationProofJWT.sub` comment now describes the Responsible Party explicitly (was "User DID (on whose behalf)"), and the `userDid` field description in `schemas/delegation-credential.json` now reads "whose delegated authority the agent exercises" instead of "on whose behalf the delegation acts."

### Spec

- Added §11.0 (Trust Model) naming the three trust boundaries explicitly: the agent process, the verifier (with the Edge Verifier called out as a TCB component at L1), and the service / resource owner. Includes key custody options (software, proxy-managed, hardware-attested) and a mutual-authentication recommendation for services.
- Added §11.1 (Threat Model Summary) as a structured table: threat → mitigation → residual risk. Covers impersonation, replay, scope escalation, confused deputy, credential theft, agent abuse, key compromise, revocation race, downgrade, and DoS — with cross-references to detailed sections and to the cap-sec invariants in §6.4.1 / §6.5.
- Renumbered §11 subsections to fit the new structure (Revocation Freshness moved to §11.10; previous §11.1–§11.5 shifted by one).
- Introduced **Principal** and **Responsible Party** as first-class terms (§2). The Responsible Party is the entity ultimately accountable for actions taken under a delegation chain — the root issuer of the chain. Distinguished from the Principal (the immediate human delegator) to support organizational deployments where the operating human is not the accountable entity.
- Added a normative invariant to §6.4: every delegation chain MUST terminate at a Responsible Party, identified by the `issuerDid` of the root `DelegationCredential`.
- Reworded the Abstract to drop "on whose behalf" (impersonation framing) in favor of "what authority they hold (a delegation chain rooted at a Responsible Party)" — capability-security framing that matches the protocol's actual semantics.
- Added normative _meta hash exclusion paragraph and `session.metaPolicy` opt-in (default: `strict`).
- Documented anonymous handshake nonce-dedupe boundary; reference impl now uses a 60s TTL for anonymous nonces.
- Added `clockSkewSeconds` field to `.well-known/mcp` for server-advertised skew negotiation.
- Added the **designation invariant** to §6.4.1 as a normative MUST: invocations must designate the specific resource being exercised, even when the delegation authorizes multiple resources. The reference implementation already enforces this via the per-tool `scopeId` check; this change makes the behavior normative and cross-references it from §11.6 (Confused Deputy Attacks).
- Added §6.5.1 (Revocation Rights) defining who may revoke a delegation in v1.0: direct issuer, any ancestor issuer in the chain, and the responsible party at the root. Subject-side revocation is explicitly disallowed in v1.0; UCAN-style "revocation as a delegatable permission" is tracked for v1.1.
- Added §6.5.2 (Concurrency and the Revocation Race) acknowledging the Lamport-concurrent race between revocation issuance and propagation, with implementation guidance on bounding the window.

### Security

- **BREAKING (default flip): `requireAudienceOnRedelegation` now defaults to `true`.**
  Every non-root credential in a delegation chain must carry an `audience`
  constraint. Closes the confused-deputy class flagged by Alan Karp's
  transitive-access analysis and matches `SPEC.md` §11.6. Integrations that
  cannot yet bind audience on every re-delegation can set the flag to `false`
  explicitly to preserve legacy behavior; doing so logs a one-time
  per-process warning so the configuration is auditable in production logs.
- **Unsafe-mode warning:** setting `allowLegacyUnsafeDelegation` to `true`
  now emits a one-time per-process `console.warn` on first use. Default
  is unchanged (`false` / strict). The warning surfaces accidental
  configuration in production logs without spamming per-session.
- `SECURITY.md` gained a "Secure Defaults & Unsafe Delegation Modes" section
  documenting both flags, when to opt out, and the migration path back to
  safe defaults.
- Added test coverage pinning the warn-once behavior on both unsafe-mode
  flags: warns exactly once per process on opt-in, silent on safe defaults,
  no duplicate warnings across repeated `wrapWithDelegation` calls.

### Added

- **Generic `Identity` interface** exported from the root entry point.
  Captures the shape shared by every subject the protocol speaks about
  (DID + verification-method id + key material). `AgentIdentity` now
  extends `Identity`; the agent-flavoured shape is unchanged for
  existing consumers.
- **`buildDidWebDocument(identity, options?)`** in
  `delegation/did-web-resolver`. Produces the DID Document a `did:web`
  controller serves at its resolution URL (see `didWebToUrl`),
  completing the producer/consumer round-trip with `DidWebResolver`.
  Emits both `publicKeyJwk` and `publicKeyMultibase` for cross-format
  interop, matching the `Ed25519VerificationKey2020` form used by the
  did:key resolver.
- Optional `@context` field on `DIDDocument` so produced documents can
  declare the JSON-LD contexts they reference.

### Changed

- **Package renamed from `@mcp-i/core` to `@kya-os/mcp`.** Renamed
  under the KYA-OS protocol (Know Your Agent Operating System), the
  agent identity, authorization, and observability protocol donated
  to DIF TAAWG. Version stays at 1.2.0 — the wire format, public
  exports, and behavior are unchanged. The old `@mcp-i/core` package
  is deprecated and points at this one.
- **Spec renamed from MCP-I to KYA-OS** across `SPEC.md`,
  `CONFORMANCE.md`, `GOVERNANCE.md`, and example READMEs. Wire-format
  identifiers (`_kyaos` tool name, well-known path, JSON Schema
  files, JSON-LD context URLs) are deferred to a later cutover so
  this doc-only rename doesn't break running implementations.

  Why the rename: two forces.

  First, MCP is Anthropic's trademark and lives under Anthropic's
  governance. Calling a DIF-track identity protocol "MCP-Identity"
  suggested an official extension of MCP and tied the protocol to a
  single vendor's roadmap. The Linux Foundation flagged this during
  pre-donation review and we agreed: a foundation-owned identity
  protocol should not carry another foundation's (or vendor's)
  trademark in its name.

  Second, the protocol was never going to be MCP-only. The design
  intent was a primitive layer for identity, authority, and
  accountability that other agent-facing protocols adopt, analogous
  to how TLS is a security layer that transports adopt rather than
  a transport itself. KYA-OS primitives are intended to embed in
  three kinds of host surface: transport bindings (wire protocols
  an agent's calls ride over, e.g. MCP, HTTPS, gRPC, SMTP, Matrix,
  browser-driven actions), runtime bindings (agent harnesses where
  the loop runs and tool invocations can be wrapped uniformly), and
  manifest / assertion embeddings (host formats like C2PA manifests
  that already carry signed assertions and can carry a KYA-OS proof
  as one assertion type). Naming the protocol after one binding
  undersold the surface.

  The MCP binding ships first because MCP is the most concentrated
  agent-to-tool RPC surface today. Additional bindings will be
  specified in the working group as they reach consensus.
- **Spec cut to `1.0.0`** (was `0.1.0-draft` in `SPEC.md`, `1.0.0-draft`
  in `CONFORMANCE.md`). The wire format was already pinned at `1.0.0`
  in the handshake protocol-version field; the spec docs now match.
  Status: Stable — donated to DIF TAAWG for ratification review. Spec
  semver is independent of package semver: the spec describes the wire
  protocol, the package describes the implementation shipping it.
- Delegation middleware remains strict by default for chain and status-list validation.
- Added `delegation.allowLegacyUnsafeDelegation` to `createKyaOsMiddleware` as a temporary migration escape hatch for legacy integrations.
- Added middleware tests covering legacy-compatibility behavior for parent-linked and status-list credentials.

### Docs

- L1 revocation terminology clarified (verifier-local, not global CRL).
- Orchestration directory scope explicitly narrowed from global to service-local.
- Nonce lifetime documented to prevent early-eviction replay class.
- Multi-level audit record example added.
- Conformance-tiered audit-logging requirements added.
- Registry types (Delegation / Credential / Trust) disambiguated.
- Broken link to Protocol Registry fixed.
- Key Topics ordering aligned with site navigation.

## [1.0.0-draft] - 2026-03-12

### Added

- SPEC.md protocol specification defining KYA-OS extension for cryptographic identity
- Supported DID methods: `did:key` (ephemeral/dev) and `did:web` (production)
- Ed25519/EdDSA cryptography for signing and verification
- Delegation module with W3C Verifiable Credential issuance and verification
- CRISP constraint envelopes for scope, budget, temporal bounds, and audience
- Delegation graph management with parent-child relationships
- Cascading revocation via StatusList2021
- `did:key` resolver for synchronous DID Document resolution
- `did:web` resolver with HTTPS fetching and caching
- Proof module with detached JWS generation over canonicalized request/response
- Proof verification with DID resolution and timestamp validation
- SHA-256 hashing with RFC 8785 JCS canonicalization
- Session module with handshake validation and nonce-based replay prevention
- Session TTL management with idle timeout tracking
- Auth module with `verifyOrHints` orchestration and sensitive scope detection
- Resume token storage for authorization flows
- `needs_authorization` hint response pattern
- MCP SDK middleware wrapper (`createKyaOsMiddleware`)
- Tool wrapping with automatic proof generation
- Handshake tool registration and handling
- Provider abstractions: CryptoProvider, ClockProvider, FetchProvider, StorageProvider, NonceCacheProvider, IdentityProvider
- In-memory implementations for all providers (testing)
- Configurable logging with debug, info, warn, error levels
- Pure TypeScript protocol type definitions (zero runtime dependencies)
- Well-known endpoint (`/.well-known/mcp`) for server discovery
- Outbound delegation proof JWT builder for downstream API calls
- Three-tier conformance levels:
  - Level 1: Core Crypto (key generation, signing, hashing, DID resolution)
  - Level 2: Full Session (handshake, nonce, replay prevention, proofs)
  - Level 3: Full Delegation (VCs, CRISP, graphs, revocation, chain validation)
- Example implementations: Node.js server, proof verification, delegation issuance
- Vitest test suite covering all conformance levels
- GitHub Actions CI with type checking, build, test, and coverage
