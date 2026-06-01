# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- `./oauth` authorization-server seam: a neutral `AuthorizationServerAdapter`
  port with a shared dispatch predicate, an `AuthorizationServerRegistry` that
  routes a tool's protection to one adapter, and a generic-OIDC reference
  adapter (mandatory S256 PKCE, RFC 8707 resource binding, injectable fetch
  seam — no named vendor IdP, per the donation's vendor-neutrality).
- `AccountabilityContext` projection (agent → accountable-admin → user →
  intent) that feeds the policy principal's `responsibleParty`; `orgRootDid` is
  a forward-compatible slot pending the organization root identity.
- A deterministic, network-free in-memory OIDC example exercising the full
  authorization path. Additive; no new runtime dependency (zod, jose, Web
  Crypto only).

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
