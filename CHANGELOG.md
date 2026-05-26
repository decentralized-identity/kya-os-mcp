# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

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
- **Verifier rejects claim-contaminated delegation credentials.** A
  `DelegationCredential` whose `credentialSubject` carries properties beyond
  `id` and `delegation` is now rejected by default: claim-bearing fields in a
  permission credential separate designation from authorization (the
  confused-deputy class — `SPEC.md` §6.2 / §11.6). The reference verifier
  exposes `allowNonDelegationSubjectFields` (default `false`) as an audited
  opt-out that logs a one-time per-process warning. Spec-conformant issuers are
  unaffected — the reference issuer already emits `{ id, delegation }` subjects,
  and the full suite passes unchanged. New conformance requirement L3.5a.

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
