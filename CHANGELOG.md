# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Spec

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
- **Spec cut to `1.0.0`** (was `0.1.0-draft` in `SPEC.md`, `1.0.0-draft`
  in `CONFORMANCE.md`). The wire format was already pinned at `1.0.0`
  in the handshake protocol-version field; the spec docs now match.
  Status: Stable — donated to DIF TAAWG for ratification review. Spec
  semver is independent of package semver: the spec describes the wire
  protocol, the package describes the implementation shipping it.
- Delegation middleware remains strict by default for chain and status-list validation.
- Added `delegation.allowLegacyUnsafeDelegation` to `createKyaOsMiddleware` as a temporary migration escape hatch for legacy integrations.
- Added middleware tests covering legacy-compatibility behavior for parent-linked and status-list credentials.

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
