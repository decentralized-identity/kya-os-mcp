# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

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
- **`createIdentity(crypto, request)`** — discriminated-union
  dispatching surface that selects the DID method at call time
  (`{ method: 'did:key', ... }` or
  `{ method: 'did:web', domain, path?, ... }`). Per-method options
  (e.g. `kidFragment` on did:web only) live on the request itself so
  cross-method misuse fails at compile time rather than at runtime.
  Future `did:jwk` / `did:peer` / `did:ion` helpers extend the union
  without growing the top-level export footprint.
- **`createDidKeyIdentity(crypto, options?)`** and
  **`createDidWebIdentity(crypto, args, options?)`** in
  `providers/identity-factory`. Single-call provisioning helpers that
  compose a `CryptoProvider` with the appropriate DID method to mint a
  fresh `Identity`. Both return `ProvisionedIdentity` (the narrowed
  `Identity & { privateKey: string }`) and accept an optional
  `ClockProvider` for deterministic `createdAt` stamping. The did:web
  helper validates `domain` and `path` segments per the construction-
  throws contract.

### Changed

- **Package renamed from `@mcp-i/core` to `@kya-os/mcp`.** Reframed under
  the KYA-OS taxonomy: MCP-I is the identity surface of KYA-OS (Know
  Your Agent Operating System), the umbrella protocol for agent
  identity, authorization, and observability. Version stays at 1.2.0 —
  the wire format, exports (`MCPI*`), and behavior are unchanged. The
  old `@mcp-i/core` package is deprecated and points at this one.
- **Spec cut to `1.0.0`** (was `0.1.0-draft` in `SPEC.md`, `1.0.0-draft`
  in `CONFORMANCE.md`). The wire format was already pinned at `1.0.0`
  in the handshake protocol-version field; the spec docs now match.
  Status: Stable — donated to DIF TAAWG for ratification review. Spec
  semver is independent of package semver: the spec describes the wire
  protocol, the package describes the implementation shipping it.
- Delegation middleware remains strict by default for chain and status-list validation.
- Added `delegation.allowLegacyUnsafeDelegation` to `createMCPIMiddleware` as a temporary migration escape hatch for legacy integrations.
- Added middleware tests covering legacy-compatibility behavior for parent-linked and status-list credentials.

## [1.0.0-draft] - 2026-03-12

### Added

- SPEC.md protocol specification defining MCP-I extension for cryptographic identity
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
- MCP SDK middleware wrapper (`createMCPIMiddleware`)
- Tool wrapping with automatic proof generation
- Handshake tool registration and handling
- Provider abstractions: CryptoProvider, ClockProvider, FetchProvider, StorageProvider, NonceCacheProvider, IdentityProvider
- In-memory implementations for all providers (testing)
- Configurable logging with debug, info, warn, error levels
- Pure TypeScript protocol type definitions (zero runtime dependencies)
- Well-known endpoint (`/.well-known/mcpi`) for server discovery
- Outbound delegation proof JWT builder for downstream API calls
- Three-tier conformance levels:
  - Level 1: Core Crypto (key generation, signing, hashing, DID resolution)
  - Level 2: Full Session (handshake, nonce, replay prevention, proofs)
  - Level 3: Full Delegation (VCs, CRISP, graphs, revocation, chain validation)
- Example implementations: Node.js server, proof verification, delegation issuance
- Vitest test suite covering all conformance levels
- GitHub Actions CI with type checking, build, test, and coverage
