# Changelog

All notable changes to @kya-os/mcp will be documented here.

Format: https://keepachangelog.com/en/1.0.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

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
