# KYA-OS Conformance Requirements

**Compliance levels for KYA-OS implementations**

Version: 1.0.0
Status: Stable

---

## Overview

This document defines three compliance levels for KYA-OS implementations. Each level builds on the previous, with increasing capability requirements. Implementations MUST pass all tests for a given level to claim conformance at that level.

---

## Level 1 — Core Crypto

Level 1 establishes the cryptographic foundation. An implementation at this level can generate identities, sign data, verify signatures, and expose discovery metadata.

### Requirements

| ID | Requirement | Test File | Test Name |
|----|-------------|-----------|-----------|
| L1.1 | Generate Ed25519 key pair and derive a `did:key` DID | `src/utils/__tests__/did-helpers.test.ts` | `generateDidKeyFromBytes` / `generateDidKeyFromBase64` |
| L1.2 | Implement SHA-256 hashing of canonicalized JSON (RFC 8785 JCS) | `src/proof/__tests__/proof-generator.test.ts` | `Canonical Hash Generation > should generate SHA-256 hashes with correct format` |
| L1.3 | Sign data with EdDSA (JWS compact serialization) | `src/proof/__tests__/proof-generator.test.ts` | `JWS Generation > should generate compact JWS in correct format` |
| L1.4 | Verify EdDSA signatures | `src/proof/__tests__/proof-generator.test.ts` | `Proof Verification > should verify valid proof structure` |
| L1.5 | Use EdDSA algorithm identifier in JWS header | `src/proof/__tests__/proof-generator.test.ts` | `JWS Generation > should use EdDSA algorithm` |
| L1.6 | Resolve `did:key` DIDs to DID Documents | `src/delegation/__tests__/did-key-resolver.test.ts` | `createDidKeyResolver > should resolve Ed25519 did:key to DID Document` |
| L1.7 | Extract Ed25519 public key from `did:key` | `src/delegation/__tests__/did-key-resolver.test.ts` | `extractPublicKeyFromDidKey > should extract public key bytes from valid did:key` |
| L1.8 | Convert public key bytes to JWK format | `src/delegation/__tests__/did-key-resolver.test.ts` | `publicKeyToJwk > should convert public key bytes to JWK format` |
| L1.9 | Implement base58btc encoding/decoding | `src/delegation/__tests__/did-key-resolver.test.ts` | `Base58 Utilities` (all tests) |
| L1.10 | Expose `/.well-known/mcp` endpoint (recommended) | — | Implementation-specific |
| L1.11 | Audit logging MAY be implemented | — | Implementation-specific |

### Detailed Requirements

#### L1.1 — Ed25519 Key Generation

Implementation MUST:
- Generate cryptographically secure random 32-byte private seed
- Derive 32-byte public key from seed
- Derive `did:key` DID from public key using multicodec prefix `0xed01` and base58btc encoding
- Key ID format: `<did>#keys-1`

#### L1.2 — SHA-256 Hashing

Implementation MUST:
- Accept arbitrary JSON input
- Canonicalize according to RFC 8785 (JCS): sorted keys, no whitespace, specific escaping
- Compute SHA-256 hash of UTF-8 encoded canonical JSON
- Return hash in format: `sha256:<64-char-lowercase-hex>`

#### L1.3 — EdDSA Signing

Implementation MUST:
- Accept data bytes and Ed25519 private key
- Produce JWS compact serialization: `<header>.<payload>.<signature>`
- Header MUST include `"alg": "EdDSA"` and `"kid": "<key-id>"`
- Signature MUST be 64 bytes, base64url-encoded

#### L1.4 — EdDSA Verification

Implementation MUST:
- Accept JWS compact string and public key (JWK format)
- Verify signature against payload
- Verify `kid` in header matches expected key
- Return boolean result

#### L1.11 — Audit Logging

Audit logging MAY be implemented at Level 1. If implemented, it SHOULD capture key generation events and signature operations.

---

## Level 2 — Full Session

Level 2 adds session management with replay prevention and proof generation. An implementation at this level can establish secure sessions and generate non-repudiation proofs.

### Requirements

All Level 1 requirements, plus:

| ID | Requirement | Test File | Test Name |
|----|-------------|-----------|-----------|
| L2.1 | Implement handshake request validation | `src/session/__tests__/session-manager.test.ts` | `Handshake validation > should create a valid session on correct handshake` |
| L2.2 | Validate nonce format (base64url, 22+ chars) | `src/session/__tests__/session-manager.test.ts` | `Nonce format > should generate nonce as base64url string` |
| L2.3 | Enforce timestamp skew ≤120 seconds (default) | `src/session/__tests__/session-manager.test.ts` | `Handshake validation > should reject request with stale timestamp` |
| L2.4 | Accept requests within timestamp skew | `src/session/__tests__/session-manager.test.ts` | `Handshake validation > should accept request within timestamp skew` |
| L2.5 | Enforce nonce uniqueness (replay prevention) | `src/session/__tests__/session-manager.test.ts` | `Handshake validation > should reject replayed nonce` |
| L2.6 | Generate unique nonces | `src/session/__tests__/session-manager.test.ts` | `Nonce format > should generate unique nonces` |
| L2.7 | Generate session IDs with `kyaos_` prefix | `src/session/__tests__/session-manager.test.ts` | `Handshake validation > should return session ID with kyaos_ prefix` |
| L2.8 | Maintain session TTL | `src/session/__tests__/session-manager.test.ts` | `Session expiry — TTL behaviour > should expire idle sessions after TTL` |
| L2.9 | Support configurable timestamp skew | `src/session/__tests__/session-manager.test.ts` | `Custom timestamp skew > should use custom timestampSkewSeconds when provided` |
| L2.10 | Update session `lastActivity` on access | `src/session/__tests__/session-manager.test.ts` | `Session lookup — getSession > should update lastActivity on each getSession call` |
| L2.11 | Generate detached proof with request/response hashes | `src/proof/__tests__/proof-generator.test.ts` | `Proof Metadata > should include all required metadata fields` |
| L2.12 | Include session context in proof metadata | `src/proof/__tests__/proof-generator.test.ts` | `Proof Metadata > should include all required metadata fields` |
| L2.13 | Verify proof against request/response | `src/proof/__tests__/proof-generator.test.ts` | `Proof Verification > should reject proof with mismatched request` |
| L2.14 | Validate handshake request format | `src/session/__tests__/session-manager.test.ts` | `validateHandshakeFormat` (all tests) |
| L2.15 | Create handshake request with current timestamp | `src/session/__tests__/session-manager.test.ts` | `createHandshakeRequest > should use current timestamp` |
| L2.16 | Audit logging SHOULD be implemented | — | Implementation-specific |

### Detailed Requirements

#### L2.1 — Handshake Validation

Implementation MUST validate:
- `nonce`: Non-empty string, base64url format, minimum 16 bytes entropy
- `audience`: Non-empty string matching server identity
- `timestamp`: Positive integer, within skew tolerance of server time
- `agentDid` (optional): Valid DID format if present

#### L2.5 — Nonce Replay Prevention

Implementation MUST:
- Store (nonce, agentDid) tuples for at least `sessionTtlMinutes + 1 minute`
- Reject any request with a previously-seen nonce for the same agentDid
- Support cleanup of expired nonces

#### L2.16 — Audit Logging

Audit logging SHOULD be implemented at Level 2. Implementations SHOULD record session lifecycle events (handshake, expiry, replay rejection) and proof generation events with enough detail to reconstruct the sequence of operations for a given session.

#### L2.11 — Detached Proof Generation

Proof metadata MUST include:
- `did`: Signer's DID
- `kid`: Key ID used for signing
- `ts`: Unix epoch seconds
- `nonce`: Session nonce
- `audience`: Session audience
- `sessionId`: Session identifier
- `requestHash`: SHA-256 of canonicalized request (`sha256:<hex>`)
- `responseHash`: SHA-256 of canonicalized response (`sha256:<hex>`)

---

## Level 3 — Full Delegation

Level 3 adds W3C Verifiable Credential-based delegation with revocation support. An implementation at this level can issue, verify, and revoke delegations, and propagate delegation context on outbound calls.

### Requirements

All Level 2 requirements, plus:

| ID | Requirement | Test File | Test Name |
|----|-------------|-----------|-----------|
| L3.1 | Issue W3C DelegationCredentials | `src/delegation/__tests__/vc-issuer.test.ts` | `issueDelegationCredential > should issue a signed delegation credential` |
| L3.2 | Wrap DelegationRecord in VC structure | `src/delegation/__tests__/vc-issuer.test.ts` | `issueDelegationCredential > should call wrapDelegationAsVC with delegation record` |
| L3.3 | Support issuance options (id, dates, status) | `src/delegation/__tests__/vc-issuer.test.ts` | `issueDelegationCredential > should pass options to wrapDelegationAsVC` |
| L3.4 | Canonicalize VC before signing | `src/delegation/__tests__/vc-issuer.test.ts` | `issueDelegationCredential > should canonicalize VC before signing` |
| L3.5 | Verify DelegationCredential basic properties | `src/delegation/__tests__/vc-verifier.test.ts` | `verifyDelegationCredential - Basic Validation Stage` (all tests) |
| L3.5a | Reject claim-contaminated `credentialSubject` (only `id` + `delegation`) | `src/delegation/__tests__/vc-verifier.test.ts` | `Subject Shape (claim contamination) > rejects a credentialSubject carrying non-delegation (claim) fields` |
| L3.6 | Reject expired credentials | `src/delegation/__tests__/vc-verifier.test.ts` | `Basic Validation Stage > should reject expired credentials` |
| L3.7 | Reject not-yet-valid credentials | `src/delegation/__tests__/vc-verifier.test.ts` | `Basic Validation Stage > should reject not-yet-valid credentials` |
| L3.8 | Reject revoked credentials (status field) | `src/delegation/__tests__/vc-verifier.test.ts` | `Basic Validation Stage > should reject revoked credentials` |
| L3.9 | Verify credential signature | `src/delegation/__tests__/vc-verifier.test.ts` | `Signature Verification > should succeed when signature verification passes` |
| L3.10 | Resolve issuer DID for signature verification | `src/delegation/__tests__/vc-verifier.test.ts` | `Signature Verification > should fail when DID resolution fails` |
| L3.11 | Check credential status via StatusList2021 | `src/delegation/__tests__/vc-verifier.test.ts` | `Status Checking > should fail when credential is revoked` |
| L3.12 | Cache verification results | `src/delegation/__tests__/vc-verifier.test.ts` | `Caching > should return cached result when available` |
| L3.13 | Enforce CRISP scope constraints | `src/delegation/__tests__/audience-validator.test.ts` | All tests |
| L3.14 | Register delegation in graph | `src/delegation/__tests__/delegation-graph.test.ts` | `registerDelegation > should register a root delegation` |
| L3.15 | Link child to parent in delegation graph | `src/delegation/__tests__/delegation-graph.test.ts` | `registerDelegation > should register a child delegation and link to parent` |
| L3.16 | Validate delegation chain (issuer/subject continuity) | `src/delegation/__tests__/delegation-graph.test.ts` | `validateChain > should validate correct chain` |
| L3.17 | Detect chain with mismatched issuer/subject | `src/delegation/__tests__/delegation-graph.test.ts` | `validateChain > should invalidate chain with mismatched issuer/subject` |
| L3.18 | Get delegation chain from leaf to root | `src/delegation/__tests__/delegation-graph.test.ts` | `getChain > should return chain from root to node` |
| L3.19 | Get all descendants of a delegation | `src/delegation/__tests__/delegation-graph.test.ts` | `getDescendants > should return all descendants recursively` |
| L3.20 | Create StatusList2021 credential | `src/delegation/__tests__/statuslist-manager.test.ts` | (StatusList2021Manager tests) |
| L3.21 | Set/check revocation status by index | `src/delegation/__tests__/bitstring.test.ts` | All tests |
| L3.22 | Cascading revocation of descendant delegations | `src/delegation/__tests__/cascading-revocation.test.ts` | All tests |
| L3.23 | Build delegation proof JWT for outbound calls | `src/delegation/__tests__/outbound-proof.test.ts` | All tests |
| L3.24 | Build delegation chain string | `src/delegation/__tests__/outbound-proof.test.ts` | `buildChainString` tests |
| L3.25 | Return `needs_authorization` hints | Implementation-specific | — |
| L3.26 | Audit logging MUST be implemented | — | Implementation-specific |

### Detailed Requirements

#### L3.1 — VC Issuance

Implementation MUST:
- Produce valid W3C Verifiable Credential structure
- Include `@context` with VC v1 and KYA-OS delegation context
- Include `type` array with `VerifiableCredential` and `DelegationCredential`
- Include `issuer` as DID string or object with `id`
- Include `issuanceDate` in ISO 8601 format
- Include `credentialSubject` with delegation details
- Include `proof` with Ed25519Signature2020 or equivalent

#### L3.5 — VC Verification

Implementation MUST validate:
- `@context` starts with W3C VC v1 context
- `type` includes required types
- `issuer` is present and valid
- `issuanceDate` is present and in the past
- `expirationDate` (if present) is in the future
- `credentialSubject.delegation` has required fields
- `proof` is present

#### L3.11 — StatusList2021 Checking

Implementation MUST:
- Fetch StatusList2021 credential from `credentialStatus.statusListCredential`
- Decompress and decode the bitstring
- Check bit at `statusListIndex`
- Return revoked status if bit is 1

#### L3.22 — Cascading Revocation

When revoking a delegation, implementation MUST:
- Mark the target delegation as revoked
- Recursively mark all descendants as revoked
- Update StatusList2021 for each revoked delegation
- Emit revocation events (implementation-specific)

#### L3.26 — Audit Logging

Audit logging MUST be implemented at Level 3. Implementations MUST record:
- Delegation issuance and revocation events (including cascading revocations), with issuer DID, subject DID, credential ID, and timestamp
- Delegation verification outcomes (pass/fail), including chain validation results
- Outbound delegation proof attachments, including the chain string and target audience
- Any `needs_authorization` hints returned to callers

Audit records MUST be tamper-evident (e.g., append-only log, signed entries, or equivalent) and MUST be retained for at least the duration of the longest-lived delegation in the system.

> **Note:** Revocation is verifier-local (checked against the verifier's local list or cache). L1 implementations MAY use simple local checks; higher levels MAY use StatusList2021.

---

## Running Conformance Tests

### Prerequisites

```bash
# Install dependencies
pnpm install

# Or with npm
npm install
```

### Running All Tests

```bash
# Run all tests
pnpm test

# Or with npx
npx vitest run
```

### Running Specific Test Files

```bash
# Level 1 - Core Crypto
npx vitest run src/delegation/__tests__/did-key-resolver.test.ts
npx vitest run src/utils/__tests__/did-helpers.test.ts
npx vitest run src/utils/__tests__/base58.test.ts

# Level 2 - Session
npx vitest run src/session/__tests__/session-manager.test.ts
npx vitest run src/proof/__tests__/proof-generator.test.ts

# Level 3 - Delegation
npx vitest run src/delegation/__tests__/vc-issuer.test.ts
npx vitest run src/delegation/__tests__/vc-verifier.test.ts
npx vitest run src/delegation/__tests__/delegation-graph.test.ts
npx vitest run src/delegation/__tests__/cascading-revocation.test.ts
npx vitest run src/delegation/__tests__/statuslist-manager.test.ts
npx vitest run src/delegation/__tests__/bitstring.test.ts
npx vitest run src/delegation/__tests__/outbound-proof.test.ts
npx vitest run src/delegation/__tests__/audience-validator.test.ts
```

### Test Coverage

```bash
# Run tests with coverage
pnpm test:coverage

# Or
npx vitest run --coverage
```

---

## Submitting Conformance Results

To submit conformance results for your implementation:

1. Fork the `kya-os-mcp` repository
2. Run the test suite against your implementation
3. Capture test output and coverage report
4. Open a GitHub issue at https://github.com/decentralized-identity/kya-os-mcp/issues with:
   - Implementation name and version
   - Target conformance level (1, 2, or 3)
   - Test results (pass/fail counts)
   - Coverage report
   - Platform/runtime information
   - Any deviations or extensions

### Issue Template

```markdown
## KYA-OS Conformance Submission

**Implementation**: [Name] v[Version]
**Conformance Level**: [1 | 2 | 3]
**Platform**: [Node.js 20.x | Cloudflare Workers | etc.]

### Test Results

- Total Tests: X
- Passed: X
- Failed: X
- Skipped: X

### Coverage

[Attach or link coverage report]

### Deviations

[List any deviations from the specification]

### Extensions

[List any extensions beyond the specification]
```

---

## Conformance Badges

Implementations that pass conformance testing may display badges:

- **KYA-OS Level 1 Conformant** — Core cryptographic operations
- **KYA-OS Level 2 Conformant** — Session management and proofs
- **KYA-OS Level 3 Conformant** — Full delegation support

Badge assets will be provided upon successful conformance submission.

---

*End of Conformance Requirements*
