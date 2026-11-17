# KYA-OS Conformance Requirements

**Compliance levels for KYA-OS implementations**

Version: 1.6.0
Status: Stable

---

## Overview

This document defines three compliance levels for KYA-OS implementations. Each level builds on the previous, with increasing capability requirements. Implementations MUST pass all tests for a given level to claim conformance at that level.

Three independent ladders live in this document, and two of them reuse the
names L1–L3. A conformance claim MUST name its ladder:

| Ladder | Levels | Measures |
|--------|--------|----------|
| Core (this section onward) | Core L1 / L2 / L3 | Crypto primitives, the legacy session-bound proof, W3C delegation credentials |
| Entity Card (§ Entity Card Conformance) | Card L1 / L2 / L3 | The typed card and the stateless `org.kya-os/proof.v1` request proof |
| Audit Assurance Profile (§ Audit Assurance Profile conformance) | AAP-0 … AAP-4 | Auditability mechanics an implementation can truthfully advertise |

A bare "L2" is ambiguous; write "Core L2", "Card L2", or "AAP-2".

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
- Key ID format: `<did>#<multibase>`, the W3C did:key verification method ID (SPEC.md §4.3)

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
- Read the JWS as SPEC.md §7.4 has a verifier read a proof's: exactly three segments, each base64url and nothing looser, and the key's `x` the same way
- Verify signature against payload
- Verify `alg` in header is `EdDSA`
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
| L2.17 | Process only the KYA-OS proof `_meta` key; ignore (do not reject) reserved keys | — | Spec-defined behavior (SPEC §7.6) |

### Detailed Requirements

#### L2.1 — Handshake Validation

Implementation MUST validate:
- `nonce`: Non-empty string, base64url format, minimum 16 bytes entropy
- `audience`: Non-empty string matching server identity
- `timestamp`: Positive integer, within skew tolerance of server time
- `agentDid` (optional): Valid DID format if present

#### L2.5 — Nonce Replay Prevention

Implementation MUST:
- Store (nonce, agentDid) tuples at least until the nonce's timestamp leaves the acceptance window (`ts + skew`, SPEC §5.5)
- Reject any request with a previously-seen nonce for the same agentDid
- Support cleanup of expired nonces

#### L2.16 — Audit Logging

Audit logging SHOULD be implemented at Level 2. Implementations SHOULD record session lifecycle events (handshake, expiry, replay rejection) and proof generation events with enough detail to reconstruct the sequence of operations for a given session.

#### L2.11 — Detached Proof Generation

Proof metadata MUST include:
- `did`: Signer's DID
- `kid`: Key ID used for signing
- `ts`: Unix epoch seconds
- `nonce`: Fresh random nonce per proof
- `audience`: Session audience
- `sessionId`: Session identifier
- `requestHash`: SHA-256 of the canonicalized request (`sha256:<hex>`), over the covered request of SPEC §7.3 or, as 1.x implementations emit it, the legacy `{method: <tool name>, params: <arguments>}` shape; a verifier accepts either for the same call

`responseHash` (SHA-256 of the canonicalized response, `sha256:<hex>`) MUST be
present on proofs that carry a response body — success proofs and
`needs_authorization` challenges — and is ABSENT on `denied` / `step_up_required`
proofs (which have no response body). See SPEC §7.2 / §7.4 and the
`detached-proof` schema (`responseHash` is intentionally not in `required`).

A verifier that acts on a `needs_authorization` `authorizationUrl` — or
otherwise relies on the response body — MUST recompute `responseHash` over the
response it actually received and compare it to the bound value BEFORE trusting
it. The signature alone proves the proof is authentic, not that the received
content matches what was signed: an in-path intermediary can leave the signature
intact while swapping the `authorizationUrl`, and only the recompute detects it.

#### L2.17 — `_meta` Namespacing Tolerance

`_meta` is the MCP per-request metadata channel and is shared with reserved
reverse-DNS keys. A conformant verifier MUST:
- Read the detached response proof from `org.kya-os/response-proof`. Through
  1.x, also accept the prior keys `org.kya-os/proof` and bare `proof` (SPEC
  §7.6), in that order: the first key present wins. Servers write `org.kya-os/response-proof` and, unless configured with
  `emitLegacyProofKey: false`, mirror it under bare `proof`; nothing writes
  `org.kya-os/proof`.
- Treat the holder-of-key request proof, under `org.kya-os/request-proof`
  (SPEC-ENTITY-CARD §8.1), as a separate profile: never read one in place of
  the other.
- Process **only** the KYA-OS proof key; ignore every other `_meta` key (never
  hash it, never trust it).
- **Never reject** a response merely because `_meta` also carries non-KYA-OS
  keys, including the MCP-reserved `io.modelcontextprotocol/*` and the W3C Trace
  Context keys `traceparent` / `tracestate` / `baggage`.

This holds under the default `strict` `metaPolicy`; `allow-extensions` shares the
same trust boundary but additionally surfaces non-KYA-OS keys to the application
layer. See SPEC §7.6.

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
| L3.9a | Verify it only with a key the issuer's DID document lists under `assertionMethod`, from a conforming method whose id is under the issuer's DID, whose `controller` is the issuer and that the document defines once; a VC-JWT by its non-empty `kid`, or with none by the first `assertionMethod` entry (SPEC §6.2) | `src/delegation/__tests__/delegation-key-relationship.test.ts`; `conformance/vectors/delegation-chain-key-relationship.json` and `conformance/vectors/status-list-key-relationship.json` | All tests; every vector in both files |
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
| L3.27 | Derive authorization from the VC; treat L2 chain/scope headers as advisory | — | Spec-defined behavior (SPEC §8.1) |
| L3.28 | Compute the delegation chain digest and the delegation reference, holding each credential to the nesting bound; reject a chain that is not the one a proof binds, a credential that is not the one it names, and an outcome that is not the one expected | `src/delegation/__tests__/chain-digest.test.ts`, `src/delegation/__tests__/delegation-ref.test.ts`, `src/delegation/__tests__/signed-form.test.ts`, `src/proof/__tests__/delegation-chain-binding.test.ts`, `src/proof/__tests__/outcome-binding.test.ts` | `reproduces the SPEC Appendix C.4 vector`; `delegationReference` (all tests); `of an object nested as deep as a credential may be` (all tests); `a verifier that holds the chain` and `the credential a proof names, for a verifier that holds the chain` (all tests); `a verifier that requires an outcome` (all tests) |

### Detailed Requirements

#### L3.1 — VC Issuance

Implementation MUST:
- Produce valid W3C Verifiable Credential structure
- Include `@context` with VC v1 and KYA-OS delegation context
- Include `type` array with `VerifiableCredential` and `DelegationCredential`
- Include `issuer` as DID string or object with `id`
- Include `issuanceDate` in ISO 8601 format
- Include `credentialSubject` with delegation details
- Include `proof` as SPEC.md §6.2 specifies: an Ed25519 signature over the JCS canonicalization of the credential without `proof`, in `proofValue` as unpadded base64url. This is not the W3C `Ed25519Signature2020` suite, despite the `proof.type` value ([#184](https://github.com/decentralized-identity/kya-os-mcp/issues/184))

#### L3.5 — VC Verification

Implementation MUST validate:
- `@context` starts with W3C VC v1 context
- `type` includes required types
- `issuer` is present and valid
- `issuanceDate` is present and in the past
- `expirationDate` (if present) is in the future
- `credentialSubject.delegation` has required fields
- `proof` is present and verifies as SPEC.md §6.2 specifies

#### L3.11 — StatusList2021 Checking

Implementation MUST:
- Fetch StatusList2021 credential from `credentialStatus.statusListCredential`
- Verify the list's `proof` as SPEC.md §6.2 specifies, and reject the credential when it does not verify
- Reject the credential unless the list's `issuer` is the one keeper of the entry's `statusListCredential` URL (SPEC.md §6.6), decided before the list is fetched: the issuer the verifier's configuration binds that exact URL to, else the issuer it binds the URL's `https:` origin to, else the root issuer of the credential's delegation chain when the verifier pins that root and the root's own credential's status entry names the same URL, else the credential's issuer
- Reject the credential when the list's `statusPurpose` does not include `credentialStatus.statusPurpose`, or is an array on any list, a `StatusList2021Credential` included, but a `BitstringStatusListCredential` whose subject's `type` is `BitstringStatusList`; read such a list when its array of strings includes `credentialStatus.statusPurpose` (W3C Bitstring Status List v1.0 §2.2)
- Reject the credential when the list's `id` is not, byte for byte, `credentialStatus.statusListCredential`; only a list the credential's own issuer signed, where the verifier pins no other root and its configuration names no other issuer, may state no `id`, and an implementation at this level reads such a list (`status-list/no-id-list`), though SPEC.md §6.6 lets a reader refuse it, as the reference `CheqdStatusListResolver` does
- Reject the credential when `credentialStatus.statusSize` is stated and is not an integer greater than zero (`status-list/status-size-zero`), and never read an entry of more than one bit from the bit at its `statusListIndex`, which is another entry's (`status-list/status-size-two-bits`); the reference readers reject every entry whose `statusSize` is not 1, and read one that states 1 as one that states none (`status-list/status-size-one`)
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

A conformant implementation MAY satisfy part of this requirement using the
signed detached-JWS proof attached to each outcome: `denied`, `step_up_required`,
and `needs_authorization` responses carry a proof whose `meta.outcome` records
the authorization decision (success proofs omit `outcome`, implying `allowed`).
Such proofs are themselves tamper-evident signed records.

Audit records MUST be tamper-evident (e.g., append-only log, signed entries, or equivalent) and MUST be retained for at least the duration of the longest-lived delegation in the system.

> **Note:** Revocation is verifier-local (checked against the verifier's local list or cache). L1 implementations MAY use simple local checks; higher levels MAY use StatusList2021.

#### L3.27 — VC-Authoritative Layer-2 Headers

The Verifiable Credential is authoritative for granted authority. A conformant
verifier MUST:
- Derive granted scopes and the delegation chain from `KYA-OS-Delegation-Credential`
  (the VC-JWT) — its embedded scopes, its chain to a trusted root, and its
  StatusList revocation state — together with the `KYA-OS-Delegation-Proof` JWT.
- Check that `KYA-OS-Agent-DID` equals the Layer-1 signature's resolved DID.
- **NOT** use `KYA-OS-Delegation-Chain` or `KYA-OS-Granted-Scopes` for any
  authorization decision; these are OPTIONAL advisory transport hints and MUST be
  ignored when they disagree with the credential.

Because authority is derived only from signed artifacts (the VC and the proof
JWT), the Layer-2 headers are NOT required to be RFC 9421 covered components; a
tampered advisory header is ignored, not a vulnerability. See SPEC §8.1.

#### L3.28 - Delegation Chain Binding

A response proof may bind the delegation chain its server evaluated, as `delegationChainDigest` (SPEC §7.8).
Emitting the claim is OPTIONAL: a verifier that predates it rejects a proof that carries it, so a producer opts in.

An implementation that emits it MUST:
- Compute it as SPEC §7.8 defines, over every credential it evaluated, root to leaf, and reproduce the Appendix C.4 vector
- Verify each credential's signature over the same signed form the digest is taken over
- Derive `delegationRef` as SPEC §7.8 defines: the id the credential shows, or the SHA-256 of an id that is too long, holds a character that does not print or a lone surrogate, reads as a digest, or is the word `unknown`
- Set both on the proof of a refused call as well as an allowed one, over what it had examined when it refused, and set no digest where the presented value, or a credential it examined, has no signed form, or where a value it was handed for the chain could not be read

Signing either claim from the server is not part of this release of the reference implementation: its server sets neither `delegationRef` nor `delegationChainDigest`, and its verifier checks both against a chain it is given.

A verifier that is given the chain MUST:
- Reject a proof whose outcome is not the one it expects, which is an allowed call unless it is checking a refusal: a refusal binds what was presented, not what is valid
- Recompute the digest and reject the proof when it differs from the signed value
- Reject a proof that carries no `delegationChainDigest`: an equal `delegationRef` does not bind a chain
- Reject a proof whose `delegationRef` is not the reference of the chain's last credential

Both MUST hold every credential to the nesting bound of SPEC §7.8, counting before they parse, copy or canonicalize it.
A credential whose arrays and objects nest 64 levels deep is read.
A credential object nested deeper has no signed form, and the header or payload of a VC-JWT nested deeper is not read as JSON.
Neither reports its own failure to read a value, a call stack that ran out say, as a value with no signed form.

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

## Independent Conformance Harness

The `conformance/` directory contains an **implementation-agnostic** test harness:
a set of versioned, pre-signed test vectors plus a runner that asserts a verifier
ACCEPTS every positive vector and REJECTS every negative one. It exercises the
protocol's **public** verify primitives — it does not fork verification logic — so
the reference implementation and any third-party implementation are held to the
exact same evidence.

### What it covers

Each vector is a self-contained JSON object — `{ id, category, description, input,
expected: "pass" | "fail", reason }` — and carries fully-formed signed artifacts
so it is reproducible against any implementation without re-signing.

| File | Category | Positive | Negative |
|------|----------|----------|----------|
| `vectors/signed-proof.json` | Detached proof verification | valid signature + in-window ts; envelope content binding (profile `org.kya-os/response-proof.envelope`); delegation chain binding on an allowed call, on a refusal held as a refusal, and against a re-serialized copy of the chain (`delegationChainDigest`); a credential whose id is too long to record, or holds a bidi override, a zero-width space or a code point that renders as nothing by default, or is the word `unknown`, named by its digest (`delegationRef`); a request with no `params`, bound by its method alone | tampered signature, tampered meta, wrong key, timestamp skew exceeded; tampered `structuredContent` under envelope coverage, `prf` stripped (downgrade), unknown profile; chain with a re-issued hop, chain digest stripped, proof that binds no chain, a refusal held against its chain with no outcome stated, a chain whose VC-JWT signature is not base64url, a proof that names another credential of its chain; a JWS segment with a character outside base64url, white space or padding, or written in the base64 alphabet, a JWS of four segments, a claim of `meta` altered after signing, a proof held against another request, a header that names another algorithm or another key, a `kid` of another DID than `meta.did` |
| `vectors/delegation-chain.json` | Delegation chain verification | single-hop, two-hop attenuated | broken issuer↔subject linkage, scope widening, a scope under a parent that states none, tampered signature, audience mismatch |
| `vectors/delegation-chain-key-relationship.json` | Delegation chain verification: the issuer's key (SPEC.md §6.2) | signed with the key the issuer lists under `assertionMethod`; as a VC-JWT with no `kid`, signed with the key its first `assertionMethod` entry names | signed with a key it lists only under `authentication`, proof stating `proofPurpose: "authentication"`, issuer document whose `id` is another DID, signing key whose method names another DID as its `controller`, signing key whose method the document defines twice, signing key under another DID's id, signing key under no relationship, signing key whose method has no `type` or no `controller`; as a VC-JWT, a `kid` naming the `authentication` key, an empty `kid` |
| `vectors/status-list.json` | StatusList2021 and Bitstring Status List revocation | active (bit unset), issuer's list stating no `id`, Bitstring list declaring two purposes | revoked (bit set), list altered after signing, list signed by another issuer, list of another purpose, StatusList2021 list declaring its purposes in an array, list stating another URL as its `id`, list of a pinned root or a configured issuer stating no `id` |
| `vectors/status-list-key-relationship.json` | StatusList2021 revocation: the list issuer's key (SPEC.md §6.2) | list signed with the key the issuer lists under `assertionMethod` | list signed with a key it lists only under `authentication`, list proof stating `proofPurpose: "authentication"`, issuer document whose `id` is another DID, list signed with a key it lists under `assertionMethod` whose method names another DID as its `controller`, list signed with a key whose method the document defines twice |
| `vectors/status-list-authority.json` | Status list revocation: who may sign a credential's list (SPEC.md §6.6) | pinned root's list at the URL its own credential names, list of a service the verifier binds the exact URL or its origin to, issuer's own list stating no `id` while also named as root, with or without the URL its credential names, index with leading zeros, entry stating a `statusSize` of 1 | pinned root's list at a URL its credential does not name, service bound to no URL, to another URL or to a look-alike origin, issuer's own list at a URL bound to a service, pinned root's list at a URL the configuration binds to a service, pinned root's list stating no `id` for a delegate's credential, issuer's list stating no `id` at a pinned root's URL, index with a suffix, a fraction or a space, index given as a number, entry of two bits whose own bits are set, entry stating a `statusSize` of 0 |
| `vectors/did-key-resolution.json` | did:key resolution | valid Ed25519 | malformed multibase, wrong method |
| `vectors/did-web-resolution.json` | did:web resolution | well-formed id-matched document | document id mismatch, not found |
| `vectors/card-proof.json` | `org.kya-os/proof.v1` holder-of-key proof | valid signed proof, in-window, audience-bound | tampered body, tampered signature, wrong audience, expired, kid⇄did forgery |
| `vectors/entity-card.json` | Entity Card `parseCard` + `verifyCard` | golden card per `entityType`, accountable agent | malformed (unknown field), broken accountability JOIN |
| `vectors/audit-integrity.json` | Audit JCS + domain-separated hashing + RFC 9162 | fixed Unicode event, leaf/root, inclusion and consistency paths | mutated event/proof relationships are exercised by the audit unit suites |
| `vectors/negotiation.json` | MCP extension admission gate (`org.kya-os/decentralized-authority`) | declared and malformed-degrades-to-core (optional server); empty-object and initialize-era declarations, `server/discover` exemption (required server) | absent against a required server (`-32021`), present-but-malformed against a required server (`-32602`, malformed_declaration) |

The first five categories exercise the **legacy** session-bound primitives; the
next two exercise the **Entity Card** layer (see the dedicated section below),
`audit-integrity` provides language-neutral bytes and hashes for the audit
protocol, and `negotiation` exercises the MCP extension admission gate
(`org.kya-os/decentralized-authority`, SPEC-MCP-EXTENSION.md §3-§5).

A `fail` vector passes the suite only when the implementation correctly **rejects**
it. The runner exits non-zero on any mismatch.

**On the envelope-profile vectors (`signed-proof/envelope-*`, `prf-stripped-downgrade`, `unknown-profile`; suite ≥ 1.1.0).**
These exercise the `org.kya-os/response-proof.envelope` profile (SPEC.md §7.3): `responseHash` covers the full result envelope with the top-level `_meta` member removed, discriminated by a signature-covered `prf` claim.
Their inputs carry an OPTIONAL `expected` member (`{ request, response }`) — the content the verifier "received" — which a conformant verifier re-hashes under the proof's own `prf` profile and reconciles against the bound hashes.
Vectors without `expected` remain pure signature/skew checks.

**On `signed-proof/tampered-meta`.**
The proof's `meta` block mirrors the claims signed inside the JWS, but it is a convenience for consumers that read the proof without decoding the token, not an authoritative copy.
This vector leaves the JWS byte-identical to `valid-basic` and alters only the mirrored `meta.requestHash`, so the JWS signature still verifies.
A conformant verifier MUST reconcile `meta` against the decoded JWS payload and reject on any mismatch.
Signature validity alone does not pass this vector: it is the `requestHash` counterpart of the `responseHash` recompute rule in L2.11.

**On the chain-binding vectors (`signed-proof/delegation-chain-*` and `signed-proof/delegation-ref-*`; suite 1.5.0 or later).**
These exercise `delegationChainDigest` and `delegationRef` (SPEC.md §7.8, L3.28): a proof binds the delegation chain its server evaluated, and `input.expected.delegationChain` is the chain the verifier holds, root first.
`input.expected.outcome`, where present, is the outcome the verifier expects; where absent, a verifier that is given a chain expects an allowed call.
Either of the two given as `null` is absent.
The chain is three §6.2 credentials, each signed by its issuer: two credential objects and a VC-JWT leaf, so both signed forms are covered.
`delegation-chain-reserialized` supplies another copy of the same credentials: proof metadata outside the signature is edited, and the three signatures are written with padding, with a line break, and with spare bits set.
It must pass: an implementation that hashes a credential's bytes as received, rather than its signed form, fails it, and so does one that reads a signature string otherwise than §7.8 says.
`delegation-chain-substituted` replaces the middle credential with one its issuer signed again under the same id, so every id and parent link still matches and only the digest tells the chains apart.
`delegation-chain-unbound` is an authentic proof that names its credential by `delegationRef` alone: a verifier that is given a chain must reject it, where one that only checks the signature accepts.
`delegation-chain-refused` and `delegation-chain-refused-outcome-unstated` are one denial proof, which binds the chain its server refused.
Held as a refusal (`expected.outcome: "denied"`) it must pass; held against the same chain with no outcome stated it must fail, since a refusal is no evidence that the chain was accepted, however well its digest matches.
`delegation-chain-no-signed-form` supplies the bound chain with the VC-JWT leaf's signature rewritten in the base64 alphabet (`+` and `/`): that string is not a JWS segment, the leaf has no signed form, and no proof binds such a chain.
An implementation that reads a VC-JWT's signature as loosely as a `proofValue` passes a chain it must reject.
`delegation-ref-substituted` is an authentic proof whose digest binds the chain and whose `delegationRef` names the chain's root: a verifier must hold the reference against the chain's last credential and reject it.
`delegation-ref-digest-form` binds a single credential whose id is longer than 256 UTF-16 code units, named on the proof by the SHA-256 of the id; a verifier that compares `delegationRef` with the id itself fails it.
`delegation-chain-nested-at-bound` and `delegation-chain-nested-past-bound` are single credential objects whose arrays and objects nest 64 and 65 levels deep, each signed by its issuer.
The first must pass: an implementation whose own limit is lower than the protocol's refuses a credential it must read.
The second carries the chain digest an implementation that counts no nesting takes of its credential, and must fail: a credential object nested past the bound has no signed form, so an implementation that does not apply the bound passes a chain it must reject.
`delegation-ref-jwt-nested-at-bound` and `delegation-ref-jwt-nested-past-bound` are single VC-JWTs whose payloads nest 64 and 65 levels deep.
The first is named by the id its payload shows.
The second is a denial proof that binds the VC-JWT, by its segments as received, and names no credential, held as a refusal.
It must pass: a payload nested past the bound is not read as JSON, so an implementation that parses it derives an id the proof does not carry, and rejects a proof it must accept.
`delegation-ref-jwt-long-number` is a denial proof that binds a single VC-JWT whose payload holds an integer of 4301 digits, held as a refusal.
It must pass, naming the credential by the id its payload shows: JSON sets no limit on a number's length, so an implementation whose parser refuses a long integer derives no id, and rejects a proof it must accept.
`delegation-ref-jwt-duplicate-id` is a denial proof that binds a single VC-JWT whose payload holds the credential's `id` twice, another id written ahead of the issuer's, held as a refusal.
It must pass, naming the credential by the id written last: of the members of one object that share a name the last is read, so an implementation whose parser keeps the first names another credential, one whose parser refuses the payload names none, and each rejects a proof it must accept.
`delegation-chain-number-read-as-binary64` binds a credential object that holds `9007199254740993.5`, which is no integer as written and reads as the IEEE 754 binary64 value 9007199254740994.
Its issuer signed it as a canonicalizer that holds numbers to no rule writes it, and the proof carries the chain digest that canonicalizer gives.
It must fail: read as binary64 the number is an integer of magnitude above 2^53 - 1, so the credential has no RFC 8785 form and no signed form, and an implementation that asks whether the number is an integer as written passes a chain it must reject.
`delegation-ref-control-at-bound` and `delegation-ref-control-past-bound` bind single credentials whose ids are U+001F alone, the last C0 control character, and U+0020 alone, the first character past the C0 controls.
The first is named by the SHA-256 of its id and the second by the id itself, so the edge of the control range is pinned from both sides.
`delegation-ref-digest-form-suffixed` binds a credential whose id is `sha256:` followed by 64 lowercase hexadecimal digits and one more character, named by the id itself: only an id that is exactly of the digest form is replaced by its own digest.
`delegation-ref-bidi-override` and `delegation-ref-zero-width` bind single credentials whose ids hold U+202E, a right-to-left override, and U+200B, a zero-width space, each named by the SHA-256 of its id.
Neither is a control character, and each prints as something other than the id holds, so an implementation that hashes only the ids with a control character names the credential by the id itself.
`delegation-ref-grapheme-joiner`, `delegation-ref-hangul-filler`, `delegation-ref-variation-selector` and `delegation-ref-variation-selector-supplement` bind single credentials whose ids hold U+034F, a combining grapheme joiner, U+3164, a Hangul filler, U+FE0F, a variation selector, and U+E0100, a variation selector outside the basic plane, each named by the SHA-256 of its id.
None is a control or format character, and each renders as nothing by default, so an implementation that hashes only the ids with a control or format character names the credential by the id itself.
`delegation-ref-unknown` binds a credential whose id is the word `unknown`, named by the SHA-256 of its id: an audit record names a credential that shows no id by that word, so no credential is named by it.
`delegation-chain-proto-member` binds a credential object whose issuer signed a member named `__proto__`.
It must pass: the member is part of the signed form, so an implementation that copies a credential by assignment, which makes `__proto__` the copy's prototype rather than a member of it, digests less than the issuer signed and rejects a proof it must accept.
An implementation that predates suite 1.5.0 fails these vectors, which is the conformant outcome for it: it rebuilds the signed payload without `delegationChainDigest`, so it rejects the proofs that must pass, and it accepts `delegation-chain-unbound`, whose expected chain it does not read.

**On the proof-as-received vectors (`signed-proof/delegation-proof-*`; suite 1.5.0 or later).**
These hold a verifier to the proof as it receives it (SPEC.md §7.3, §7.4, L1.4): each but the last alters one thing of the `delegation-chain-binding` proof, or of what its verifier holds, and must fail for that thing, however well the chain matches.
`delegation-proof-signature-stray-character` and `delegation-proof-signature-stray-characters` put characters outside base64url in the signature segment, `delegation-proof-signature-base64` writes that segment in the base64 alphabet, padded, and `delegation-proof-header-non-ascii` puts U+00E9, a letter outside ASCII, in the header segment.
`delegation-proof-signature-white-space` puts a line break in the signature segment, and `delegation-proof-signature-padded` pads it with `=` to complete its last group.
A decoder that passes over characters outside its alphabet, white space or padding, or reads both alphabets, reads the bound proof's bytes from each, but none of them is a JWS segment as SPEC.md §7.4 reads one, base64url as RFC 7515 §2 writes it, so none is a JWS.
`delegation-proof-fourth-segment` appends a fourth segment: a compact JWS is three, and a verifier that reads the first three of four verifies a JWS that is none.
`delegation-proof-request-hash-altered`, `delegation-proof-nonce-altered` and `delegation-proof-session-altered` keep the bound JWS and alter one claim of `meta` after signing: every claim is held to the payload the signature covers, rebuilt from `meta`, so a verifier that compares only the delegation claims with the payload passes the last two.
`delegation-proof-request-substituted` holds the bound proof against the chain it binds and another call than the one it proves.
`delegation-proof-header-algorithm` and `delegation-proof-header-key` are the bound claims signed again with the server's key under a header that names HS256, or another key of the server's DID, and `delegation-proof-signer-of-another-did` is signed again over a `meta` whose `did` is another DID than the one `meta.kid` names a key of.
Each of the three verifies as a signature under the key the vector gives, and none is the server's proof.
`delegation-proof-request-without-params` must pass: a request with no `params` is hashed as `JCS({method})`, so its proof binds the method alone.

**On `status-list/tampered-list` (suite ≥ 1.2.0).**
This vector carries the revoked credential and its signed list with the revoked bit cleared and the list's proof left as signed.
A verifier that reads the bits without verifying the list's proof reports the credential active and passes a vector it must reject (L3.11).
Suites before 1.2.0 shipped a list whose proof did not verify, so an implementation that checked it failed `status-list/active-credential`.

**On the key-relationship vectors (suite ≥ 1.3.0).**
Their issuer is a did:web whose DID document lists `#login-1` under `authentication` and `#assert-1` under `assertionMethod`.
Each file has one vector a verifier accepts, signed with `#assert-1`, and five that it rejects, each for one thing: the credential, or its status list, signed with `#login-1`; its proof stating `proofPurpose: "authentication"`; the document supplied for the issuer naming another DID as its `id`; that document naming another DID as the `controller` of the key that signs; or that document defining the method of the key that signs twice, in `verificationMethod` and again embedded in `assertionMethod`.
A verifier that takes any key the document publishes, accepts a proof that states `authentication`, reads a document without checking whose it is, takes a key whose method another DID controls, or takes the first of two definitions of a method, passes a vector it must reject (L3.9a).
In `status-list/issuer-document-id-mismatch` the list's issuer is the credential's, so one document serves both proofs, and a conformant verifier rejects the credential's proof before it reads a bit.
For the same reason, `status-list/assertion-key-other-controller-list` signs the list with `#login-1` and has its document also list that key under `assertionMethod`, with another DID as its controller, so that the credential's proof verifies and the list's does not.
`status-list/assertion-key-defined-twice-list` signs the list with `#login-1` too, and has its document embed a second definition of it in `assertionMethod`.
The delegation file also rejects a delegation whose key the document publishes under another DID's id, under no relationship, or with no `type` or no `controller`.
It also carries the delegation as a VC-JWT, as a string `leaf`.
With no `kid`, it verifies with `#assert-1`, the key the first `assertionMethod` entry names, though the document publishes `#login-1` first.
With a `kid` naming `#login-1`, or an empty `kid`, it is rejected; the empty-`kid` VC-JWT is signed with `#assert-1`, so a verifier that reads an empty `kid` as none accepts it.
The Entity Card's `eddsa-jcs-2022` proofs on status lists and delegation hops have no vector: no adapter method verifies such a proof, and the card vectors carry placeholder proofs.
`conformance/__tests__/key-relationship-vectors.test.ts` shows that the reference adapter rejects each negative for its one thing, and accepts it once that thing is undone.
`conformance/__tests__/credential-proof-construction.test.ts` checks every credential, status list and VC-JWT in the `delegation-chain` and `status-list` vectors against the SPEC.md §6.2 text, with `node:crypto` and an RFC 8785 library and none of the package's verifier code.
It checks the specification's construction against the bytes the suite ships; it is not an implementation, and no adapter runs it.

**On `status-list/foreign-issuer-list`, `purpose-mismatch-list`, `purpose-array-2021-list` and `id-mismatch-list` (suite ≥ 1.4.0).**
Each carries a revoked credential and, at its `statusListCredential` URL, a list with the credential's bit unset whose proof verifies against a DID document the vector supplies.
Each list is the credential issuer's list in all but one respect: another DID issued and signed it, its `statusPurpose` is `suspension`, its `statusPurpose` is the array `["suspension", "revocation"]`, or it states another URL as its `id`.
A verifier that checks only that the list's proof verifies reports the credential active and passes a vector it must reject (L3.11).
The list's `issuer` must be the keeper of the entry's URL (SPEC.md §6.6), its `statusPurpose` must include the entry's, and its `id` must be, byte for byte, the URL it was fetched from.
A `StatusList2021Credential` states its `statusPurpose` as one string (Verifiable Credentials Status List v2021 §2.2), so the list of `purpose-array-2021-list` is refused although its array includes the entry's `revocation`, while a verifier reads the same array on the Bitstring Status List of `purpose-array-list`.

**On `status-list/root-no-id-list` and `configured-issuer-no-id-list` (suite ≥ 1.4.0).**
Each carries a revoked credential and, at its `statusListCredential` URL, a list with the credential's bit unset whose proof verifies, signed by the issuer the vector has keep the credential's list URL, and re-issued without an `id`.
In `root-no-id-list` a delegate of the list's issuer issued the credential, and the vector's `trustedRootIssuer` pins the list's issuer as the root of the credential's chain, with the list's URL as `trustedRootStatusList`, the URL the root's own credential names.
In `configured-issuer-no-id-list` the vector's `statusListIssuers` binds the list's URL to the list's issuer, the DID that signs `foreign-issuer-list`.
Only the `id` binds a list to the URL it is served at, so a list from an issuer other than the credential's must state it (SPEC.md §6.6), and a verifier that reads either list reports the credential active and passes a vector it must reject (L3.11).
A verifier without the configuration a vector carries refuses the list for its issuer, which fails closed as well.

**On `status-list/no-id-list` and `purpose-array-list` (suite ≥ 1.4.0).**
Each carries an active credential and a list its issuer signed, in a form W3C Bitstring Status List v1.0 §2.2 allows.
In `no-id-list` the issuer's list is re-issued without an `id`, which a list the credential's own issuer signed may leave out where no other root is pinned and the configuration names no other issuer.
In `purpose-array-list` the credential's `credentialStatus` is a `BitstringStatusListEntry`, and its list a `BitstringStatusListCredential` whose `statusPurpose` is the array `["suspension", "revocation"]`.
The credential's bit is unset and the list's proof verifies, so a verifier that refuses either form denies an active credential and fails a vector it must pass (L3.11).

### Running the reference implementation

```bash
pnpm install
pnpm run conformance               # run all vectors, exit non-zero on any mismatch
pnpm run conformance -- --category signed-proof   # one category
pnpm run conformance -- --json     # machine-readable report
```

CI runs this on every push/PR (the **Protocol Conformance Harness** job).

### Regenerating the vectors

The committed JSON is produced from the reference primitives:

```bash
pnpm run conformance:generate
```

Re-running mints fresh keys but preserves every positive/negative relationship by
construction.
The key-relationship files have their own generator, `pnpm run conformance:generate:key-relationship`, which also mints fresh keys.
`status-list-authority.json` has its own generator too, `pnpm run conformance:generate:status-authority`, which also mints fresh keys and writes no other file.
Because fresh keys change the committed bytes, regenerated output MUST NOT be committed over an existing `suiteVersion` (see [Suite versioning and immutability](#suite-versioning-and-immutability)).

### Suite versioning and immutability

Suite 1.6.0 adds one `delegation-chain` vector, for 141 vectors total: `delegation-chain/scopeless-parent-widening`, a re-delegation that states a scope under a parent that states none, which must be refused, since a parent with no scopes grants none (SPEC.md §6.4).
`delegation-chain.json` is regenerated in one run, so its six earlier vectors are signed again with the same ids, cases and expected outcomes; the other 134 vector objects of suite 1.5.0 are unchanged.
`delegation-chain/tampered-signature` now changes the first character of the signature, where it changed the last, which in a 64-byte Ed25519 signature carries bits a decoder ignores.

Suite 1.5.0 adds 43 `signed-proof` vectors, for 140 vectors total: the `signed-proof/delegation-*` vectors described above.
`signed-proof.json` is regenerated in one run, so its nine earlier vectors are signed again with the same ids, cases and expected outcomes; the other 88 vector objects of suite 1.4.0 are unchanged.

Suite 1.4.0 adds 29 status-list vectors, for 97 vectors total: eight in `status-list.json` and 21 in a new file, `status-list-authority.json`.
`status-list.json` is regenerated in one run, so its three earlier vectors are signed again with the same ids, cases and expected outcomes; the other 65 vector objects of suite 1.3.0 are unchanged.
Nine of the 21 hold the keeper rule, over one credential, one list URL and a clear list that states its `id`, so only the list's signer and the configuration differ.
`pinned-root-list` requires reading the pinned root's list at the URL `trustedRootStatusList` says the root's own credential names, and `root-list-at-issuer-url` requires refusing the same list when the root's credential names another URL, since the URL is then the credential issuer's.
`configured-service-list` and `configured-origin-list` require reading the list of a service `statusListIssuers` binds the exact URL, or its `https:` origin, to.
`lookalike-origin-list` requires refusing it when the bound origin is only a prefix of the URL's host, an origin being matched on the bytes as written and continued only by `/`, `?` or `#`.
`unconfigured-service-list` and `service-list-at-unbound-url` require refusing it when `statusListIssuers` binds nothing, or another URL, to the service.
`issuer-list-at-bound-url` requires refusing the credential's own issuer's list at a URL bound to the service, and `configured-over-root-list` the pinned root's list at a URL that its credential names and the configuration binds to the service: the configuration decides first.
`owner-root-alias-no-id` requires reading a list that the credential's own issuer signed without an `id`, even when the verifier also pins that issuer as the root.
`pinned-root-own-no-id` requires reading it as well when the vector names the list's URL as the one that root's own credential names, and `pinned-root-no-id-for-delegate` requires refusing the same list for a delegate's credential whose entry names that URL, since the root is not that credential's issuer.
`owner-no-id-at-pinned-root-url` requires refusing such a list when the verifier pins another root whose credential names the list's URL, which that root then keeps.
`index-suffix`, `index-fraction`, `index-space` and `index-number` require refusing a signed entry whose `statusListIndex` is not a non-negative decimal string.
`index-leading-zeros` requires reading an index that opens with 4,300 zeros as the bit its value names.
`status-size-two-bits` requires refusing a signed entry that states a `statusSize` of 2: its value is set at bits 14 and 15 of its list and the bit at its index, 7, is clear, so an implementation that reads one bit at the index passes it.
`status-size-zero` requires refusing an entry whose `statusSize` is not an integer greater than zero, over a clear list.
`status-size-one` requires reading an entry that states a `statusSize` of 1, the size of an entry that states none, from the bit at its index.
Regenerating `status-list-authority.json` (see [Regenerating the vectors](#regenerating-the-vectors)) changes keys and bytes and still requires the version/manifest process below.

For these status-list vectors, `trustedRootIssuer` and `trustedRootStatusList` are already-authorized context for the supplied credential, not a chain or a root claim to authenticate: an implementation takes the second as the URL a root credential it has verified names.
The loader refuses a status-list vector whose `trustedRootIssuer` or `trustedRootStatusList` is present and not a non-empty string, or whose `statusListIssuers` is present and not an object that maps non-empty keys to arrays of strings starting with `https://` or `http://`, none of them under two keys, and `status_list.py` refuses the same inputs.
The category does not test chain admission, or how a verifier finds each hop's issuer and root.
Passing this category alone does not establish that an implementation authenticates chains.

The committed vector set is immutable at a given `suiteVersion`: the vector bytes may only change together with a `suiteVersion` bump.
`conformance/SUITE-MANIFEST.json` pins the current set (`suiteVersion`, `vectorSetHash`, `vectorCount`, per-file hashes) and is the anchor CI verifies against.
The hash recipe: SHA-256 each vector file's raw committed bytes, sort the `[filename, hex]` pairs by filename, canonicalize the array with RFC 8785 (JCS), SHA-256 that, prefix with `sha256:`.
CI enforces the invariant twice: a vitest guard (`conformance/__tests__/suite-immutability.test.ts`) and a dedicated step running `node conformance/suite-hash.mjs --check`.
To change vectors intentionally, bump `suiteVersion` (including the in-file `version` fields), regenerate the manifest with `node conformance/suite-hash.mjs --json`, and keep `pinnedAt` current.
A new suite version may add vectors that an implementation of an earlier one fails: suite 1.5.0 adds the `signed-proof/delegation-chain-*` and `signed-proof/delegation-ref-*` vectors, which a verifier built against suite 1.4.0 or earlier fails until it implements L3.28, and the `signed-proof/delegation-proof-*` vectors, which a verifier that reads a JWS more loosely than SPEC.md §7.4 fails, so a result is always reported with the suite version it was run against.
Suite 1.6.0 adds `delegation-chain/scopeless-parent-widening`, which a verifier that reads a parent with no scopes as unrestricted fails.
The SIGNED public suite manifest published by the Conformance Attestation Program is a separate artifact built on this committed one.

### Running the harness against YOUR implementation

The harness is decoupled from `@kya-os/mcp` through a single documented port,
`ConformanceAdapter` (`conformance/types.ts`). Implement its methods over your own
verifier and feed it the same vectors:

```ts
import { loadVectors } from "./conformance/loader.js";
import { runConformance, formatReport } from "./conformance/runner.js";
import type { ConformanceAdapter } from "./conformance/types.js";

const myAdapter: ConformanceAdapter = {
  name: "my-implementation",
  async verifySignedProof(input)      { /* return { outcome: "pass" | "fail" } */ },
  async verifyDelegationChain(input)  { /* a string leaf is a VC-JWT */ },
  async verifyStatusList(input)       { /* ... */ },
  async resolveDidKey(input)          { /* ... */ },
  async resolveDidWeb(input)          { /* ... */ },
  async verifyCardProof(input)        { /* org.kya-os/proof.v1 holder-of-key proof */ },
  async verifyEntityCard(input)       { /* parseCard + verifyCard */ },
  async verifyAuditIntegrity(input)   { /* JCS event digest + RFC 9162 proofs */ },
};

const report = await runConformance(myAdapter, loadVectors());
console.log(formatReport(report));
process.exit(report.allMatched ? 0 : 1);
```

**Adapter contract.** Every method takes a vector's `input` and returns
`{ outcome: "pass" | "fail", detail? }`, where `pass` means your implementation
ACCEPTED the artifact and `fail` means it REJECTED it. Methods MUST be
**fail-closed**: any error, malformed input, or unmet security property maps to
`{ outcome: "fail" }` — never throw. The runner records a thrown error as a
harness failure, not a rejection. The reference adapter
(`conformance/reference-adapter.ts`) is the worked example wiring these methods to
the public `@kya-os/mcp` primitives.

### Audit Assurance Profile conformance

An AAP claim is broader than a single vector result. An implementation MUST pass
all lower profiles and MUST truthfully advertise only mechanics its configured
providers can supply:

| Profile | Required executable evidence |
|---------|------------------------------|
| AAP-0 | No auditability claim. |
| AAP-1 Recorded | Strict event schemas and typed lifecycle capture for the declared instrumentation surface. |
| AAP-2 Chained | AAP-1 plus durable non-best-effort delivery and the journal provider contract, including atomic stale-head rejection, global idempotency, and ordered snapshot reads. |
| AAP-3 Transparent | AAP-2 plus durable source reconciliation, checkpoint signing, RFC 9162 inclusion/consistency vectors, epoch continuity, and historical verification. |
| AAP-4 Observed | AAP-3 plus the observer provider contract, independent administration, checkpoint view comparison/fork detection, and authenticated supporting-anchor verification where claimed. |

Reference adapter authors can run the framework-neutral suites exported by
`@kya-os/mcp/audit/testing`. Passing the in-memory reference suite demonstrates
the contract; it is not evidence that a production datastore, KMS, or observer
deployment satisfies its operational durability or independence claims.

---

## Entity Card Conformance

The Entity Card is a **distinct, newer layer** on top of the Level 1–3 ladder above:
a typed, DID-anchored card plus a stateless, sender-constrained per-request proof.
It is orthogonal to the legacy session-bound proof — the two coexist, each under
its OWN distinct `_meta` key (`_meta["org.kya-os/response-proof"]` for the legacy
session-bound proof, historically `org.kya-os/proof`; `_meta["org.kya-os/request-proof"]`
for the stateless card proof, whose object carries `prf: "org.kya-os/proof.v1"`),
and each verifier reads its own key and ignores the other. Its
conformance vectors live in the SAME harness under two categories, wired to the two
adapter methods `verifyCardProof` and `verifyEntityCard`.

### `card-proof` — the `org.kya-os/proof.v1` holder-of-key proof

`vectors/card-proof.json` carries fully-formed, pre-signed proofs. Each vector's
`input` is self-contained: the proof object, the `request` it binds, the DID-keyed
`jwks` the signing key resolves from, the verifier's `expectedAudience`, and a
pinned `nowMs`/`skewSeconds` window. A conformant `verifyCardProof` MUST recompute
**every** binding and fail closed on the first that does not hold:

| Vector | Expected | Property under test |
|--------|----------|---------------------|
| `card-proof/valid` | pass | signature + `requestHash` + `audience` + nonce + window + `kid`⇄`did` all hold |
| `card-proof/tampered-body` | fail | `requestHash` no longer recomputes to the signed value |
| `card-proof/tampered-signature` | fail | mutated detached-JWS signature fails EdDSA verification |
| `card-proof/wrong-audience` | fail | `audience` ≠ the verifier (anti-relay / confused-deputy) |
| `card-proof/expired` | fail | evaluated outside `created`/`expires` (±skew) — replay guard |
| `card-proof/kid-did-forgery` | fail | `kid.split('#')[0] !== did` — the forgeable-principal gap |

### `entity-card` — the typed card (`parseCard` + `verifyCard`)

`vectors/entity-card.json` ships the golden `parseCard`-valid card for each
`entityType` (`mcp` \| `agent` \| `client` \| `verifier` \| `human`), the accountable
agent card (whose `responsibleParty === issuer(rootVC)` and leaf-invoker === proof
`did` recompute over an embedded multi-hop VC 2.0 + ZCAP-LD chain), and negatives:
a malformed card (unknown top-level property → the strict schema rejects) and a
broken accountability JOIN (leaf-invoker ≠ the asserted proof `did`). A conformant
`verifyEntityCard` MUST reject a malformed card and MUST NOT trust the card's
self-declared `conformanceLevel` — it recomputes it.

### Card conformance ↔ the L1/L2/L3 ladder

The card's conformance level is **recomputed**, never trusted from the card. It maps
onto the same ladder:

- **L1** — the card parses (`parseCard`) and its DID + key are well-formed; capabilities
  are self-declared (bare strings). The CIMD on-ramp (`client_id` ⇄ `did:web`) sits here.
- **L2** — every declared capability is attested (a verified `CapabilityAttestation`),
  and, for a card carrying `responsibleParty`, the delegation/accountability edge verifies
  offline (`responsibleParty === issuer(rootVC)`).
- **L3** — L2 **plus** a valid live holder-of-key proof (a passing `card-proof` vector)
  bound to the request, fused with the token's RFC 9449 `cnf.jkt` (`L3`) or standalone
  (`L3-minus`), and a fresh (live) revocation status. Any missing/expired/revoked artifact
  demotes L3 → L2 → L1, fail-closed.

### Cross-language reference (`conformance/verify.py`)

`conformance/verify.py` is the **second-language complement** to the adapter contract:
a pure-Python-stdlib re-implementation that shares no code with the TypeScript
reference. It verifies the positive `org.kya-os/proof.v1` vector and independently
re-derives the audit event's RFC 8785 bytes, domain-separated digest, RFC 9162
root, inclusion path, and consistency path. Ed25519 uses the RFC 8032 reference
without `pip install`.
It also checks every positive and negative status-list vector via `status_list.py`, independently deriving signer authority, exact id/purpose binding, both credential and list signatures, bounded gzip decoding, and the indexed bit.
This reader is restricted to the vectors' Ed25519Signature2020/JCS, one-bit profile; it is not a general VC engine and does not authenticate a chain from `trustedRootIssuer`.
The raw-chain differential test, `conformance/__tests__/status-list-independent.test.ts`, compares 13,608 cases against that Python authority predicate, including root-pin mismatch, role collisions, mapping direction, malformed values and exact URL binding.
This finite partition complements the 56,700-case decision table; neither is an exhaustive proof.
That test, `status-list-configuration.test.ts`, and `crosslang-verifier.test.ts`, which runs this script in isolated mode (`-I`), use the first of `python3`, `python` and `py -3` that runs Python 3.9 or later.
Without one, they fail when the `CI` environment variable is set, and are skipped with the reason otherwise.
The published runtime gains no dependency.
It also runs the `signed-proof/delegation-*` vectors, and holds every `signed-proof` vector to the verdict it expects.
It holds each response proof as the TypeScript verifier holds it: to its form, its signer, its time and its signature, each segment of its JWS and the key's `x` read as SPEC.md §7.4 reads them, the signature checked over the payload rebuilt from `meta`, and a key of small order refused; then to the request and the response it binds.
It recomputes the delegation chain digest and the delegation reference of SPEC.md §7.8 from the credentials, and holds them and the proof's outcome against what the proof signs, for the positive vectors and for each negative one's intended reason.
It reads a `null` as the TypeScript verifier does: a chain or an outcome the verifier gives as `null` is none, and a claim the proof's `meta` gives as `null`, or out of the form `schemas/detached-proof.json` gives it, makes no proof.
It holds its reading of a signed form, and of a credential's id and reference, to the cases the TypeScript tests hold theirs to (`src/delegation/__tests__/chain-digest.test.ts`, `src/delegation/__tests__/delegation-ref.test.ts`): the values §7.8 gives no signed form are refused, and the others come to the same digests and references.
It holds its reading of a response proof to the cases the TypeScript reference is held to under the same names (`conformance/__tests__/proof-path-cases.test.ts`): the verifier's clock, skew and key, the JWS as received, the request, the response and the chain it holds, and each claim signed again with the test key of RFC 8032 §7.1.
The cases sign the payload §7.4 lists, written out apart from the code that rebuilds it, with a signer first held to the public key and the signature RFC 8032 gives for that key.
`verify.py` is the driver: it reads the vector files, makes each check, and reports it under its name.
What it checks with is in the modules beside it in `conformance/`, one job to each, which its docstring lists: `ed25519.py`, `strict_json.py`, `base64url.py`, `digests.py`, `card_proof.py`, `audit_merkle.py`, `status_list.py` for the status-list vectors, `response_proof.py` for §7.3 and §7.4, and for §7.8 `signed_form.py`, `delegation_ref.py`, `chain_binding.py` and `delegation_cases.py`, which holds the cases above, with `proof_cases.py` holding those of a response proof.

```bash
python3 conformance/verify.py       # npm run conformance:verify:crosslang
npm run conformance:generate:card   # deterministically regenerate the card vectors
```

Expected output:

```
KYA-OS cross-language verifier (Python 3.x, stdlib-only)
  proof: org.kya-os/proof.v1  did: did:web:example.com:agents:acme-pay
  [PASS] requestHash JCS+SHA-256 recompute
  [PASS] detached EdDSA JWS over JCS(coveredClaims)
  [PASS] RFC 9421 httpSig over the signature base
  [PASS] RFC 7638 cnf.jkt thumbprint fusion
  [PASS] audit event JCS canonical bytes
  [PASS] full JCS value space (fractions, exponents, non-BMP keys)
  [PASS] domain-separated audit event digest
  [PASS] RFC 9162 audit Merkle root
  [PASS] RFC 9162 audit inclusion proof
  [PASS] RFC 9162 audit consistency proof
  [PASS] status-list/pinned-root-list
  [PASS] status-list/root-list-at-issuer-url
  ... one result for every status-list vector ...
  [PASS] delegation chain digest signed by an allowed call's proof
  [PASS] same digest for a copy of the chain that differs in nothing signed
  [PASS] delegation chain digest signed by a refusal's proof, held as a refusal
  [PASS] refusal's proof held against its chain with no outcome stated is no acceptance
  [PASS] re-issued hop under the same id changes the chain digest
  [PASS] chain digest stripped from meta no longer matches the signed payload
  [PASS] proof that only names a credential binds no chain
  [PASS] chain whose VC-JWT signature is not base64url has no digest to bind
  [PASS] proof that binds a chain and names another of its credentials
  [PASS] credential id too long to record is named by its SHA-256
  [PASS] credential nested 64 levels deep, as deep as one may be, is bound
  [PASS] credential nested 65 levels deep has no signed form, so no digest to bind
  [PASS] VC-JWT whose payload nests 64 levels deep is named by the id it shows
  [PASS] VC-JWT whose payload nests 65 levels deep shows no id, and is still digested
  [PASS] VC-JWT whose payload holds an integer of 4301 digits is read, and named by its id
  [PASS] VC-JWT whose payload holds the credential id twice is named by the last
  [PASS] credential holding 9007199254740993.5, an integer above 2^53 - 1 once read, has no signed form
  [PASS] credential id U+001F, the last C0 control character, is named by its SHA-256
  [PASS] credential id U+0020, the first character past the C0 controls, is named as it is
  [PASS] credential id that reads as a digest and has one more character is named as it is
  [PASS] credential id holding a bidi override or a zero-width space is named by its SHA-256
  [PASS] credential id holding a code point that renders as nothing by default is named by its SHA-256
  [PASS] credential id that is the word unknown is named by its SHA-256
  [PASS] credential object whose issuer signed a __proto__ member is digested with it
  [PASS] JWS segment with characters outside base64url, or in the base64 alphabet, is none
  [PASS] JWS segment holding white space, or padded, is none
  [PASS] JWS of four segments is no JWS
  [PASS] claim of meta altered after signing breaks the signature, whichever claim it is
  [PASS] proof held against another request than the one it binds
  [PASS] JWS header that names another algorithm than EdDSA makes no proof
  [PASS] JWS header that names another key than meta.kid makes no proof
  [PASS] kid that names a key of another DID than meta.did makes no proof
  [PASS] request with no params is bound by its method alone
  [PASS] every signed-proof vector has the verdict it expects
  [PASS] verifier that ran out of stack reports a fault, which is no verdict
  [PASS] empty delegationRef in meta names no credential, as leaving it out does
  [PASS] outcome asked for as an empty string is asked for, and no proof states it
  [PASS] chain given as null is no chain, and asks no outcome of the proof
  [PASS] claim in meta given as null, or out of its form, makes no proof
  [PASS] claims in meta are held to the forms the proof schema gives them
  [PASS] signer of the proof cases gives the keys and signatures RFC 8032 gives
  [PASS] forgeries of the proof cases satisfy the verification equation under their keys
  [PASS] response proofs are held to what the TypeScript reference holds them to
  [PASS] NaN and Infinity are not JSON, in a vector file or in what a proof signs
  [PASS] of members that share a name the last is read, as JSON.parse reads it
  [PASS] values that have no signed form are refused a digest
  [PASS] credential ids are read, and referred to, as 7.8 has them
RESULT: PASS — cross-language JCS + Ed25519 parity confirmed
```

---

*End of Conformance Requirements*
