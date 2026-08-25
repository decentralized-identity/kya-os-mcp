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
- Read the KYA-OS proof from `org.kya-os/proof` and, for backward compatibility,
  from the legacy bare `proof` key.
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
| `vectors/signed-proof.json` | Detached proof verification | valid signature + in-window ts | tampered signature, tampered meta, wrong key, timestamp skew exceeded |
| `vectors/delegation-chain.json` | Delegation chain verification | single-hop, two-hop attenuated | broken issuer↔subject linkage, scope widening, tampered signature, audience mismatch |
| `vectors/status-list.json` | StatusList2021 revocation | active (bit unset) | revoked (bit set) |
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

**On `signed-proof/tampered-meta`.**
The proof's `meta` block mirrors the claims signed inside the JWS, but it is a convenience for consumers that read the proof without decoding the token, not an authoritative copy.
This vector leaves the JWS byte-identical to `valid-basic` and alters only the mirrored `meta.requestHash`, so the JWS signature still verifies.
A conformant verifier MUST reconcile `meta` against the decoded JWS payload and reject on any mismatch.
Signature validity alone does not pass this vector: it is the `requestHash` counterpart of the `responseHash` recompute rule in L2.11.

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
Because fresh keys change the committed bytes, regenerated output MUST NOT be committed over an existing `suiteVersion` (see [Suite versioning and immutability](#suite-versioning-and-immutability)).

### Suite versioning and immutability

The committed vector set is immutable at a given `suiteVersion`: the vector bytes may only change together with a `suiteVersion` bump.
`conformance/SUITE-MANIFEST.json` pins the current set (`suiteVersion`, `vectorSetHash`, `vectorCount`, per-file hashes) and is the anchor CI verifies against.
The hash recipe: SHA-256 each vector file's raw committed bytes, sort the `[filename, hex]` pairs by filename, canonicalize the array with RFC 8785 (JCS), SHA-256 that, prefix with `sha256:`.
CI enforces the invariant twice: a vitest guard (`conformance/__tests__/suite-immutability.test.ts`) and a dedicated step running `node conformance/suite-hash.mjs --check`.
To change vectors intentionally, bump `suiteVersion` (including the in-file `version` fields), regenerate the manifest with `node conformance/suite-hash.mjs --json`, and keep `pinnedAt` current.
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
  async verifyDelegationChain(input)  { /* ... */ },
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
its OWN distinct `_meta` key (`_meta['org.kya-os/proof']` for the legacy
session-bound proof, `_meta['org.kya-os/proof.v1']` for the stateless card proof),
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
  [PASS] domain-separated audit event digest
  [PASS] RFC 9162 audit Merkle root
  [PASS] RFC 9162 audit inclusion proof
  [PASS] RFC 9162 audit consistency proof
RESULT: PASS — cross-language JCS + Ed25519 parity confirmed
```

---

*End of Conformance Requirements*
