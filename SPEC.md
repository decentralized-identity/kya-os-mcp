# KYA-OS Protocol Specification

**Cryptographic identity, delegation, and proof for Model Context Protocol servers**

Version: 1.0.0
Status: Stable
Editors: KYA-OS Working Group
Repository: https://github.com/decentralized-identity/kya-os-mcp

---

## Abstract

KYA-OS (Know Your Agent Operating System) is a protocol extension for the Model Context Protocol (MCP) that adds cryptographic identity, delegation chains, and non-repudiation proofs to AI agent interactions. KYA-OS enables MCP servers to verify *who* is calling (agent DID), *what authority they hold* (a delegation chain rooted at a Responsible Party, expressed as W3C Verifiable Credentials), and *what was done* (signed proof for audit trails). The protocol uses Decentralized Identifiers (DIDs) for agent identity, W3C Verifiable Credentials for delegation, Ed25519 signatures for cryptographic operations, and StatusList2021 for revocation.

---

## Conformance Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

---

## Status

**Stable 1.0.0** — Donated to DIF TAAWG (Decentralized Identity Foundation, Trust and Authorization for AI Agents Working Group). Under review for ratification as a DIF standard. The wire format is stable: any future change that breaks compatibility with this version will require a major version bump.

---

## 1. Motivation

The Model Context Protocol (MCP) defines a standard interface for AI agents to interact with tools and resources. However, MCP lacks an identity layer, creating several security vulnerabilities:

1. **Agent Impersonation**: Without identity verification, any process can claim to be a particular agent. Malicious actors can impersonate trusted agents to gain unauthorized access to sensitive tools.

2. **Prompt Injection with Forged Identity**: Attackers can inject prompts that include fabricated identity claims. Without cryptographic verification, servers cannot distinguish legitimate identity assertions from forged ones.

3. **No Delegation Chain**: When Agent A delegates to Agent B, there is no standard mechanism to prove the delegation occurred or verify the delegation constraints. This prevents secure hierarchical agent architectures.

4. **No Audit Trail**: Tool calls leave no cryptographic evidence of what was requested, what was returned, or who was responsible. This makes compliance, debugging, and incident response difficult.

5. **Replay Attacks**: Without nonce-based session establishment, captured tool call payloads can be replayed by attackers.

DIDs and Verifiable Credentials are the right fit for this problem:

- **DIDs** provide decentralized, cryptographically-verifiable identifiers that agents control. They do not require a central authority and support multiple resolution methods (did:key for ephemeral, did:web for persistent organizational identity).

- **Verifiable Credentials** provide a W3C standard for expressing cryptographically-signed claims. Delegation credentials can express scope constraints, temporal bounds, budget limits, and revocation status in an interoperable format.

- **EdDSA/Ed25519** provides high-performance, deterministic signatures suitable for high-throughput agent interactions with no reliance on hash function collision resistance.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Agent DID** | A Decentralized Identifier (DID) that uniquely identifies an AI agent. KYA-OS supports `did:key` (self-certifying, ephemeral) and `did:web` (organization-hosted, persistent). |
| **Principal** | The entity that immediately delegates authority to an agent — typically the human operator who launches the agent for a task. The Principal MAY or MAY NOT be the Responsible Party. In personal-use scenarios they are usually the same; in organizational scenarios they differ. |
| **Responsible Party** | The entity ultimately accountable for the actions of an agent operating under a delegation chain. The Responsible Party is the root issuer of the chain (`issuerDid` of the root `DelegationCredential`). In personal use, the Responsible Party equals the Principal. In organizational use, the Responsible Party is the employing organization or parent entity while the Principal is the immediate human delegator within that organization. |
| **Delegation Chain** | An ordered sequence of Delegation Credentials from a root delegator (the Responsible Party) to the current agent, where each credential's subject is the next credential's issuer. |
| **Delegation Credential** | A W3C Verifiable Credential that grants specific permissions from an issuer (delegator) to a subject (delegate). Contains CRISP constraints defining allowed operations. |
| **Detached Proof** | A JWS (JSON Web Signature) that cryptographically binds a tool request and response together, enabling non-repudiation and audit. Attached to responses in the `_meta` field. |
| **CRISP Constraints** | **C**onstraints, **R**esources, **I**dentity, **S**cope, **P**olicy — a structured envelope defining what operations a delegation permits: allowed scopes, budget caps, temporal bounds, and audience restrictions. |
| **Session** | A validated, time-bounded context established via handshake. Sessions prevent replay attacks and provide a stable context for proof generation. |
| **Handshake Nonce** | A cryptographically random value provided by the client during session establishment. Used once; prevents replay attacks. |
| **Audience** | The intended recipient of a credential or proof, typically the MCP server's DID or domain. Prevents credential/proof misuse across different servers. |

---

## 3. Protocol Overview

The following diagram illustrates the KYA-OS protocol flow:

```
┌─────────────────┐                              ┌─────────────────┐
│  Client Agent   │                              │   MCP Server    │
│  (did:key:z...) │                              │ (did:web:srv)   │
└────────┬────────┘                              └────────┬────────┘
         │                                                │
         │  ┌──────────────────────────────────────────┐  │
         │  │ 1. HANDSHAKE REQUEST                     │  │
         │  │    - nonce: <22-char base64url>          │  │
         │  │    - audience: "did:web:srv"             │  │
         │  │    - timestamp: <unix epoch seconds>     │  │
         │  │    - agentDid: "did:key:z6Mk..."         │  │
         ├──┴──────────────────────────────────────────┴──►
         │                                                │
         │         ┌─ Validate:                           │
         │         │  • timestamp within ±120s            │
         │         │  • nonce not seen before             │
         │         │  • audience matches server DID       │
         │         └──────────────────────────────────────┤
         │                                                │
         │  ┌──────────────────────────────────────────┐  │
         │  │ 2. HANDSHAKE RESPONSE                    │  │
         │  │    - sessionId: "kyaos_<uuid>"            │  │
         │  │    - serverDid: "did:web:srv"            │  │
         │  │    - ttlMinutes: 30                      │  │
         ◄──┴──────────────────────────────────────────┴──┤
         │                                                │
         │  ┌──────────────────────────────────────────┐  │
         │  │ 3. TOOL CALL REQUEST                     │  │
         │  │    method: "tools/call"                  │  │
         │  │    params:                               │  │
         │  │      name: "read_file"                   │  │
         │  │      arguments: { path: "/etc/hosts" }   │  │
         │  │      sessionId: "kyaos_..."               │  │
         │  │      delegation: <DelegationCredential>  │◄── Optional
         ├──┴──────────────────────────────────────────┴──►
         │                                                │
         │         ┌─ Process:                            │
         │         │  • Validate session                  │
         │         │  • Verify delegation (if present)    │
         │         │  • Execute tool                      │
         │         │  • Generate detached proof           │
         │         └──────────────────────────────────────┤
         │                                                │
         │  ┌──────────────────────────────────────────┐  │
         │  │ 4. TOOL CALL RESPONSE                    │  │
         │  │    content: [ { type: "text", ... } ]    │  │
         │  │    _meta:                                │  │
         │  │      proof:                              │  │
         │  │        jws: "eyJhbGciOiJFZERTQSI..."     │  │
         │  │        meta:                             │  │
         │  │          did: "did:web:srv"              │  │
         │  │          kid: "did:web:srv#key-1"        │  │
         │  │          ts: 1710288000                  │  │
         │  │          nonce: "..."                    │  │
         │  │          requestHash: "sha256:..."       │  │
         │  │          responseHash: "sha256:..."      │  │
         ◄──┴──────────────────────────────────────────┴──┤
         │                                                │
         ▼                                                ▼
```

---

## 4. Agent Identity

### 4.1 Supported DID Methods

KYA-OS implementations MUST support:

| Method | Use Case | Resolution |
|--------|----------|------------|
| `did:key` | Ephemeral agents, development, testing | Local derivation from public key bytes |
| `did:web` | Production servers, organizational identity | HTTPS fetch of `/.well-known/did.json` or path-based document |

Implementations MAY support additional DID methods.

### 4.2 Key Material

KYA-OS uses Ed25519 (EdDSA over Curve25519) for all cryptographic operations:

- **Key Size**: 32-byte private seed, 32-byte public key
- **Signature Size**: 64 bytes
- **Algorithm Identifier**: `EdDSA` (in JWS headers)
- **JWK Key Type**: `OKP` (Octet Key Pair)
- **JWK Curve**: `Ed25519`

### 4.3 did:key Derivation

A `did:key` DID is derived from an Ed25519 public key as follows:

1. Prepend the Ed25519 multicodec prefix `0xed01` to the 32-byte public key
2. Encode the result using base58btc
3. Prepend the multibase prefix `z`
4. Construct the DID: `did:key:z<base58btc-encoded-bytes>`

Example:
```
Public Key (hex): 8076ee2cfc1a...32 bytes...
Multicodec:       ed01 + 8076ee2cfc1a...
Base58btc:        6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
DID:              did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The verification method ID is `<did>#keys-1`.

### 4.4 did:web Resolution

A `did:web` DID resolves to a DID Document via HTTPS:

| DID | Resolution URL |
|-----|---------------|
| `did:web:example.com` | `https://example.com/.well-known/did.json` |
| `did:web:example.com:agents:bot1` | `https://example.com/agents/bot1/did.json` |

The DID Document MUST contain at least one verification method with `publicKeyJwk` in Ed25519 format:

```json
{
  "id": "did:web:example.com",
  "verificationMethod": [{
    "id": "did:web:example.com#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:example.com",
    "publicKeyJwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url-encoded-32-byte-public-key>"
    }
  }],
  "authentication": ["did:web:example.com#key-1"],
  "assertionMethod": ["did:web:example.com#key-1"]
}
```

---

## 5. Session Lifecycle

### 5.1 Handshake Request

To establish a session, the client sends a handshake request:

```typescript
interface HandshakeRequest {
  nonce: string;      // 16 bytes, base64url-encoded (22 chars, no padding)
  audience: string;   // Server DID or domain
  timestamp: number;  // Unix epoch seconds
  agentDid?: string;  // Client's DID (optional for anonymous sessions)
  clientInfo?: {      // Optional client metadata
    name: string;
    version?: string;
    platform?: string;
  };
}
```

### 5.2 Validation Rules

The server MUST validate the handshake request:

1. **Timestamp Skew**: `|server_time - request.timestamp| <= 120 seconds`
   - Reject if outside this window
   - Remediation: "Check NTP sync on client and server"

2. **Nonce Uniqueness**: The (nonce, agentDid) pair MUST NOT have been seen before
   - Reject with "Nonce already used (replay attack prevention)"
   - Nonces MUST be cached for at least `sessionTtlMinutes + 1 minute`
   - When `agentDid` is omitted, the dedupe key is `nonce` alone. Servers MUST use a shorter cache TTL for anonymous nonces (recommended: 60 seconds, vs. the default 120 seconds for authenticated handshakes)

3. **Audience Match**: `request.audience` MUST match the server's DID or expected domain
   - Prevents credential forwarding attacks

### 5.3 Session Creation

On successful validation, the server creates a session:

```typescript
interface SessionContext {
  sessionId: string;         // Format: "kyaos_<uuid-v4>"
  audience: string;          // Echoed from request
  nonce: string;             // Echoed from request
  timestamp: number;         // Request timestamp
  createdAt: number;         // Server timestamp at creation
  lastActivity: number;      // Updated on each request
  ttlMinutes: number;        // Default: 30
  agentDid?: string;         // Client DID if provided
  serverDid?: string;        // Server's DID
  identityState: 'anonymous' | 'authenticated';
}
```

### 5.4 Session TTL and Expiry

- **Idle Timeout**: Sessions expire after `ttlMinutes` of inactivity
- **Absolute Lifetime**: Implementations MAY enforce a maximum session lifetime
- **Activity Update**: `lastActivity` is updated on each valid request

### 5.5 Replay Prevention

The nonce cache implementation MUST:
- Store (nonce, agentDid, expiry) tuples
- Support TTL-based automatic expiry
- Be atomic to prevent race conditions in concurrent environments
- For distributed deployments: use Redis, DynamoDB, or Cloudflare KV (not in-memory)

Nonce lifetime MUST exceed the session TTL. Servers MUST NOT drop nonces before the lifetime expires, to prevent replay attacks via early eviction.

---

## 6. Delegation

### 6.1 DelegationRecord Structure

Internal representation of a delegation:

```typescript
interface DelegationRecord {
  id: string;                    // Unique delegation identifier
  issuerDid: string;             // DID of the delegator
  subjectDid: string;            // DID of the delegate
  controller?: string;           // DID that can revoke this delegation
  vcId: string;                  // URN of the Verifiable Credential
  parentId?: string;             // Parent delegation ID (for chains)
  constraints: DelegationConstraints;
  signature: string;             // Extracted from VC proof
  status: 'active' | 'revoked' | 'expired';
  createdAt?: number;
  revokedAt?: number;
  revokedReason?: string;
  metadata?: Record<string, unknown>;
}
```

### 6.2 DelegationCredential as W3C VC

> **Note:** A Delegation credential is itself a W3C Verifiable Credential. The Delegation Registry is a specialized index of delegations, which are VCs.

Delegations are issued as W3C Verifiable Credentials:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.modelcontextprotocol-identity.io/xmcp-i/credentials/delegation.v1.0.0.json"
  ],
  "id": "urn:uuid:d7f8a9b0-1234-5678-9abc-def012345678",
  "type": ["VerifiableCredential", "DelegationCredential"],
  "issuer": "did:key:z6MkIssuer...",
  "issuanceDate": "2024-03-01T12:00:00Z",
  "expirationDate": "2024-03-02T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkDelegate...",
    "delegation": {
      "id": "del-001",
      "issuerDid": "did:key:z6MkIssuer...",
      "subjectDid": "did:key:z6MkDelegate...",
      "constraints": {
        "scopes": ["tool:read_file", "tool:list_directory"],
        "notBefore": 1709294400,
        "notAfter": 1709380800,
        "audience": "did:web:mcp-server.example.com"
      },
      "status": "active"
    }
  },
  "credentialStatus": {
    "id": "https://example.com/status/1#42",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "42",
    "statusListCredential": "https://example.com/status/1"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2024-03-01T12:00:00Z",
    "verificationMethod": "did:key:z6MkIssuer...#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base64url-encoded-signature>"
  }
}
```

A `DelegationCredential` carries a _permission_, not a _claim_. To keep claim
semantics out of an authorization decision — a confused-deputy vector (§11.6) —
the `credentialSubject` MUST contain only two properties: `id` (the delegate's
DID) and `delegation` (the permission payload). A verifier MUST reject a
`DelegationCredential` whose `credentialSubject` carries any other property, and
MUST reject a credential whose `type` array does not include both
`VerifiableCredential` and `DelegationCredential`.

Implementations MAY offer an explicit, audited opt-out of the `credentialSubject`
shape check to bridge non-conformant issuers. Such an opt-out MUST default to off
and MUST emit a one-time warning when enabled, so the relaxation is visible in
operational logs.

### 6.3 CRISP Constraint Envelope

```typescript
interface DelegationConstraints {
  // Temporal bounds (Unix epoch seconds)
  notBefore?: number;
  notAfter?: number;

  // Simple scope list (tool names, resource patterns)
  scopes?: string[];

  // Audience restriction (server DID or domain)
  audience?: string | string[];

  // Extended CRISP constraints
  crisp?: {
    budget?: {
      unit: 'USD' | 'ops' | 'points';
      cap: number;
      window?: {
        kind: 'rolling' | 'fixed';
        durationSec: number;
      };
    };
    scopes: Array<{
      resource: string;
      matcher: 'exact' | 'prefix' | 'regex';
      constraints?: Record<string, unknown>;
    }>;
  };
}
```

### 6.4 Delegation Graph

Delegations form a directed acyclic graph (DAG):

```
     [Root: Responsible Party → Principal]
            │
     [Principal → Agent A]
            │
     ┌──────┴──────┐
     ▼             ▼
[A → B]        [A → C]
     │
     ▼
[B → D]
```

- Each node is a `DelegationCredential`
- `parentId` links to the parent delegation
- Child delegation's `issuerDid` MUST equal parent's `subjectDid`
- Scope constraints MUST be equal to or narrower than parent's constraints
- Every chain MUST terminate at a Responsible Party. The Responsible Party's DID is the `issuerDid` of the root `DelegationCredential` and is the entity ultimately accountable for actions taken under any descendant delegation. In personal use the Responsible Party equals the Principal; in organizational use the Responsible Party is the parent organization while the Principal is the immediate human delegator (see §2).

### 6.4.1 Designation Invariant

A `DelegationCredential` may authorize multiple resources, either via a list
of explicit scope strings (`constraints.scopes[]`) or via pattern matchers
(`constraints.crisp.scopes[].matcher`: `'exact' | 'prefix' | 'regex'`). When
the credential is used to invoke a specific tool or resource, the invocation
MUST designate the specific scope being exercised, and verifiers MUST confirm
that the designated scope is a member of (or matches a pattern in) the
delegation's authorized scopes.

In other words: multi-resource delegations are valid as authority grants
but cannot be used in invocations without designation. An invocation that
omits the specific resource designation MUST be rejected, even if the
delegation would have authorized it under any matching scope.

This is the designation/authorization separation: without it, an attacker
who acquires a multi-resource delegation can use it against resources the
original delegator did not anticipate. Together with the audience-on-
re-delegation requirement (§11.6), this closes the confused-deputy class
on the invocation path.

Reference implementation: each tool wrapped via `wrapWithDelegation` is
registered with a fixed `scopeId`; invocations carry the wrapped tool's
name and the verifier requires the delegation's scopes to contain that
exact scopeId before the handler runs.

### 6.5 Cascading Revocation

When a delegation is revoked:

1. Mark the delegation as `revoked` in the delegation graph
2. Recursively mark all descendant delegations as `revoked`
3. Update StatusList2021 credential for each revoked delegation
4. Emit revocation events for audit logging

#### 6.5.1 Revocation Rights

For v1.0, the parties authorized to revoke a delegation are:

1. **The direct issuer of the delegation.** The party that signed the
   `DelegationCredential` MAY revoke it at any time.
2. **Any ancestor issuer in the delegation chain.** A party that issued
   an upstream delegation MAY revoke any descendant delegation; cascading
   revocation propagates downward through the graph (§6.5).
3. **The Responsible Party at the root of the chain.** The root issuer
   MAY revoke the entire chain.
4. **The subject of a delegation MAY NOT revoke it.** Revocation requires
   authority from above; an agent cannot unilaterally invalidate a
   delegation it received.

Revocation requests SHOULD be signed by the revoking party's key, and
verifiers SHOULD validate the revoker's identity against the chain before
honoring the revocation.

Future versions may adopt an explicit "revocation as a delegatable
permission" model (UCAN-style), allowing the responsible party to grant
revocation authority to other parties (e.g. a security operations team)
without those parties being in the original chain. Tracked for v1.1.

#### 6.5.2 Concurrency and the Revocation Race

Revocation and invocation are concurrent operations in the Lamport sense.
An invocation that arrives at a verifier between the moment a revocation
is issued and the moment that revocation propagates to the verifier will
succeed despite the revocation being logically prior. This race is
unavoidable in any distributed system; implementations can bound the
window but cannot eliminate it.

Implementations MUST:

- Propagate revocations to all known verifiers as quickly as possible,
  including immediate StatusList2021 updates and cache invalidation.
- Cache status-list lookups with a TTL no longer than the revocation
  propagation target. For high-privilege scopes, ≤ 60 seconds is
  recommended.
- Honor explicit revocation signals (e.g., a side-channel notification
  from a trusted source) immediately, ahead of the next status-list
  refresh.

Operators of high-stakes resources SHOULD reduce the race window by
issuing short-lived delegations (so revocation by expiration is the
primary mechanism) and polling status lists frequently. The unavoidable
race is the same trade-off familiar from PKI: short certificate lifetimes
reduce the window during which a compromised credential can be used.

### 6.6 StatusList2021 Revocation

KYA-OS uses the W3C StatusList2021 specification for revocation:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "https://example.com/status/1",
  "type": ["VerifiableCredential", "StatusList2021Credential"],
  "issuer": "did:web:example.com",
  "issuanceDate": "2024-03-01T00:00:00Z",
  "credentialSubject": {
    "id": "https://example.com/status/1#list",
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "<gzip-compressed-base64-bitstring>"
  }
}
```

L1 implementations do not require revocation support; revocation checking is available at L3 only.

### 6.7 Orchestration & Extensibility

Orchestration scope is service-local; directory federation is out of scope for this version. Delegation graphs and revocation state are managed within a single service boundary and are not synchronized across independent KYA-OS deployments or external agent directories (e.g. NANDA).

- Each delegation is assigned a `statusListIndex` (0 to 131071)
- Bit at index is 0 = valid, 1 = revoked
- Bitstring is gzip-compressed and base64-encoded

### 6.8 Protocol Registry

The registry indexes anything addressable by DID — agents, MCP servers, services, and delegation policies.

Three registry types are defined within the protocol:

- **Delegation Registry** — stores `DelegationCredential` objects and supports querying by issuer, subject, scope, and revocation status.
- **Credential Registry** — stores all W3C Verifiable Credentials issued within the ecosystem, providing a general-purpose VC index.
- **Trust Registry** — indexes entities by DID for discovery, enabling participants to resolve trust relationships and verify standing.

`DelegationCredential` IS a Verifiable Credential; Delegation Registry is a specialized Credential Registry view.

---

## 7. Proof Generation

### 7.1 Purpose

Detached proofs provide:

- **Non-repudiation**: Cryptographic evidence that the server processed the request
- **Integrity**: Hashes bind the exact request and response together
- **Audit Trail**: Proofs can be stored and verified offline

### 7.2 ProofMeta Fields

```typescript
interface ProofMeta {
  did: string;          // Server's DID (signer)
  kid: string;          // Key ID used for signing
  ts: number;           // Unix epoch seconds when proof was generated
  nonce: string;        // Session nonce (prevents cross-session replay)
  audience: string;     // Session audience
  sessionId: string;    // Session identifier
  requestHash: string;  // SHA-256 of canonicalized request
  responseHash: string; // SHA-256 of canonicalized response
  scopeId?: string;     // Scope under which the call was made
  delegationRef?: string; // Reference to delegation credential
  clientDid?: string;   // Client's DID if authenticated
}
```

### 7.3 Hash Generation

1. **Canonicalize**: Convert request/response to RFC 8785 (JCS) canonical JSON
2. **Hash**: Compute SHA-256 of the canonical JSON bytes (UTF-8 encoded)
3. **Format**: `sha256:<64-char-lowercase-hex>`

Request canonicalization includes:
```json
{
  "method": "tools/call",
  "params": { /* sorted keys, no whitespace */ }
}
```

Response canonicalization is the `data` field only (excludes `_meta`).

### 7.4 JWS Compact Serialization

The proof JWS is generated as:

```
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
```

**Header**:
```json
{
  "alg": "EdDSA",
  "kid": "did:web:server.example.com#key-1"
}
```

**Payload** (canonicalized):
```json
{
  "aud": "did:web:server.example.com",
  "iss": "did:web:server.example.com",
  "nonce": "...",
  "requestHash": "sha256:...",
  "responseHash": "sha256:...",
  "sessionId": "kyaos_...",
  "sub": "did:web:server.example.com",
  "ts": 1710288000
}
```

### 7.5 _meta Attachment

The proof is attached to tool responses in the `_meta` field:

```json
{
  "content": [{ "type": "text", "text": "File contents..." }],
  "_meta": {
    "proof": {
      "jws": "eyJhbGciOiJFZERTQSIsImtpZCI6Ii4uLiJ9.eyJhdWQiOi4uLn0.c2ln...",
      "meta": {
        "did": "did:web:server.example.com",
        "kid": "did:web:server.example.com#key-1",
        "ts": 1710288000,
        "nonce": "abc123...",
        "audience": "did:web:server.example.com",
        "sessionId": "kyaos_d7f8a9b0-...",
        "requestHash": "sha256:a1b2c3...",
        "responseHash": "sha256:d4e5f6..."
      }
    }
  }
}
```

### 7.6 _meta Hash Exclusion

The response hash is computed over the response object with `_meta` removed. Implementations MUST NOT rely on signature coverage of `_meta` fields. Verifiers SHOULD treat `_meta` as containing only `proof` unless the session config explicitly enables additional `_meta` fields via `session.metaPolicy`.

When `session.metaPolicy` is set to `strict` (the default), verifiers MUST reject responses whose `_meta` contains keys other than `proof`. When set to `allow-extensions`, verifiers permit additional keys in `_meta` but MUST NOT include them in any hash computation or signature verification.

### 7.7 Delegation Chain Audit Example

The following shows how audit records link across a 3-level delegation chain: User → Agent A → Agent B → tool call.

**Step 1 — User delegates to Agent A**

```json
{
  "id": "urn:uuid:1111-aaaa",
  "type": "DelegationCredential",
  "issuer": "did:web:user.example.com",
  "credentialSubject": {
    "id": "did:web:agent-a.example.com",
    "parentDelegation": null,
    "scope": "files:read files:write"
  }
}
```

**Step 2 — Agent A delegates to Agent B**

```json
{
  "id": "urn:uuid:2222-bbbb",
  "type": "DelegationCredential",
  "issuer": "did:web:agent-a.example.com",
  "credentialSubject": {
    "id": "did:web:agent-b.example.com",
    "parentDelegation": "urn:uuid:1111-aaaa",
    "scope": "files:read"
  }
}
```

The `parentDelegation` field links this record back to the User → Agent A credential, forming a verifiable chain.

**Step 3 — Agent B calls a tool; the server generates an audit record**

```json
{
  "content": [{ "type": "text", "text": "file contents..." }],
  "_meta": {
    "proof": {
      "jws": "eyJhbGciOiJFZERTQSJ9...",
      "meta": {
        "did": "did:web:tool-server.example.com",
        "kid": "did:web:tool-server.example.com#key-1",
        "ts": 1710288120,
        "nonce": "xyz789",
        "audience": "did:web:tool-server.example.com",
        "sessionId": "kyaos_f1e2d3c4-...",
        "requestHash": "sha256:aabbcc...",
        "responseHash": "sha256:ddeeff...",
        "delegationRef": "urn:uuid:2222-bbbb",
        "clientDid": "did:web:agent-b.example.com"
      }
    }
  }
}
```

The `delegationRef` in the proof points to Agent B's delegation credential (`urn:uuid:2222-bbbb`), which in turn carries `parentDelegation: urn:uuid:1111-aaaa` back to the original user grant. An auditor can reconstruct the full chain — User → Agent A → Agent B → tool call — by following `delegationRef` → `parentDelegation` links. All three records are independently verifiable offline using the signers' DID documents.

---

## 8. Outbound Delegation Propagation

When an MCP server calls downstream services (APIs, other MCP servers), it MUST forward delegation context.

### 8.1 HTTP Headers

| Header | Value |
|--------|-------|
| `KYA-OS-Agent-DID` | Original agent's DID |
| `KYA-OS-Delegation-Chain` | Comma-separated list of delegation IDs from root to current |
| `KYA-OS-Session-Id` | KYA-OS session ID |
| `KYA-OS-Delegation-Proof` | Signed JWT proving delegation authority |
| `KYA-OS-Granted-Scopes` | Comma-separated list of granted scopes |

### 8.2 Delegation Proof JWT

```typescript
interface DelegationProofJWT {
  // Standard JWT claims
  iss: string;   // Server DID (JWT issuer)
  sub: string;   // Responsible Party DID (the root issuer of the delegation chain)
  aud: string;   // Target service hostname
  iat: number;   // Issued at (Unix epoch)
  exp: number;   // Expires at (iat + 60 seconds)
  jti: string;   // Unique JWT ID (UUID)

  // KYA-OS claims
  delegation_id: string;    // Current delegation ID
  delegation_chain: string; // Chain path (vcId>delegationId)
  scope: string;            // Comma-separated scopes
}
```

The JWT is signed with EdDSA using the server's private key.

### 8.3 Chain String Format

```
<vcId>><delegationId>
```

Example: `urn:uuid:d7f8a9b0-1234-5678-9abc-def012345678>del-001`

---

## 9. Authorization Flow

### 9.1 verifyOrHints Pattern

When a tool call requires authorization:

1. Server checks for valid delegation in the request
2. If delegation is valid and covers required scopes: proceed
3. If delegation is missing or insufficient: return `needs_authorization` error

### 9.2 needs_authorization Error Structure

```typescript
interface NeedsAuthorizationError {
  error: 'needs_authorization';
  message: string;
  authorizationUrl: string;  // URL where user can grant authorization
  resumeToken: string;       // Token to resume flow after authorization
  expiresAt: number;         // Unix epoch when resumeToken expires
  scopes: string[];          // Scopes being requested
  display?: {
    title?: string;
    hint?: Array<'link' | 'qr' | 'code'>;
    authorizationCode?: string;
    qrUrl?: string;
  };
}
```

### 9.3 Resume Flow

1. Client receives `needs_authorization` error
2. Client directs user to `authorizationUrl`
3. User authenticates and grants authorization
4. Authorization service issues DelegationCredential
5. Client retries request with `resumeToken` and new delegation
6. Server validates delegation and processes request

---

## 10. Well-Known Endpoint

KYA-OS servers SHOULD expose `/.well-known/mcp`:

```json
{
  "did": "did:web:mcp-server.example.com",
  "version": "1.0.0",
  "capabilities": {
    "delegation": true,
    "proof": true,
    "revocation": true
  },
  "supported_did_methods": ["did:key", "did:web"],
  "proof_algorithms": ["EdDSA"],
  "clockSkewSeconds": 120,
  "endpoints": {
    "handshake": "/_kya-os/handshake",
    "status_list": "/.well-known/status/1"
  }
}
```

### 10.1 Clock Skew Negotiation

Servers MAY advertise a `clockSkewSeconds` field (type: number, default: 120, minimum: 30, maximum: 600) indicating the tolerance window for timestamp validation. Clients SHOULD read this value on first contact and use it for their own clock-skew tolerance when validating server timestamps, falling back to the hardcoded default (120 seconds) if the field is absent or out of range.

---

## 11. Security Considerations

### 11.0 Trust Model

KYA-OS distributes verification work across three trust boundaries. Operators
deploying the protocol need to know which component is trusted with what.

**1. The agent process itself.** Every agent holds its own Ed25519 secret key
and is trusted to use it only on operations the agent has been authorized to
perform. Compromise here yields full compromise of every chain the agent can
sign under. Mitigations are platform-level: software-only identity (default),
proxy-managed identity (key held by a trusted local process), or
hardware-attested identity (TEE-bound — SEV-SNP, TDX, Nitro Enclaves). The
spec is signature-algorithm-agnostic; operators choose key custody to fit
their threat model.

**2. The verifier.** At Conformance Level 1 (edge-proxy verification), the
verifier sits in front of legacy MCP servers that don't natively understand
KYA-OS. In this deployment the verifier is part of the trusted computing
base for any resource it gates — a compromised L1 verifier can forge accepts
on requests the resource owner would have rejected. **Operators relying on
L1 SHOULD treat the verifier as a TCB component**, deploy it with the same
isolation as other TCB infrastructure, and minimize its blast radius via
per-service or per-tenant verifier instances rather than a single global
edge gate.

At Conformance Level 2+, verification moves into the resource boundary
(native server-side verification). This shrinks the TCB: the edge verifier
becomes defense-in-depth rather than the sole gate. **Services protecting
sensitive resources SHOULD adopt L2+ to remove the edge verifier from their
TCB.**

**3. The service / resource owner.** The service decides what scopes it
accepts, who its trust registry trusts, and which `did:web` documents it
will fetch. Trust-registry decisions are advisory: an adversarial agent
can route around registry rejection via credential sharing or request
proxying. The cryptographic delegation check is the load-bearing gate; the
registry is a signal that raises the friction of adversarial behavior.

**Mutual authentication.** Services SHOULD be addressable by a DID
(typically `did:web`), and agents performing verification SHOULD authenticate
the service identity before sending sensitive payloads. This prevents an
agent's delegation from being harvested by a service masquerading as the
intended audience.

### 11.1 Threat Model Summary

The table below names each protocol-level threat, the protocol's mitigation,
and the residual risk an operator carries.

| Threat | Mitigation | Residual risk |
|---|---|---|
| **Impersonation** — a process claims to be an agent it is not. | Cryptographic identity (Ed25519 + DID). Every tool response carries a detached JWS proof; verifiers check the agent's DID document. | Compromise of an agent's secret key, or compromise of an L1 verifier (see §11.0). |
| **Replay** — capturing a valid signed request and re-sending it. | Per-handshake nonces with bounded lifetime, dedupe cache on `(nonce, agentDid)`, ±120s clock skew. | Race within the dedupe cache window. Distributed deployments need atomic check-and-set on the cache. |
| **Scope escalation** — a delegated agent invokes outside the delegator's intent. | Scope subset enforcement at every chain link; CRISP `matcher: 'exact'` for sensitive resources. See §11.4. | Implementation bugs in scope-subset checks. |
| **Confused deputy** — a multi-resource delegation is repurposed for resources the delegator did not anticipate. | Designation invariant (§6.4.1) + audience-on-redelegation default `true` (§11.6). | Implementation bugs in the designation check. |
| **Credential theft** — a `DelegationCredential` is intercepted and used by an attacker. | `audience` constraint; short `notAfter`; session binding at high-security tiers (§11.8); StatusList2021 revocation. | Window between theft and revocation. |
| **Agent abuse** — a legitimate agent exceeds expected behavior. | Audit log of every signed tool call (§7); reputation tracking on both agent and Responsible Party (§2); revocation. | Detection latency; damage done before revocation propagates. |
| **Key compromise** — an agent's secret key is exfiltrated. | Short-lived delegations; explicit revocation; key rotation via DID document update. | Window between compromise and detection. See §11.5. |
| **Revocation race** — an invocation arrives while a revocation is propagating. | Status-list TTL bounded ≤ 60s for high-privilege scopes; side-channel revocation signals honored immediately; expiry as primary revocation mechanism. See §6.5.2. | Unavoidable Lamport-concurrent race. Operators bound the window; they cannot eliminate it. |
| **Downgrade** — a client strips KYA-OS headers entirely. | Fail-closed: servers requiring identity MUST reject sessionless calls; `/.well-known/mcp` advertises requirements. See §11.7. | A non-compliant client that the operator has not configured to require identity. |
| **Denial of service** | Per-session and per-handshake rate limiting; session caps; external session storage with TTL eviction. See §11.9. | Standard transport-layer DoS exposure (DDoS) is out of scope — operators rely on conventional network defenses. |

### 11.2 Nonce Replay Attacks

- Nonces MUST be cryptographically random (16 bytes minimum entropy)
- Nonce cache MUST persist across server restarts (use external storage)
- Nonce cache TTL MUST exceed session TTL
- Distributed deployments MUST use atomic check-and-set operations

### 11.3 Timestamp Skew Attacks

- Default skew tolerance is 120 seconds
- Servers MAY reduce this for high-security deployments
- Servers SHOULD use NTP for time synchronization
- Timestamps in proofs allow detection of delayed replay attempts

### 11.4 Delegation Scope Escalation

- Child delegations MUST NOT exceed parent scope
- Servers MUST validate entire delegation chain, not just leaf
- Scope comparison MUST be performed at each chain link
- Use CRISP `matcher: 'exact'` for sensitive resources

### 11.5 Key Rotation

- did:key: Generate new DID (no rotation mechanism)
- did:web: Update `did.json` with new verification method
- Old keys SHOULD remain in `did.json` for proof verification
- Delegation credentials reference specific key IDs; reissue after rotation
- Key custody options include software-only (default), proxy-managed, and hardware-attested (TEE). See §11.0.

### 11.6 Confused Deputy Attacks

A confused deputy attack occurs when Agent B receives a valid delegation from Agent A, then uses it to invoke tools that Agent A did not intend. Because delegation scopes may be coarse-grained (e.g., `tool:*`), the delegated agent may access resources beyond the delegator's intent.

- Servers SHOULD enforce the principle of least privilege when issuing delegations
- Delegation scopes SHOULD be as narrow as possible (prefer `tool:read_file` over `tool:*`)
- CRISP `matcher: 'exact'` SHOULD be used for sensitive resources
- Servers MAY implement per-delegation call logging to detect misuse

Two normative invariants close the confused-deputy class on the invocation path:

1. **Designation invariant (§6.4.1).** Invocations MUST designate the specific
   resource being exercised; verifiers MUST reject invocations that rely on a
   multi-resource delegation without designation. The reference implementation
   enforces this by requiring each tool's registered `scopeId` to be present
   in the delegation's authorized scopes before the handler runs.
2. **Audience-on-redelegation default (§this section).** Non-root credentials
   in a delegation chain MUST carry an `audience` constraint binding them to a
   specific verifying server. This default is `true` as of v1.3.x; opt-out is
   available with a one-time per-process warning for legacy integrations.

### 11.7 Downgrade Attacks

An adversary or non-compliant client may omit KYA-OS headers entirely, bypassing identity and delegation checks. Because KYA-OS is an extension to MCP, a server cannot distinguish between a client that does not support KYA-OS and one that is deliberately stripping identity headers.

- Servers that require identity MUST reject tool calls without a valid session (fail-closed)
- Servers SHOULD NOT fall back to unauthenticated mode for tools that require delegation
- The `/.well-known/mcp` endpoint allows clients to discover server requirements before connecting

### 11.8 Delegation Credential Theft

If a DelegationCredential is intercepted (e.g., via a compromised transport or log exposure), an attacker may present it to other servers. The `audience` constraint in the credential limits where it can be used, but does not bind it to a specific session or transport channel.

- Delegations SHOULD include an `audience` constraint limiting them to the intended server DID
- Delegations SHOULD use short `notAfter` expiration windows
- Servers SHOULD bind delegation context to the session that presented it
- High-security deployments SHOULD use session-scoped delegations (include `sessionId` in constraints)
- Revocation via StatusList2021 provides a mitigation path for stolen credentials

### 11.9 Session Exhaustion (Denial of Service)

An attacker may send a large volume of valid handshake requests to exhaust server memory.

- Implementations MUST enforce a maximum number of concurrent sessions
- Implementations SHOULD evict the oldest sessions when the limit is reached
- Rate limiting on the handshake endpoint is RECOMMENDED
- Distributed deployments SHOULD use external session storage with built-in TTL eviction

### 11.10 Revocation Freshness

The Lamport-concurrent revocation race is documented in §6.5.2. The
deployment-level controls are:

- StatusList2021 credentials have cache-control considerations
- Servers SHOULD set appropriate `Cache-Control` headers
- High-security deployments MAY require real-time revocation checks
- Cascading revocation MUST be atomic
- Status-list cache TTL SHOULD be ≤ 60 seconds for high-privilege scopes

---

## 12. Privacy Considerations

### 12.1 DID Correlation

A persistent `did:key` or `did:web` identifier acts as a pseudonym. Using the same DID across multiple MCP servers enables cross-server activity correlation. Implementations SHOULD consider per-server DID rotation for privacy-sensitive deployments.

### 12.2 Session Linkability

Session IDs (`kyaos_*`) appear in detached proofs. Within a session, all tool calls are linkable. Implementations SHOULD use short session TTLs and avoid logging session IDs alongside PII.

### 12.3 Delegation Chain Disclosure

Outbound `KYA-OS-Agent-DID` and `KYA-OS-Delegation-Chain` headers reveal the agent's identity and delegation provenance to downstream services. Implementations SHOULD only propagate delegation headers to trusted downstream services.

### 12.4 Proof Retention and Right to Erasure

Detached proofs are audit records containing DIDs and session identifiers. Operators retaining proof logs SHOULD consider applicable data protection regulations (GDPR Art. 17, CCPA) and implement appropriate retention policies.

---

## 13. Protocol Versioning

The current protocol version is `1.0.0`.

Handshake requests SHOULD include `clientProtocolVersion: "1.0.0"`.
Handshake responses MUST include `protocolVersion: "1.0.0"`.

Servers MUST reject clients with an incompatible major version (e.g., a `2.x` server MUST reject a `1.x` client).
Minor version differences SHOULD be handled gracefully — servers SHOULD implement backward compatibility within a major version.

---

## 14. Transport Binding

KYA-OS is transport-agnostic. The handshake and proofs use standard MCP mechanisms:

**Handshake**: Implemented as an MCP tool named `_kyaos_handshake`. This is compatible with all MCP transports (stdio, SSE, HTTP Streamable) without modification.

**Proof attachment**: Detached proofs are attached to tool responses in the standard MCP `_meta` field, which is transported transparently by all MCP transport implementations.

**Outbound delegation headers**: When an MCP server makes outbound HTTP calls (not MCP calls), delegation context is propagated via HTTP headers as defined in §8. For MCP-to-MCP calls, delegation context SHOULD be passed via the `_kyaos_handshake` flow.

---

## 15. Conformance

Implementation conformance requirements are defined in `CONFORMANCE.md`. Three compliance levels are specified:

- **Level 1 — Core Crypto**: Basic key generation, signing, verification, and well-known endpoint
- **Level 2 — Full Session**: Session handshake, nonce replay prevention, proof generation
- **Level 3 — Full Delegation**: VC issuance/verification, delegation graphs, revocation, outbound propagation

See `CONFORMANCE.md` for detailed requirements and test references.

---

## 16. References

### Normative References

- **[RFC 2119]** IETF. *Key words for use in RFCs to Indicate Requirement Levels*. https://datatracker.ietf.org/doc/html/rfc2119
- **[DID-CORE]** W3C. *Decentralized Identifiers (DIDs) v1.0*. https://www.w3.org/TR/did-core/
- **[VC-DATA-MODEL]** W3C. *Verifiable Credentials Data Model v1.1*. https://www.w3.org/TR/vc-data-model/
- **[DID-KEY]** W3C CCG. *did:key Method Specification*. https://w3c-ccg.github.io/did-method-key/
- **[DID-WEB]** W3C CCG. *did:web Method Specification*. https://w3c-ccg.github.io/did-method-web/
- **[STATUS-LIST-2021]** W3C CCG. *Status List 2021*. https://w3c-ccg.github.io/vc-status-list-2021/
- **[RFC8037]** IETF. *CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE*. https://datatracker.ietf.org/doc/html/rfc8037
- **[RFC7517]** IETF. *JSON Web Key (JWK)*. https://datatracker.ietf.org/doc/html/rfc7517
- **[RFC7515]** IETF. *JSON Web Signature (JWS)*. https://datatracker.ietf.org/doc/html/rfc7515
- **[RFC8785]** IETF. *JSON Canonicalization Scheme (JCS)*. https://datatracker.ietf.org/doc/html/rfc8785

### Informative References

- **[MCP]** Anthropic. *Model Context Protocol Specification*. https://spec.modelcontextprotocol.io/
- **[MULTICODEC]** Multiformats. *Multicodec Table*. https://github.com/multiformats/multicodec
- **[MULTIBASE]** Multiformats. *Multibase Specification*. https://github.com/multiformats/multibase

---

## Appendix A: Error Codes

| Code | Description |
|------|-------------|
| `KYA_OS_EHANDSHAKE` | Handshake validation failed (timestamp, nonce, or audience) |
| `KYA_OS_ESESSION` | Session not found or expired |
| `KYA_OS_EDELEGATION` | Delegation verification failed |
| `KYA_OS_ESCOPE` | Requested operation outside delegated scope |
| `KYA_OS_EREVOKED` | Delegation has been revoked |
| `KYA_OS_EPROOF` | Proof verification failed |
| `KYA_OS_EDID` | DID resolution failed |

---

## Appendix B: Base58btc Alphabet

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Note: Excludes `0`, `O`, `I`, `l` to avoid visual ambiguity.

---

## Appendix C: Test Vectors

These test vectors enable interoperability testing across implementations.

### C.1 SHA-256 Canonical Hash

**Input JSON:**
```json
{"method":"tools/call","params":{"name":"echo","arguments":{}}}
```

**JCS Canonicalized (RFC 8785):**
```json
{"method":"tools/call","params":{"arguments":{},"name":"echo"}}
```

**SHA-256 (hex):**
```
5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033
```

**KYA-OS Format:**
```
sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033
```

### C.2 did:key Derivation

**Ed25519 Public Key (32 bytes, hex):**
```
8076ee2cfc1acdd3f8f4e38c665a0a3e6ad6e06dc05b4f6ec9c5b1ae7c81c9a2
```

**Steps:**
1. Prepend multicodec prefix `0xed01` (Ed25519 public key)
2. Encode with base58btc
3. Prepend multibase prefix `z`

**Multicodec + Key (hex):**
```
ed018076ee2cfc1acdd3f8f4e38c665a0a3e6ad6e06dc05b4f6ec9c5b1ae7c81c9a2
```

**Base58btc Encoded:**
```
6Mko6jQvza2BSKRcrbJwgwbL9KYDn1isCUV5Lnq7gSTTKJq
```

**did:key:**
```
did:key:z6Mko6jQvza2BSKRcrbJwgwbL9KYDn1isCUV5Lnq7gSTTKJq
```

**Verification Method ID:**
```
did:key:z6Mko6jQvza2BSKRcrbJwgwbL9KYDn1isCUV5Lnq7gSTTKJq#keys-1
```

### C.3 JWS Structure

A valid detached proof JWS has the following structure:

**Protected Header (decoded):**
```json
{
  "alg": "EdDSA",
  "kid": "did:key:z6Mk...#keys-1"
}
```

**Payload (decoded, canonicalized):**
```json
{
  "aud": "did:web:server.example.com",
  "iss": "did:web:server.example.com",
  "nonce": "abc123...",
  "requestHash": "sha256:5057521f...",
  "responseHash": "sha256:d4e5f6...",
  "sessionId": "kyaos_d7f8a9b0-...",
  "sub": "did:web:server.example.com",
  "ts": 1710288000
}
```

**Signature:**
```
Ed25519Sign(privateKey, BASE64URL(header) || "." || BASE64URL(canonicalize(payload)))
```

**Compact JWS:**
```
<base64url-header>.<base64url-payload>.<base64url-signature>
```

Note: Actual signature values are key-dependent. Implementers should verify the structure and use the test key material from the reference implementation's test suite for bit-exact validation.

---

*End of Specification*
