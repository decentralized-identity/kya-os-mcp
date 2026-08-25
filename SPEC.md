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

**Stable 1.0.0** — Donated to DIF TAAWG (Decentralized Identity Foundation, Trusted AI Agents Working Group) and ratified as a DIF standard. The wire format is stable: any future change that breaks compatibility with this version will require a major version bump.

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
| **Responsible Party** | The entity ultimately accountable for the actions of an agent operating under a delegation chain. The Responsible Party is the root issuer of the chain (`issuerDid` of the root `DelegationCredential`). In personal use, the Responsible Party equals the Principal. In organizational use, the Responsible Party is the employing organization or parent entity while the Principal is the immediate human delegator within that organization. Reputation and accountability signals are scoped primarily to the Responsible Party rather than to an agent's ephemeral identity — "can this be trusted?" is ultimately a question about the accountable party. |
| **Delegation Chain** | An ordered sequence of Delegation Credentials from a root delegator (the Responsible Party) to the current agent, where each credential's subject is the next credential's issuer. |
| **Delegation Credential** | A W3C Verifiable Credential that grants specific permissions from an issuer (delegator) to a subject (delegate). Contains CRISP constraints defining allowed operations. |
| **Detached Proof** | A JWS (JSON Web Signature) that cryptographically binds a tool request and response together, enabling non-repudiation and audit. Attached to responses under the reverse-DNS key `org.kya-os/response-proof` within the MCP `_meta` field (prior keys `org.kya-os/proof` and bare `proof` accepted for backward compatibility; see §7.6). |
| **CRISP Constraints** | **C**onstraints, **R**esources, **I**dentity, **S**cope, **P**olicy — a structured envelope defining what operations a delegation permits: allowed scopes, budget caps, temporal bounds, and audience restrictions. |
| **Session** | An OPTIONAL, validated, time-bounded convenience context established via the `_kyaos_handshake` tool. Sessions aid replay prevention and provide a stable context for proof generation, but are **not** the durable authority — the per-request detached-JWS proof (§7) and DID-anchored grant (§6) are (see §5 preamble). KYA-OS sessions are independent of MCP's session, which was removed in MCP 2026-07-28 (SEP-2567/SEP-2575). |
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
         │  │      org.kya-os/response-proof:          │  │
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

Implementations MAY support additional DID methods. `did:cheqd` support, when
implemented, MUST be additive: it MUST NOT replace or weaken existing `did:key`
or `did:web` behavior, and it MUST NOT make cheqd resolution mandatory for
deployments that have not configured it.

### 4.2 Key Material

KYA-OS uses Ed25519 (EdDSA over Curve25519) for all cryptographic operations:

- **Key Size**: 32-byte private seed, 32-byte public key
- **Signature Size**: 64 bytes
- **Algorithm Identifier**: `EdDSA` (in JWS headers)
- **JWK Key Type**: `OKP` (Octet Key Pair)
- **JWK Curve**: `Ed25519`

> **Terminology.** This specification uses _secret key_ for the private half of a
> key pair, following current cryptographic convention. _Private key_ is synonymous
> and is retained where referenced standards use it (e.g. PKCS#8, JWK).

An agent's key pair MUST be generated by the agent or its designated custodian.
The secret key MUST NOT be generated by, transmitted to, or escrowed with any
registration, DID, directory, or reputation service; such services receive only
the public key (as the DID document or an indexing record). For `did:key` this
holds by construction — the DID is derived locally from the public key (§4.3) and
no service participates in creation. For `did:web`, the controller publishes only
the public key in the DID document (§4.4). A key-management proxy or HSM that
holds the secret key on the agent's behalf (key custody, §11.0) is part of the
agent's own trust boundary and is distinct from the shared services this
requirement constrains.

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

### 4.4.1 Optional did:cheqd Resolution and Registrar Writes

A KYA-OS implementation MAY support `did:cheqd` as an additional resolvable DID
method. `did:cheqd` resolution MUST be explicit opt-in through a configured
resolver endpoint, such as `https://resolver.cheqd.net/1.0/identifiers/{did}`.
Resolution failures MUST fail closed and MUST NOT fall back to accepting an
unresolved key.

Resolvers SHOULD accept both raw DID Documents and Universal Resolver-style DID
Resolution Results containing `didDocument`. They MUST reject malformed
`did:cheqd` values, HTTP or transport failures, invalid JSON, malformed DID
Documents, and DID Document `id` mismatches by returning no document.

KYA-OS deployments that expose cheqd support SHOULD use the generic DID method
resolver registry rather than a vendor-specific core config block:

```ts
didResolvers?: Record<
  string,
  DIDResolver | ((fetchProvider: FetchProvider) => DIDResolver)
>;

didResolvers: {
  cheqd: cheqdResolver({ resolverUrl: 'https://resolver.cheqd.net' }),
}
```

cheqd-specific resolver URL, cache, and header settings live in the cheqd
resolver factory or integration module, not in core middleware/provider
configuration. Registrar URLs are for explicit operator/admin write flows only.
Runtime proof generation and normal MCP tool-call handling MUST NOT create,
update, or publish cheqd ledger entries.

Updates to cheqd DID Documents and DID-Linked Resources SHOULD use cheqd DID
Registrar's client-managed-secret flow for `/create`, `/update`, and
`/{did}/create-resource`: the registrar returns a `jobId` and serialized
payload, the controller signs the serialized payload locally, then the client
submits `secret.signingResponse` back to the registrar. Secret keys MUST NOT be
transmitted to the registrar. Signing MAY be delegated to a KMS/HSM-backed
signer hook. Local Ed25519 helpers MUST keep key material inside the caller's
trust boundary and send only signatures to the registrar.

Mainnet deployments SHOULD run or contract against their own fee-payer
registrar deployment. Public or staging registrar endpoints SHOULD be treated as
testnet-only unless the operator has an explicit mainnet service agreement.

When linking an existing `did:web` identity to a `did:cheqd` identity, verifiers
SHOULD require bidirectional `alsoKnownAs` linkage:

1. Resolve the `did:web` DID Document.
2. Resolve the `did:cheqd` DID Document.
3. Confirm the `did:web` document lists the `did:cheqd` DID in `alsoKnownAs`.
4. Confirm the `did:cheqd` document lists the `did:web` DID in `alsoKnownAs`.

`did:web` remains canonical unless an operator explicitly publishes reciprocal
linkage. `alsoKnownAs` values on DID Documents MUST be strings. Resource metadata
aliases, where supported by a registrar, use a different resource-specific shape
and MUST NOT be accepted as DID Document `alsoKnownAs` entries.

Selected durable artifacts MAY be anchored as cheqd DID-Linked Resources under
the `did:cheqd` subject. Supported KYA-OS DLR artifact categories are:

| Artifact | Purpose |
|----------|---------|
| `CapabilityManifest` | Durable description of agent/tool capabilities and outputs |
| `ConformanceManifest` | Durable statement of protocol profiles and checks satisfied |
| `AccessHashManifest` | Durable hashes of off-chain policy/access artifacts |
| `TrustConfigManifest` | Durable trust policy, accepted DID methods, and linkage requirements |

DLR content SHOULD be canonicalized before hashing, and content hashes SHOULD
use `sha256:<64 lowercase hex characters>`. Updating a DLR means publishing a
new resource version in the same resource collection/name/type; prior content is
not overwritten. High-volume runtime events, raw operational logs, normal
tool-call proofs, and frequently changing metadata MUST remain off-chain.

Out of scope for this specification section: external registry changes,
reputation VC snapshot publication, status-list backend hosting, KYC/KYB
issuance, and replacing `did:web` as the canonical identity.

### 4.5 Agent-Controlled Key Generation

An agent MUST generate its own keypair locally. No other party generates,
holds, escrows, or otherwise gains access to an agent's secret key at any
point:

1. The agent generates an Ed25519 keypair (§4.2) using a local CSPRNG.
2. The agent derives its DID from the public key (`did:key`, §4.3) or publishes
   a DID document referencing the public key (`did:web`, §4.4).
3. Where a DID document is registered or published through a service, the agent
   signs the registration request with its secret key.
4. The service verifies the signature and publishes the document. It receives
   the public key only.

A registry (§6.8), verifier, or any registration or provisioning service MUST
NOT generate, escrow, or otherwise gain access to an agent's secret key. This
invariant keeps identity infrastructure from becoming a centralized key escrow:
a compromise of a registry or verifier MUST NOT yield agent secret keys (see
§11.11).

Implementations that generate or hold agent secret keys on the agent's behalf
are non-conformant.

---

## 5. Session Lifecycle

> **Normative framing (MCP 2026-07-28).** The KYA-OS session described in this
> section is an **OPTIONAL convenience layer**, not the protocol's durable source
> of authority. The **normative, durable authority** for every KYA-OS interaction
> is (a) the per-request **holder-of-key detached-JWS proof** (§7), which is
> self-contained and replay-bound on its own, and (b) the **DID-anchored
> delegation grant** (§6). A conformant verifier MUST be able to authorize and
> audit a request from the proof and grant alone, with no server-side session
> state.
>
> This independence is deliberate. MCP 2026-07-28 removed `initialize`/
> `initialized` (SEP-2575) and the `Mcp-Session-Id` header (SEP-2567), making the
> MCP core stateless: every request is self-contained, and client info, version,
> and capabilities ride in `_meta` per request. KYA-OS sessions are **KYA-OS's
> own layer** — established via the `_kyaos_handshake` tool (§14), independent of
> MCP's now-removed session — and exist only as a **transport/UX convenience**
> (e.g. for wallet-less clients, nonce bookkeeping, and a stable context for proof
> generation). They are an *application-state handle* in the SEP-2575 sense:
> explicit and model-visible, never hidden server state on which authorization
> silently depends.
>
> The `sessionId`/`nonce` carried in a proof (§7.2) therefore bind a proof to its
> originating handshake for replay defense; they are **not** a substitute for
> verifying the proof signature and the delegation chain. The mechanics below
> remain valid where a session is used.

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
    "https://schema.kya-os.org/v1/protocol/delegation/context/v1.0.0"
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

> **Schema dialect (MCP 2026-07-28).** All KYA-OS JSON Schemas in this
> specification — and the normative copies in `schemas/*.json` — are authored
> against **JSON Schema 2020-12** and MUST declare
> `"$schema": "https://json-schema.org/draft/2020-12/schema"`. KYA-OS MCP tool
> definitions MUST likewise express their `inputSchema` and `outputSchema` in
> JSON Schema 2020-12 (SEP-2106). Consistent with the RC, a tool's
> `structuredContent` MAY be any JSON value permitted by its `outputSchema`, not
> only a JSON object.

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

Revocation does not require a globally accessible list. A verifier only needs to
know whether a delegation has been revoked **for the resources it gates**, so the
revocation state MAY be held as verifier-local state rather than fetched from an
external URL. `StatusList2021` is the interoperable wire format for _publishing_
revocation when the delegator and verifier are operationally decoupled; it is not
a requirement to operate a public, globally-readable certificate-revocation list.
A verifier that issues and gates its own delegations MAY check revocation entirely
from local state.

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

Trust-registry rejection is advisory, not blocking. The cryptographic
delegation check is the load-bearing gate (§11.0); registry standing is a
secondary signal. Services SHOULD honor well-formed delegations from
low-standing delegates but MAY apply rate limits, additional verification, or
scope reduction. Outright rejection of well-formed delegations pushes the same
authority through worse channels — credential sharing, request proxying — which
reduces auditability rather than improving security.

### 6.9 Ephemeral Delegate Keys (Non-Normative)

A delegator MAY subject a `DelegationCredential` to a one-off ephemeral public
key (typically a `did:key`) instead of a long-lived agent DID. This
privacy-preserving pattern lets a chain authorize an action without correlating
the delegate across unrelated delegations (§12.1).

```json
{
  "credentialSubject": {
    "id": "did:key:z6Mk-ephemeral-...",
    "delegation": {
      "id": "del-ephemeral-001",
      "subjectDid": "did:key:z6Mk-ephemeral-...",
      "parentId": "urn:uuid:...",
      "constraints": { "scopes": ["files:read"] },
      "status": "active"
    }
  }
}
```

The ephemeral key signs presentations of this credential and is discarded once
the delegation expires. The `credentialSubject` carries only `id` and
`delegation`, so the example remains conformant with the subject-shape rule in
§6.2. Implementations MAY support this pattern; it is not required for any
conformance level.

### 6.10 Card-era profile: VC 2.0 + ZCAP-LD delegation

The Entity Card profile ([SPEC-ENTITY-CARD.md](./SPEC-ENTITY-CARD.md) §10) uses a newer credential
shape than §6.2: a W3C Verifiable Credentials 2.0 credential whose `credentialSubject` IS an
attenuated ZCAP-LD capability, revoked via W3C Bitstring Status List v1.0 (the successor to the
StatusList2021 mechanism of §6.6). The delegation model of this chapter - one credential per hop,
subset discipline at every link, cascading revocation (§6.5), the designation invariant (§6.4.1),
and the per-hop `audience` rule (§11.6) - is unchanged; only the wire shape and the revocation
list format differ. Both shapes remain valid for the 1.x line: §6.2 is what the legacy session
profile issues and verifies, this profile is what the Entity Card path issues and verifies, and an
implementation encountering one never needs to accept the other in its place. The JSON Schema is
published at `schemas/card-delegation-credential.json`.

**Credential shape.** One `DelegationCredential` per delegation **hop**; a chain runs `root → … → leaf`. A
`DelegationCredential` is a VC 2.0 whose `credentialSubject` IS an attenuated ZCAP-LD capability:

```jsonc
{
  "@context": [ "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/zcap/v1",
                "https://kya-os.org/ns/delegation/v1" ],
  "type": [ "VerifiableCredential", "DelegationCredential" ],
  "issuer": "<delegator DID>",
  "validUntil": "2027-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "urn:zcap:del_123",
    "invoker": "<delegate DID>",           // or "controller" (§2.3)
    "parentCapability": "<parent id | root invocationTarget>",
    "invocationTarget": "<resource DID>",
    "allowedAction": [ "payments.transfer" ],
    "caveats": [ { "type": "ValidUntil", "date": "…" },
                 { "type": "MaxAmount", "limit": "500.00", "currency": "USD" } ]
  },
  "credentialStatus": { "type": "BitstringStatusListEntry",
    "statusPurpose": "revocation", "statusListIndex": "42",
    "statusListCredential": "https://…/status/delegations" },
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022" }
}
```

Per-hop signature verification (the `DataIntegrityProof`, `eddsa-jcs-2022`) is a SEPARATE injected
concern; this profile specifies the attenuation + continuity recompute.

**The delegate.** The delegate is `credentialSubject.invoker`, falling back to `credentialSubject.controller`; a
capability MUST name one of them.

**Attenuation invariants (fail-closed, on resolve).** Note: earlier drafts labelled these "CRISP
attenuation"; they are the chain-attenuation rules and are distinct from the §6.3 CRISP constraint
envelope, whose subset discipline they generalize to ZCAP chains. A chain is valid only if EVERY hop attenuates its parent. Any broadening hop invalidates the whole
chain:

- **action subset** - child `allowedAction ⊆ parent`;
- **monotone caveats** - no parent caveat may be silently dropped; for a shared caveat type, child
  `MaxAmount ≤ parent` (same currency; compared as fixed-point decimals scaled to 6 places) and
  child `ValidUntil ≤ parent`; an unknown caveat type MUST be replicated **verbatim**;
- **top-level `validUntil` narrowing** - child `validUntil ≤ parent`;
- **continuity** - the parent's delegate (`invoker`) MUST equal the child's `issuer` (you may only
  re-delegate what was delegated to YOUR key), and child `parentCapability` MUST reference the
  parent capability `id`;
- **constant `invocationTarget`** along the chain;
- **depth** MUST NOT exceed **10** hops (`MAX_DELEGATION_DEPTH`);
- **root** - root `parentCapability` MUST equal its `invocationTarget` (the resource); when a
  resource owner / resource is asserted, root `issuer` MUST equal the resource owner and root
  `invocationTarget` MUST equal the resource.

A verifying resource SHOULD assert its own identity as the expected resource when it evaluates a
chain (the `resource` context of `evaluateDelegationChain`), so that a chain minted for a
different resource fails at the root check instead of being accepted by an unrelated Verifier.

**Revocation.** Revocation uses **W3C Bitstring Status List v1.0** [BITSTRING-STATUS-LIST]
(`BitstringStatusListEntry`) - the **successor to** the deprecated StatusList2021 - behind a
pluggable `RevocationChecker` seam so status-list churn never reaches callers. The default checker
resolves `statusListCredential` via SafeFetch (§6.6), inflates the multibase (`u` = base64url) +
GZIP `encodedList`, and reads the bit at `statusListIndex` MSB-first within each byte. It is
**fail-closed**: an unreachable list, malformed credential, mismatched `statusPurpose`, or
out-of-range index all resolve to `{ revoked: true }`. Each verdict also reports `fresh` - `true`
only when read from a live, in-validity-window (`validFrom`/`validUntil`, or
`issuanceDate`/`expirationDate`) status list. The chain walk is **cascading**: root→leaf,
short-circuiting on the first revoked/unresolvable hop (a revoked ancestor invalidates the subtree),
with `fresh` the AND of every checked hop. L2 accepts a non-revoked chain (cached / offline
acceptable); L3 additionally requires `fresh` (a live check).

**KYC/KYB.** KYC/KYB rides the same rail as an `IdentityVerificationCredential` whose `credentialSubject` is the
`responsibleParty` and which asserts the verification **fact + level** (`verificationLevel ∈
{ basic, enhanced, loa3 }`), never raw PII. It is verified via the same trusted-issuer + signature +
expiry path as an L2 capability attestation and surfaced through the Card's `attestations[]`.

---

The equalities a Verifier recomputes from a resolved chain, and their place in the fail-closed
verification order, are specified in SPEC-ENTITY-CARD.md §10.2 and §11.

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
  responseHash?: string; // SHA-256 of canonicalized response. Present on success
                         // AND on needs_authorization challenges (binds the
                         // challenge content, incl. authorizationUrl); ABSENT on
                         // denial / step-up proofs (no response body).
  scopeId?: string;     // Scope under which the call was made
  delegationRef?: string; // Reference to delegation credential
  clientDid?: string;   // Client's DID if authenticated
  outcome?: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization';
                         // Authorization outcome; ABSENT ⇒ implicitly 'allowed' (success)
  reason?: string;       // Human-readable reason on a non-'allowed' outcome
  prf?: 'org.kya-os/response-proof.v2';
                         // Response-proof profile discriminator, COVERED by the
                         // JWS signature. ABSENT ⇒ profile v1 (body-only
                         // responseHash, the original wire shape). Verifiers
                         // MUST reject any other value (fail-closed; §7.3).
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

Response canonicalization is selected by the proof's response-proof profile, named by the signature-covered `prf` claim (§7.2):

- **v1** (`prf` ABSENT — the original profile): the `data` field only (excludes `_meta`).
  Under MCP carriage, `data` is the result's `content` array; result members outside it are NOT covered.
- **v2** (`prf: "org.kya-os/response-proof.v2"`): the ENTIRE result object with the top-level `_meta` member removed, mirroring the request side's `{method, params minus _meta}` rule.
  This authenticates result members such as `structuredContent`, `isError`, and `resultType` that v1 leaves uncovered, while `_meta` stays intermediary-mutable — which is what lets the proof itself be attached there after signing.

A verifier derives the profile from the received proof's own `prf` claim, never from configuration, and MUST reject an unrecognized `prf` outright.
Because `prf` is covered by the signature, stripping it from a v2 proof breaks verification — a downgrade to v1 semantics is a hard failure, not a silent fallback.
Producers default to v1 for the 1.x line (wire compatibility with existing verifiers); v2 is an explicit opt-in (`responseProofProfile` in the middleware configuration) and becomes the default at 2.0.

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

A v2 proof (§7.3) additionally carries its `prf` claim in this payload — profile selection is signed, never advisory.
Every optional `ProofMeta` member present on the proof (`scopeId`, `delegationRef`, `clientDid`, `outcome`, `reason`, `prf`) appears in the payload; the mirrored `meta` block and the decoded payload MUST reconcile exactly.

**Denial** and **step-up** proofs have no response body, so `responseHash` is
omitted and `outcome` (plus an optional `reason`) is included instead. Keys
remain RFC 8785-sorted:
```json
{
  "aud": "did:web:server.example.com",
  "iss": "did:web:server.example.com",
  "nonce": "...",
  "outcome": "denied",
  "reason": "insufficient_scope",
  "requestHash": "sha256:...",
  "sessionId": "kyaos_...",
  "sub": "did:web:server.example.com",
  "ts": 1710288000
}
```

A **needs_authorization** challenge *does* carry a response body (the consent
challenge, including the `authorizationUrl`), so its proof includes **both** a
`responseHash` over that body — binding the URL against tampering / MITM
substitution — and `outcome: "needs_authorization"`:
```json
{
  "aud": "did:web:server.example.com",
  "iss": "did:web:server.example.com",
  "nonce": "...",
  "outcome": "needs_authorization",
  "reason": "requires delegation with scope: greeting:restricted",
  "requestHash": "sha256:...",
  "responseHash": "sha256:...",
  "sessionId": "kyaos_...",
  "sub": "did:web:server.example.com",
  "ts": 1710288000
}
```

### 7.5 _meta Attachment

The proof is attached to tool responses under the reverse-DNS key
`org.kya-os/response-proof` inside the standard MCP `_meta` field. Other `_meta` keys
(e.g. `io.modelcontextprotocol/*`, `traceparent`) MAY coexist and are ignored by
the verifier (§7.6):

```json
{
  "content": [{ "type": "text", "text": "File contents..." }],
  "_meta": {
    "org.kya-os/response-proof": {
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
    },
    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
  }
}
```

The `traceparent` key above illustrates a coexisting reserved key; it is not part
of the proof and is never hashed or trusted (§7.6).

### 7.6 _meta Namespacing and Hash Exclusion

The response hash is computed over the response object with `_meta` removed (see
§7.3). Implementations MUST NOT rely on signature coverage of any `_meta` field.

`_meta` is the Model Context Protocol per-request metadata channel and is shared
real estate: under MCP 2026-07-28 it legitimately carries reverse-DNS–namespaced
keys reserved by the MCP maintainers (`io.modelcontextprotocol/*`) and W3C Trace
Context propagation keys (`traceparent`, `tracestate`, `baggage`). KYA-OS
therefore namespaces its own payload and MUST NOT assume exclusive ownership of
`_meta`.

**Canonical key.** KYA-OS attaches its detached response proof under the
reverse-DNS key `org.kya-os/response-proof` (the `proofMetaKey`). The key is
named for its role, pairing with the request proof's `org.kya-os/request-proof`
(SPEC-ENTITY-CARD §8); the two keys carry different objects, and neither carries
a version - the request proof's profile version lives inside the object (`prf`). This key SHOULD be configurable (e.g., a
single build-time constant rather than a value scattered through the code), so
that if and when KYA-OS is registered as an MCP Extension (SEP-2133), its
reverse-DNS extension id — and hence this key — can be re-pointed without a wire
change.

**Backward compatibility.** Two prior keys carried this proof: bare `proof`
(pre-1.1) and `org.kya-os/proof` (1.1 until the role-named rename). For one
major version, verifiers MUST also accept a proof published under either prior
key. Producers emit `org.kya-os/response-proof` and MAY additionally mirror the
proof under a prior key when targeting older verifiers. When several keys are
present, the newest canonical form wins (`org.kya-os/response-proof`, then
`org.kya-os/proof`, then `proof`).

**`metaPolicy` semantics.** The `session.metaPolicy` setting governs how a
verifier treats `_meta` keys that are *not* KYA-OS's proof key:

- `strict` (the default) — the verifier processes **only** the KYA-OS proof key
  (`org.kya-os/response-proof`, or a prior key `org.kya-os/proof` / `proof`). All other keys are **ignored**: never
  hashed, never trusted, and — critically — **never a cause for rejection**. In
  particular a `strict` verifier MUST NOT reject a response merely because
  `_meta` also carries `io.modelcontextprotocol/*`, `traceparent`, `tracestate`,
  or `baggage`; these reserved/standard keys are explicitly allowlisted and pass
  through untouched.
- `allow-extensions` — identical trust boundary (still only the KYA-OS proof key
  is hashed or trusted), but the verifier additionally surfaces non-KYA-OS
  `_meta` keys to the application layer rather than discarding them.

Under no policy does a verifier include any non-proof `_meta` key in a hash or
signature computation. The signature covers the profile-selected response
material only — the `data` body under v1, the result envelope minus its
top-level `_meta` under v2 — and never covers `_meta` itself (§7.3).

> **Note.** The proof object's shape is normatively defined by
> `schemas/detached-proof.json` (`$schema: draft/2020-12`). The *placement* key
> inside `_meta` is `org.kya-os/response-proof`; the schema describes the value
> (`{ jws, meta }`), not the key.

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
    "org.kya-os/response-proof": {
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

| Header | Disposition | Value |
|--------|-------------|-------|
| `KYA-OS-Delegation-Credential` | **AUTHORITATIVE** | The delegation Verifiable Credential (VC-JWT). The verifier derives granted scopes and the delegation chain from it (its embedded scopes, its chain to a trusted root, its StatusList revocation state). |
| `KYA-OS-Delegation-Proof` | **AUTHORITATIVE** | The holder-of-key delegation proof JWT (EdDSA-signed, `aud`-bound to the request authority, `sub` == the Layer-1 signature DID); see §8.2. |
| `KYA-OS-Agent-DID` | **AUTHORITATIVE** | The agent's DID. A conformant verifier MUST check it equals the Layer-1 signature's resolved DID. |
| `KYA-OS-Session-Id` | Anchor | The KYA-OS session ID, used for grant read-back. An anchor, not an authorization input. |
| `KYA-OS-Delegation-Chain` | OPTIONAL (advisory) | A transport hint for routing/observability/debugging. **MUST NOT** be used for any authorization decision; ignored when it disagrees with the credential. |
| `KYA-OS-Granted-Scopes` | OPTIONAL (advisory) | A transport hint for routing/observability/debugging. **MUST NOT** be used for any authorization decision; ignored when it disagrees with the credential. |

**The Verifiable Credential is authoritative.** Granted scopes and the delegation
chain are derived from cryptographically-signed artifacts — the
`KYA-OS-Delegation-Credential` (VC-JWT) and the `KYA-OS-Delegation-Proof` JWT —
never from advisory transport headers. A conformant verifier MUST derive
authorization from the credential (its embedded scopes, its chain to a trusted
root, its revocation state) and MUST check that `KYA-OS-Agent-DID` equals the
Layer-1 signature's resolved DID. `KYA-OS-Delegation-Chain` and
`KYA-OS-Granted-Scopes` are advisory only: a conformant verifier MUST NOT trust
them for any authorization decision and MUST ignore them when they disagree with
the credential.

**Corollary (covered components).** Because authority is derived only from signed
artifacts — the VC and the proof JWT, each with independent integrity — the
Layer-2 headers are **NOT required** to be RFC 9421 covered components. Signing
them is permitted as defense-in-depth but is not a conformance requirement. A
tampered `KYA-OS-Granted-Scopes` or `KYA-OS-Delegation-Chain` is therefore not a
vulnerability: it is ignored by a conformant verifier.

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

The JWT is signed with EdDSA using the server's secret key.

### 8.3 Chain String Format

```
<vcId>><delegationId>
```

Example: `urn:uuid:d7f8a9b0-1234-5678-9abc-def012345678>del-001`

### 8.4 Gateway Routing Without Body Inspection (MCP 2026-07-28)

A policy enforcement point (PEP) or gateway in front of a KYA-OS server can make
routing and coarse policy decisions from headers alone, without parsing the JSON
body. Under MCP 2026-07-28 (SEP-2243), the request carries the routing headers
`Mcp-Method` (the JSON-RPC method, e.g. `tools/call`) and `Mcp-Name` (the target,
e.g. the tool name). A KYA-OS-aware gateway MAY:

- route on `Mcp-Method` / `Mcp-Name`; and
- authenticate the caller and check coarse authority from the KYA-OS delegation
  headers (§8.1) and the detached `KYA-OS-Delegation-Proof` (§8.2),

all before the body is read. This is an optimization only: the origin server MUST
still perform full delegation-chain and detached-proof verification (§6, §7) on
the request body. Routing headers are advisory and MUST NOT be trusted as
authority.

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

The `needs_authorization` response is itself **signed**: it carries a detached-JWS
proof in `_meta` (`outcome: 'needs_authorization'`) whose `responseHash` binds the
challenge content, including `authorizationUrl` (see §7.4). A client detects a
substituted consent URL by verifying that proof against the resource's DID and
recomputing `responseHash` over the challenge it actually received
(`ProofVerifier.verifyProof(proof, jwk, { request, response })`) — see §11.1.

### 9.3 Resume Flow

1. Client receives `needs_authorization` error
2. Client verifies the challenge proof against the resource's DID — recomputing
   `responseHash` over the received content — before trusting `authorizationUrl`
   (detects a substituted consent URL; §11.1)
3. Client directs user to `authorizationUrl`
4. User authenticates and grants authorization
5. Authorization service issues DelegationCredential
6. Client retries request with `resumeToken` and new delegation
7. Server validates delegation and processes request

### 9.4 OAuth/OIDC Hardening Alignment (MCP 2026-07-28)

Where the authorization service in §9.3 is an OAuth 2.0 / OIDC authorization
server, the KYA-OS profile aligns with the MCP 2026-07-28 OAuth hardening SEPs.
These are *additive* hardening requirements; they do not change the KYA-OS trust
model (§15.1), in which authority rides on a verified delegation chain, not on a
bearer token.

1. **Issuer validation (RFC 9207 / SEP-2468).** On the authorization callback /
   resume step, the client MUST validate the `iss` authorization-response
   parameter against the expected issuer and MUST reject a response whose `iss`
   does not exactly match. This is verified *in addition to* recomputing
   `responseHash` over the challenge (§9.3 step 2).
2. **Credential↔issuer binding (SEP-2352).** Any token or credential obtained in
   step 5 MUST be bound to, and accepted only for, the issuer that minted it; a
   credential MUST NOT be replayed against a different issuer or resource.
3. **Dynamic Client Registration `application_type` (SEP-837).** Clients
   performing DCR MUST declare `application_type` and MUST NOT use a redirect URI
   inconsistent with it.
4. **Refresh & step-up (SEP-2207 / SEP-2350).** Refresh tokens follow SEP-2207;
   a `step_up_required` outcome (§7.2) accumulates scope per SEP-2350 rather than
   discarding previously granted scope.
5. **Metadata discovery (SEP-2351).** `.well-known` authorization-server and
   protected-resource metadata use the SEP-2351 path-suffix form.

A KYA-OS server MUST NOT treat successful completion of this OAuth flow as
sufficient on its own: the resulting DelegationCredential is still verified per
§6 and §7 on the retried request (§9.3 step 7).

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
  "supported_did_methods": ["did:key", "did:web", "did:cheqd"],
  "proof_algorithms": ["EdDSA"],
  "clockSkewSeconds": 120,
  "endpoints": {
    "handshake": "/_kya-os/handshake",
    "status_list": "/.well-known/status/1"
  }
}
```

Servers SHOULD list `did:cheqd` only when cheqd resolution has been explicitly
configured for that deployment.

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

**L2+ is not OAuth-style client registration.** Direct server-side verification
(Conformance Level 2+) authenticates the agent's identity, but the access decision
still rests on the **delegation chain the agent presents** — the delegated
authority rooted at a Responsible Party — not on the agent's identity alone. An
authenticated agent holding no valid delegation for the requested resource is
denied. This inverts the OAuth Dynamic Client Registration pattern, where a
registered client gains access by virtue of being a recognized client: here, being
a recognized agent grants nothing without a credential that designates the specific
resource (§6.4.1).

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
| **Agent abuse** — a legitimate agent exceeds expected behavior. | Audit log of every signed tool call (§7); reputation tracking on both agent and Responsible Party (§11.12); revocation. | Detection latency; damage done before revocation propagates. |
| **Key compromise** — an agent's secret key is exfiltrated. | Short-lived delegations; explicit revocation; key rotation via DID document update. | Window between compromise and detection. See §11.5. |
| **Revocation race** — an invocation arrives while a revocation is propagating. | Status-list TTL bounded ≤ 60s for high-privilege scopes; side-channel revocation signals honored immediately; expiry as primary revocation mechanism. See §6.5.2. | Unavoidable Lamport-concurrent race. Operators bound the window; they cannot eliminate it. |
| **Downgrade** — a client strips KYA-OS headers entirely. | Fail-closed: servers requiring identity MUST reject sessionless calls; `/.well-known/mcp` advertises requirements. See §11.7. | A non-compliant client that the operator has not configured to require identity. |
| **Consent-URL substitution** — a malicious in-path intermediary swaps the `authorizationUrl` in a `needs_authorization` challenge to phish the user toward an attacker-controlled consent page. | The challenge is signed (`outcome: 'needs_authorization'`); its `responseHash` binds the challenge content incl. the URL (§7.4, §9.2). A client recomputes `responseHash` over the received challenge and verifies the proof against the resource DID, detecting the swap. | A client that does not verify the challenge proof / recompute the hash — the check is the verifier's responsibility (a §11.7-style downgrade). TLS protects the URL in transit; this adds defense against a malicious in-path component. |
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

### 11.11 Key Custody and Escrow Exclusion

KYA-OS excludes centralized agent-key generation as a failure mode. If a single
service generated agent keypairs — even transiently — that service would hold
the secret material for every identity it provisioned, recreating the escrow
weakness of identity-based-encryption-style key-generation centers: one
compromise yields every dependent secret key. Agent-controlled key generation
(§4.5) removes that single point of total compromise. A registry or verifier
that is breached leaks public material and metadata, never agent secret keys,
because no protocol component ever holds them. Operators MUST NOT introduce a
server-side key-generation or escrow step as a convenience; doing so is
non-conformant (§4.5).

### 11.12 Reputation Scope

Reputation is tracked primarily on the Responsible Party — the root issuer
accountable for a delegation chain (§2). Agent-level reputation, where
surfaced, is a secondary signal scoped to a specific binding rather than a
free-floating per-agent score. A newly minted agent inheriting authority from a
high-reputation Responsible Party MUST be treated as carrying that party's
standing for capability decisions, modulo binding-specific risk signals. This
closes reputation laundering in both directions: a bad actor cannot shed a poor
Responsible-Party history by spawning fresh agents, and a new agent under a
trusted party is not penalized for lacking its own history.

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

### 12.5 Per-Delegation Keys (Delegate Unlinkability)

A delegate that does not wish to link its activity across delegations MAY present a fresh, single-purpose public key for each delegation it receives, rather than its long-term DID. The delegator issues the `DelegationCredential` to that one-off key, and the delegate proves control of it for that delegation only. This keeps the delegate's primary identity unlinkable across delegations and prevents a delegator — or an observer who sees multiple delegations — from correlating them through a shared subject DID.

_Non-normative example:_ an organization delegating read access to an external auditing agent issues each engagement's delegation to a per-engagement key the auditor generates, so separate engagements cannot be cross-correlated via a common subject identifier.

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

**Body-free routing**: On HTTP transports, intermediaries MAY route on the MCP
2026-07-28 routing headers `Mcp-Method` and `Mcp-Name` (SEP-2243) and verify the
KYA-OS delegation headers (§8.1) and detached proof (§8.2) without inspecting the
request body. See §8.4. The origin server remains responsible for full
verification.

---

## 15. Conformance

Implementation conformance requirements are defined in `CONFORMANCE.md`. Three compliance levels are specified:

- **Level 1 — Core Crypto**: Basic key generation, signing, verification, and well-known endpoint
- **Level 2 — Full Session**: Session handshake, nonce replay prevention, proof generation
- **Level 3 — Full Delegation**: VC issuance/verification, delegation graphs, revocation, outbound propagation

See `CONFORMANCE.md` for detailed requirements and test references.

### 15.1 Relationship to OAuth Dynamic Client Registration

KYA-OS L2+ is not OAuth Dynamic Client Registration restated. OAuth-DCR binds a
client by a `client_id`/`client_secret` registered with an authorization server,
after which authority rides on a bearer token. KYA-OS binds an agent by its DID
and requires the delegation chain to be presented and cryptographically verified
at every invocation (§6, §7). The delegation chain remains required and
verifiable at Level 2 and Level 3 regardless of whether or how the agent's
identity is recorded in a trust registry (§6.8). Registry presence is discovery
and a trust signal (§11.0), never a substitute for chain verification.

This is complementary to, not in tension with, MCP 2026-07-28's OAuth hardening.
Where KYA-OS interoperates with an OAuth/OIDC authorization server (§9.4), it
adopts that server-side hardening — `iss` validation per RFC 9207 (SEP-2468),
credential↔issuer binding (SEP-2352), DCR `application_type` (SEP-837) — as the
*token-acquisition* layer, while the delegation chain (§6, §7) remains the
*authority* layer verified at every invocation. OAuth hardening strengthens how a
credential is obtained; it never becomes the basis on which a KYA-OS request is
authorized.

### 15.2 MCP 2026-07-28 Compatibility

KYA-OS is designed to layer cleanly on the MCP 2026-07-28 Release Candidate.

- **Stateless core.** MCP removed `initialize`/`initialized` (SEP-2575) and the
  `Mcp-Session-Id` header (SEP-2567). KYA-OS does not depend on either: every
  KYA-OS request is authorized from its self-contained detached-JWS proof (§7)
  and DID-anchored grant (§6). The KYA-OS session (§5) is an optional KYA-OS-owned
  convenience layer delivered via the `_kyaos_handshake` tool (§14) and is
  independent of MCP's removed session.
- **`_meta` reserved-namespace coexistence.** KYA-OS publishes its response proof
  under the reverse-DNS key `org.kya-os/response-proof` and ignores all other `_meta` keys, including
  the MCP-reserved `io.modelcontextprotocol/*` and W3C Trace Context keys
  `traceparent`/`tracestate`/`baggage` (SEP-414). See §7.6.
- **Routing headers.** KYA-OS gateways MAY use `Mcp-Method`/`Mcp-Name` (SEP-2243)
  for body-free routing (§8.4).
- **JSON Schema 2020-12.** Tool `inputSchema`/`outputSchema` and KYA-OS schemas use
  JSON Schema 2020-12 (SEP-2106); see §6.2.
- **Extensions Track intent (SEP-2133).** KYA-OS intends to register as an MCP
  Extension under the proposed reverse-DNS extension id `org.kya-os/decentralized-authority`,
  with an `ext-*` repository, independent versioning, and negotiation via the
  `extensions` capability map. Once registered, the canonical proof key (§7.6
  `proofMetaKey`) and capability advertisement (§10) will use that extension id;
  the key is configurable for this reason. KYA-OS targets the SEP-2133
  Standards-Track path.
- **Deprecations are zero-impact.** SEP-2577 deprecates MCP **Roots**, **Sampling**,
  and **Logging** on 12-month windows. KYA-OS uses **none** of these features, so
  the deprecations have **no impact** on KYA-OS implementations.

### 15.3 Auditability Protocol

An implementation that advertises a KYA-OS Audit Assurance Profile (AAP) MUST
use the versioned audit schemas under `schemas/audit-*.schema.json` and MUST NOT
infer a stronger claim from detached proofs alone.

The audit protocol separates three authorities:

1. The producer emits a strict, privacy-minimal event with a stable event ID,
   source ID, source sequence, and optional source-predecessor digest.
2. Exactly one authoritative recorder for a `(ledgerId, ledgerEpochId)` assigns
   recorder time, a monotonically increasing decimal sequence, the previous
   entry digest, and a signed append receipt through an atomic compare-and-append
   operation.
3. An independent observer MAY retain and compare signed RFC 9162 checkpoints.
   WORM, RFC 3161, and SCITT receipts are supporting anchors and MUST NOT be
   represented as independent split-view detection.

The producer event, entry, receipt, checkpoint, observation, and bundle manifest
MUST be strictly schema-valid before RFC 8785 canonicalization. Integrity hashes
MUST use the domain-separated construction
`SHA-256(UTF8(domain) || 0x00 || JCS(value))`. Entries are immutable: correction,
redaction, disposal, retention, legal-hold, key transition, and epoch transition
are represented by new events.

Redelivery of the same authenticated producer/source/event identity and the same
frozen producer bytes MUST return the original stored receipt. Reuse with
different bytes MUST fail. This idempotency namespace spans retained epochs of
the logical ledger. A new epoch starts at sequence zero only through a signed
genesis that commits the prior epoch and its terminal checkpoint.

Replay-bundle verification MUST receive recorder/observer/exporter trust and
purpose/scope authorization out of band. Bundle contents cannot authorize their
own signer or bootstrap their own trust root. A verifier MUST distinguish
`valid`, `invalid`, and `indeterminate`, MUST keep authorization-as-observed
separate from current authorization/revocation, and MUST NOT consume a live
nonce cache when verifying historical proof artifacts.

Sensitive payloads SHOULD be encrypted in a separate evidence provider and
referenced by opaque randomized identifiers and ciphertext commitments. The
integrity ledger MUST NOT contain raw tool arguments, responses, access tokens,
or free-form exception text by default. Evidence disposal MUST NOT mutate the
retained integrity history.

The AAP levels are cumulative:

- **AAP-0:** no audit assurance.
- **AAP-1 Recorded:** structured capture of delivered instrumented events.
- **AAP-2 Chained:** durable atomic accepted history with non-best-effort
  delivery.
- **AAP-3 Transparent:** AAP-2 plus durable source high-water reconciliation and
  signed RFC 9162 checkpoints/proofs.
- **AAP-4 Observed:** AAP-3 plus independently administered checkpoint
  observation and authenticated view comparison, with supporting external
  receipt evidence.

Implementations MUST advertise capabilities truthfully and MUST reject startup
when configured mechanics cannot satisfy the selected profile. Full event
semantics, provider contracts, failure behavior, privacy guidance, replay-bundle
rules, and operational requirements are specified in [`AUDITABILITY.md`](./AUDITABILITY.md).

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
| `handshake_failed` | Handshake validation failed (timestamp, nonce, or audience) |
| `session_expired` | Session not found or expired |
| `delegation_invalid` | Delegation verification failed |
| `insufficient_scope` | Requested operation outside delegated scope |
| `delegation_revoked` | Delegation has been revoked |
| `invalid_proof` | Proof verification failed |
| `did_not_found` | DID resolution failed |

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
