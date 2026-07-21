# KYA-OS Entity Card - Profile Specification

**Typed, DID-anchored, per-request holder-of-key identity for the agent ecosystem**

Version: 1.1 (Entity Card profile)
Reference implementation: `@kya-os/mcp` v1.10.x (subpath `@kya-os/mcp/card`)
Status: **DIF TAAWG work item / reference implementation**
Editors: KYA-OS Working Group
Repository: https://github.com/decentralized-identity/kya-os-mcp
Profiles: the KYA-OS Protocol Specification ([SPEC.md](./SPEC.md))

---

## Abstract

The **KYA-OS Entity Card** is one canonical, typed, DID-anchored identity object, projected onto
the discovery rails the agent ecosystem already indexes: the MCP `server.json` / `catalog.json`
`_meta`, the A2A `AgentExtension`, and the NANDA `AgentFacts` document. Each projection points
back to the same card, anchored by a `KyaOsEntityCard` service entry on the entity's `did:web`
DID document. On top of that discovery layer rides a per-request, sender-constrained
holder-of-key proof (`org.kya-os/proof@1`) carried under its own `_meta["org.kya-os/proof@1"]`
key: discover like everyone, prove like no one. An unaware peer safely ignores the KYA-OS layer;
a KYA-OS-aware peer can verify the caller cryptographically on every request.

This profile claims two properties as uniquely filled seams, and only these two. First, **typed
entities**: nothing in A2A, NANDA, CIMD, MCP `server.json`, or the AIP capability-token work
types the principal (`mcp | agent | client | verifier | human`). Second, **per-request proven
accountability**: other card and document schemes prove card- or document-integrity, not that the
live caller currently holds the key bound to a typed entity that is accountable up a verifiable
delegation chain. KYA-OS does not re-claim NANDA's `owner` edge (it populates it) and does not
claim novelty for using DIDs or VCs (it profiles them).

---

## Conformance Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

Two sub-primitives in this specification are marked **[TAAWG-NORMATIVE]**: the entity **type
axis** (§3) and the per-request holder-of-key **binding** `client_id → did:web → mandate-VC`
(§7–§8). These are the two primitives KYA-OS seeks to ratify in the DIF Trust and Authorization
for AI Agents Working Group (TAAWG); every other normative requirement in this document is shipped
as the reference implementation (§15.6).

---

## Status of This Document

This is a **DIF TAAWG work item** with a conformant **reference implementation** in
`@kya-os/mcp` (v1.10.x at the time of writing). The Entity Card profile is additive over, and
non-breaking with respect to, the KYA-OS 1.x protocol. The `org.kya-os/proof@1` profile defined
here coexists with the legacy session-bound proof, and each rides its own `_meta` key:
`org.kya-os/proof@1` for this profile, `org.kya-os/proof` for the legacy proof (§8.1, §15.5). The
card proof additionally names its profile in a `prf` field. The wire shapes in §3–§8 and
Appendix A are stable for the 1.x line; a breaking change requires a major version bump.

Several referents are **moving targets**; each normative reference to one is pinned with a
**verified-at** date (§15). Implementers MUST re-verify a moving target at use-time before relying
on a version-specific claim.

---

## 1. Introduction & Scope

### 1.1 The problem: a discoverable-but-unproven ecosystem

Agent discovery has converged on a stack of unauthenticated, cacheable document fetches. That
stack answers "*can I find and connect to this entity?*" It does not answer the question that
actually gates an action: "*is the entity in front of me, right now, the accountable keyholder for
THIS exact request?*" The discovery layers, from lowest to highest:

| Layer | Rail | What it establishes | What it does NOT establish |
|-------|------|---------------------|----------------------------|
| **D1** | MCP `server.json` (MCP Registry) | Distribution + reverse-DNS/GitHub namespace trust | No cryptographic identity |
| **D2** | Server Card / `catalog.json` index (SEP-2127) | A discoverable index of server cards; identity fields **advisory, not authoritative** | No per-request proof; untyped principal |
| **D3** | CIMD (`client_id` metadata document, SEP-991 / draft-ietf-oauth-client-id-metadata-document) | OAuth key possession **once, at the token endpoint** | No DID anchor; no per-request proof-of-possession |
| **D4** | **KYA-OS Entity Card (this document)** | Typed DID-anchored identity + **per-request** holder-of-key proof | - (the layer this document adds) |

D1–D3 are shipped and widely deployed. D4 is the seam KYA-OS fills, and it fills it *by projecting
onto* D1–D3 rather than by introducing a competing rail (§6, §7).

### 1.2 Scope

This document specifies, normatively:

- the **entity model** and its `type` axis (§3);
- the **Card object** - fields, claim-minimalism, JSON Schema (§4, Appendix A);
- **anchoring** on `did:web` / `did:key` and the `KyaOsEntityCard` DID-document service (§5);
- the four **discovery projections** and their graceful-degradation contract (§6);
- the **CIMD on-ramp** binding `client_id ⇄ did:web`, `jwks_uri ⇄ DID keys` (§7);
- the **per-request holder-of-key proof** `org.kya-os/proof@1`, its dual carrier, and the
  `cnf.jkt` sender-constraint fusion (§8);
- the **conformance ladder** L1/L2/L3 and its recompute-on-verify algorithm (§9);
- the **accountability joins and revocation binding** Card verification consumes (§10); the
  delegation profile itself lives in the core protocol specification (SPEC.md §6, §6.10);
- the exact, fail-closed **verification algorithm** (§11);
- **security** (§12), **privacy** (§13), **IANA/registry** considerations (§14), and **interop**
  (§15).

Out of scope: the wire framing of MCP itself; key custody hardware; the authorization server's
internal token issuance (§7.5 specifies only the `cnf` binding KYA-OS consumes); and business-layer
KYC/KYB adjudication (§10.4 points at the credential shape that carries its *result*).

### 1.3 The two claims

KYA-OS claims exactly two uniquely-filled seams: **typed entities** (§3) and **per-request proven
accountability** (§8–§11). For comparison: A2A signs the card (card-integrity); NANDA names an
`owner` and signs `AgentFacts` (document-integrity plus a static accountability claim KYA-OS
populates); CIMD proves key possession once, at the token endpoint (session-integrity). None of
them type the principal, and none prove the live caller per request. The `cnf.jkt` fusion (§8.6)
connects the two claims, from the L1 token to the L3 per-request proof, through one DID key.

---

## 2. Terminology & Roles

### 2.1 Roles

| Role | Definition |
|------|------------|
| **Holder** | An entity that controls a DID key and MINTS an Entity Card and per-request proofs under it. |
| **Verifier** | An entity that RESOLVES another entity's Card and RECOMPUTES its claims and per-request proofs (§9, §11). A Verifier is itself a typed entity (`entityType: "verifier"`). |
| **Issuer** | An entity that signs a Verifiable Credential (a delegation, capability attestation, or identity-verification credential) about a subject (§10). The default trusted issuer is `did:web:example.com` (§9.5). |

### 2.2 Terms

| Term | Definition |
|------|------------|
| **Entity** | A first-class, DID-identified principal of exactly one `entityType` (§3). Each Entity has its own DID and its own Card. |
| **Entity Card** (Card) | The typed, DID-anchored identity object of §4. It ASSERTS identity + type + declared capabilities; everything trust-bearing is PROVEN by referenced credentials (claim-minimalism, §4.2). |
| **Responsible Party** | The entity **ultimately accountable** for an Entity's actions: the **root issuer** of its delegation chain (`issuer` of the root `DelegationCredential`). Carried on the Card as `responsibleParty`; verified as `responsibleParty === issuer(rootVC)`, never self-asserted (§10.2). |
| **Principal** | The **immediate** delegator - typically the authorizing human - when it differs from the Responsible Party. Carried as `principal`. |
| **Delegation Chain** | An ordered sequence of `DelegationCredential`s from the root delegator to the current Entity, each hop's delegate being the next hop's issuer (§10.1). |
| **Capability** (Card field) | A declared operation NAME: what an Entity says it can do. Declaring one conveys no authority - authority is conveyed only by a delegation chain (§10), where the ZCAP-LD capability (the signed credential) is the authority object. A bare string is L1 (self-declared); an object `{ name, attestations }` is L2 (attested by a Verifiable Credential) (§4.1, §9). |
| **Holder-of-Key Proof** | The per-request, sender-constrained `org.kya-os/proof@1` object (§8) that proves the caller currently controls the DID key bound to the Card. |
| **Audience** | The intended recipient of a proof - the recipient Entity's DID, read from its Card. Binds a proof to THIS recipient (anti-relay / anti-confused-deputy, §8.4). |
| **`cnf.jkt`** | An RFC 7638 [RFC7638] JWK thumbprint used as an RFC 9449 [RFC9449] confirmation-key sender-constraint. The fusion anchor of §8.6. |
| **CIMD** | Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document / SEP-991): the OAuth `client_id` is an HTTPS URL that serves the client's metadata. The KYA-OS L1 on-ramp (§7). |
| **Conformance Level** | A DERIVED, verifier-recomputable floor (`L1`/`L2`/`L3`, §9) summarizing an Entity's assurance. The Card's self-declared `conformanceLevel` is NEVER trusted. |

### 2.3 Forbidden accountability synonyms

For the accountability edge, the ONLY normative terms are **Responsible Party** (root) and
**Principal** (immediate delegator). An implementation MUST NOT introduce `owner`, `operator`, or
`controller` as accountability-role synonyms on the Card. (Note: ZCAP-LD's
`credentialSubject.controller` - SPEC.md §6.10 - names the *delegate* of a capability, a distinct concept
that is retained under its ZCAP meaning; and NANDA's `owner` slot is *populated from*
`responsibleParty` in the AgentFacts projection - §6.3 - not adopted as a Card field.)

---

## 3. Entity Model (NORMATIVE) [TAAWG-NORMATIVE]

The entity **type axis** is the first of the two primitives KYA-OS seeks to standardize. It is the
one axis empirically confirmed absent from every surveyed rail (§15).

### 3.1 Entity types

```
entityType ∈ { mcp, agent, client, verifier, human }
```

An Entity Card MUST declare exactly one `entityType` from this closed set:

| `entityType` | The principal it types |
|--------------|------------------------|
| `mcp` | An MCP server. |
| `agent` | An autonomous agent (the only principal the A2A projection applies to, §6.2). |
| `client` | An OAuth/MCP client; the natural product of the CIMD on-ramp (§7). |
| `verifier` | An entity that verifies others' Cards and proofs. |
| `human` | A person acting as a delegating principal; typically `did:key` (§5.1). |

Each type is a first-class principal with its own DID and its own Card.

### 3.2 Sub-resources are not entities

`tool` and `skill` are **sub-resources** - capabilities *of* an `mcp` or `agent` - and MUST appear
inside `capabilities` (§4.1), never as a standalone `entityType`. There is no standalone `tool`
card and no standalone `skill` card.

### 3.3 Field naming

The type field MUST be named **`entityType`**, not `type`, to avoid collision with the
deployment-flavour field `AgentIdentity.type` (`development | production`) already present in
`@kya-os/mcp`. The `entityType` value space is closed (§3.1); it MUST NOT be extended without a
version bump.

---

## 4. Card Object (NORMATIVE)

The runtime source of truth is the Zod schema `EntityCardSchema`
(`@kya-os/mcp/card`, `src/card/schema.ts`), which mirrors the published JSON Schema
`schemas/kya-os-card.schema.json` (`$id`
`https://schema.kya-os.org/v1/protocol/identity/card/v1.1.0`, Appendix A). The JSON Schema declares
`additionalProperties: false` on the Card object; a conformant Card MUST NOT carry unknown
top-level properties.

### 4.1 Fields

| Field | Type | Req. | Meaning |
|-------|------|------|---------|
| `id` | DID (`^did:(key\|web):.+$`) | **MUST** | The Entity's DID and anchor (§5). |
| `entityType` | enum (§3.1) | **MUST** | The typed principal. |
| `name` | string (≥1) | **MUST** | Human-readable display name. |
| `kid` | string | MAY | Key identifier; matches a DID-document verification method and the JWS header `kid` of the Entity's proofs. |
| `publicKeyJwk` | Ed25519 OKP JWK `{kty:"OKP",crv:"Ed25519",x,kid?,use?}` | MAY | Inline public key. If present it MUST match the key published in the DID document. |
| `createdAt` | string (date-time) | MAY | Creation timestamp. |
| `capabilities` | array of (string \| `{name, attestations[≥1]}`) | MAY | Declared capabilities. A bare string is **L1**; an object with `attestations` is **L2** (§9). |
| `conformanceLevel` | enum `L1`\|`L2`\|`L3` | MAY | **DERIVED** summary. A Verifier MUST ignore this on input and RECOMPUTE it (§9, §11). |
| `responsibleParty` | DID | MAY | Root-accountable Entity (§2.2, §10.2). SHOULD be `did:web`. |
| `principal` | DID | MAY | Immediate human delegator, when distinct. |
| `delegationRef` | string | MAY | Locator for the signed delegation chain backing `responsibleParty`/`principal` (e.g. `vc_root>del_123`, hops joined by `>`); resolved, not inlined. |
| `attestations` | array of `{type: "IdentityVerification"\|"CapabilityAttestation", vc, subject?, issuer?}` | MAY | Resolvable, signed credentials about the Entity or its `responsibleParty` (e.g. KYC/KYB). |
| `didDocument` | string | MAY | URL of the DID document (for `did:web`, otherwise derivable, §5.3). |
| `proofProfile` | literal `"org.kya-os/proof@1"` | MAY | Names the per-request proof profile the Entity's requests carry (§8). The proof itself is NEVER on the Card. |
| `cimd` | `{clientId, jwksUri}` | MAY | CIMD on-ramp coordinates (§7). |
| `revocation` | `{statusListCredential, statusListIndex}` | MAY | W3C Bitstring Status List v1.0 entry for the Card's backing credential (§10.3). |

### 4.2 Claim-minimalism

A Card ASSERTS only identity + type + declared capabilities + accountability *locators*. Everything
trust-bearing - accountability (`responsibleParty` verified via `delegationRef`), attested
capabilities (L2), KYC/KYB (`attestations`) - MUST be PROVEN by referenced, signed credentials that
a Verifier resolves and checks, and MUST NOT be treated as true merely because the Card asserts it.
A Card builder MUST NOT set `conformanceLevel` on emit (`buildCard` / the fluent `card()` builder
omit it deliberately).

### 4.3 The proof is never on the Card

The per-request holder-of-key proof (§8) MUST NOT appear on any static Card or any discovery
projection (§6). It rides per-request `_meta` only. `proofProfile` merely NAMES the profile a
Verifier should expect; a stripped `proofProfile` MUST NOT be treated as a failure.

---

## 5. Anchoring (NORMATIVE)

### 5.1 DID methods

- **`did:web` is REQUIRED** for any Entity that is accountable or KYC/KYB-bearing. A `did:web`
  Entity is domain-anchored: its DID document is served from its own origin, and the Card gains
  the holder-of-key + Verifiable-Credential layer **on top of** DNS+TLS namespace trust.
- **`did:key` is permitted** for development / ephemeral Entities and for `human` principals. A
  `did:key` Card is self-asserted (identity + type + L1 capabilities + holder-of-key-on-use only);
  it has no domain anchor and therefore MUST NOT be resolved by discovery (it must be supplied
  directly, §6.5). An Entity MAY be `did:key` while its `responsibleParty` is `did:web` (an
  ephemeral agent accountable to a registered org).

### 5.2 did:web ADDS on top of DNS (explicit)

`did:web` does not replace DNS namespace trust; it **adds** two things DNS alone cannot give: (a) a
resolvable set of verification keys enabling holder-of-key proofs, and (b) Verifiable Credentials
that are offline-verifiable independent of a live fetch. The anchor's *resolution* still trusts
DNS+TLS and a domain takeover still compromises the anchor; §12.8 gives the residual risk and
hardening guidance.

### 5.3 The `KyaOsEntityCard` DID-document service

The Card's **canonical home** is a `service` entry on the Entity's `did:web` DID document:

```json
{ "id": "#kya-os-card", "type": "KyaOsEntityCard",
  "serviceEndpoint": "https://host/{path}/card.json" }
```

KYA-OS owns exactly one registered string: the service **type** `KyaOsEntityCard` (§14.4). W3C
deliberately decentralizes DID service types, so no central registration is required. The service
entry is the **canonical** card home. A bare `did:web:host` org root has no path segment to derive a
`card.json` from, so it additionally publishes at the well-known path
`/.well-known/kya-os-card.json` (§5.4) - origin-authenticated on the entity's own host, mirroring
did:web's own `/.well-known/did.json`.

### 5.4 URL derivation

For a path-form `did:web`, with percent-decoded segments `host:seg1:…:segN`:

- **DID document:** `did:web:host:a:b → https://host/a/b/did.json`; a bare `did:web:host →
  https://host/.well-known/did.json`.
- **Card:** `did:web:host:a:b → https://host/a/b/card.json`. A bare `did:web:host` has no path
  segment, so it derives the well-known card path `https://host/.well-known/kya-os-card.json`,
  mirroring the bare-host `.well-known/did.json` rule above. This is origin-authenticated (same host
  as the DID document, https-only) and lets org roots - including the default trusted issuer -
  publish via the shipped helpers. The `KyaOsEntityCard` service entry remains the canonical pointer
  and the two-step `did.json → service entry` resolve stays gated on it; the well-known path is the
  direct-derivation fallback, not a bypass of the service entry. A non-`did:web` DID (e.g.
  `did:key`) has no web home, so a direct card-URL derivation for it MUST fail closed.

---

## 6. Discovery Projections (NORMATIVE)

One canonical Card is PROJECTED onto four rails. Each projection is a pure, deterministic function
of one Card (no I/O, no crypto) and references the SAME canonical `card.json` endpoint (§5.3), so a
Verifier always lands back on one source of truth.

**Graceful-degradation contract (applies to every projection):** an unaware peer MUST be able to
ignore the KYA-OS projection without rejecting the underlying rail's document, and a *stripped*
KYA-OS projection MUST degrade to a fetch of the canonical `card.json` (or to "no KYA-OS layer"),
never to a hard failure.

### 6.1 MCP `server.json` / `catalog.json` `_meta["org.kya-os/card"]`

The value under the reverse-DNS key `org.kya-os/card` is EITHER an inline **claim-minimal summary**:

```json
{ "org.kya-os/card": { "id": "did:web:…", "entityType": "agent", "name": "…",
  "capabilities": ["…"], "responsibleParty": "did:web:…", "proofProfile": "org.kya-os/proof@1" } }
```

OR a lazy-fetch reference `{ "org.kya-os/card": { "org.kya-os/cardRef": "<https card.json>" } }`.
A Verifier that finds an inline summary MUST be able to parse it with no fetch; a `cardRef` is
fetched (via §6.6 SafeFetch). The `org.kya-os` reverse-DNS label sits outside the reserved
`modelcontextprotocol/mcp` `_meta` namespace (§14.1); if a registry strips it, the projection
degrades to a fetch of the canonical card, not a failure.

### 6.2 A2A `AgentExtension`

Projected only for `entityType: "agent"` (the sole A2A principal); projecting any other type MUST
fail closed. The entry occupies `AgentCard.capabilities.extensions[]`:

```json
{ "uri": "https://kya-os.org/a2a/ext/entity-card/v1",
  "description": "KYA-OS typed DID-anchored holder-of-key identity",
  "required": false,
  "params": { "id": "did:web:…", "entityType": "agent",
    "cardUrl": "https://host/{path}/card.json", "proofProfile": "org.kya-os/proof@1" } }
```

The extension version is pinned **in the URI**. `required: false` (the default) IS the
graceful-degradation contract: an unaware A2A peer ignores the extension rather than rejecting the
AgentCard. The extension is activated by the `A2A-Extensions` request/response header.

### 6.3 NANDA `AgentFacts`

KYA-OS POPULATES NANDA's shipped `owner` slot from `responsibleParty` (it does not re-claim it);
the uniquely-KYA-OS axes live under a `kya:` JSON-LD `@context`:

```json
{ "@context": { "kya": "https://kya-os.org/ns/agentfacts/v1#" },
  "id": "did:web:…", "agent_name": "…", "kya:entityType": "agent",
  "owner": "did:web:…", "capabilities": ["…"],
  "kya:conformanceLevel": "L2", "kya:proofProfile": "org.kya-os/proof@1",
  "kya:delegationRef": "vc_root>del_123" }
```

Optional fields are omitted when absent (claim-minimalism; deterministic output). Unknown JSON-LD
keys MUST be preserved by conforming NANDA consumers, which is the graceful-degradation contract on
this rail.

### 6.4 MCP `catalog.json` index entry

A catalog index row is always **by-ref** (the index stays cheap; the card lazy-fetches):

```json
{ "name": "…", "_meta": { "org.kya-os/card": { "org.kya-os/cardRef": "<https card.json>" } } }
```

### 6.5 Resolution

A Verifier resolves a Card from any of: a bare `did:web` or `{ did }` (two-step: `did.json` →
`KyaOsEntityCard` service → `card.json`); `{ cardUrl }`; `{ serverMeta }` (inline summary parses
with no fetch, a `cardRef` is fetched); `{ a2a }` (follow `params.cardUrl`); or `{ agentFacts }`
(two-step from the AgentFacts `id`). Every outbound fetch MUST go through the SafeFetch seam
(§6.6). A `did:key` Card MUST NOT be resolved (no anchor); it is supplied directly.

### 6.6 SafeFetch (SSRF hardening, MANDATORY)

Because resolution follows attacker-influenced URLs across four surfaces, every outbound fetch
(card, DID document, JWKS, status list) MUST be routed through an SSRF-hardened fetch that enforces,
fail-closed: **https-only**; **public-unicast only** - RFC1918, loopback (`127/8`, `::1`),
link-local (`169.254/16` incl. the `169.254.169.254` cloud-metadata endpoint, `fe80::/10`), CGNAT
`100.64/10`, IPv6 ULA `fc00::/7` (incl. `fd00::/8`), multicast, and other non-public ranges are
denied; **resolve-once-and-pin** the connection IP (closing the DNS-rebinding TOCTOU window);
**no cross-origin redirects** (same-origin only, bounded count); and a **response-size cap** and
**timeout**. The reference implementation (`src/utils/safe-fetch.ts`) defaults to a 1 MiB cap, a
5 s timeout, and ≤3 same-origin redirects.

---

## 7. CIMD On-Ramp (NORMATIVE) [TAAWG-NORMATIVE]

CIMD (draft-ietf-oauth-client-id-metadata-document; MCP default since the 2025-11-25 spec;
**verified-at 2026-06-30**) is the L1 on-ramp with zero new infrastructure: the OAuth `client_id`
IS the Entity's `did:web` in HTTPS form, and the `jwks_uri` the authorization server (AS) validates
`private_key_jwt` against IS a mechanical projection of the DID document's keys. OAuth
client-authentication therefore *is* a DID-key proof. This binding - `client_id → did:web →
mandate-VC` - is the second of the two TAAWG-normative primitives.

### 7.1 `client_id ⇄ did:web` bijection

```
did:web:host:a:b      ⇄  https://host/a/b
did:web:host%3A3000:a ⇄  https://host:3000/a       (authority colon percent-encoded for ports)
did:web:host          ⇄  https://host
```

`bindClientId(did)` and `didFromClientId(clientId)` are inverse functions; `didFromClientId` is
https-only and fails closed on a non-https or malformed `client_id`.

### 7.2 `jwks_uri ⇄ DID keys`

`jwks_uri` MUST serve a JWKS that is a mechanical projection of the DID document's
`verificationMethod[]`: each Ed25519 (`OKP`) method becomes an `OKP` public JWK with its `kid`
preserved (the JWK's own `kid`, else the verification-method `id`) and any private `d` stripped;
non-Ed25519 methods are skipped. Because the AS validates `private_key_jwt` against this JWKS,
validating the client assertion verifies a **DID-key signature**.

### 7.3 The CIMD document

The document served at the `client_id` URL is projected from the Card:

```json
{ "client_id": "https://host/{path}",
  "client_name": "<card.name>",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://host/{path}/jwks.json",
  "_meta": { "org.kya-os/did": "did:web:…" } }
```

A pure-CIMD client with no declared DID still onboards: its `did:web` is minted from `client_id`
(`cardFromClientMetadata` yields an L1 `entityType: "client"` Card). A `did:key` client is L1-only -
it cannot bind a `did:web` origin and never reaches L2.

### 7.4 Anti-substitution bind (fail-closed)

Before trusting a CIMD binding, a Verifier MUST enforce, fail-closed (`verifyCimdBind`):

1. **origin-equality** - `did:web` host origin === `client_id` origin === `jwks_uri` origin (a
   hostile CIMD pointing `jwks_uri` at another origin's keys fails here); and
2. a **reciprocal `alsoKnownAs` bind** - the DID document's `alsoKnownAs` MUST list the `client_id`
   URL, so a CIMD cannot unilaterally claim a DID it does not control.

### 7.5 `cnf.jkt` sender-constraint

The AS SHOULD mint the access token sender-constrained per RFC 9449 [RFC9449], with `cnf.jkt` set to
the RFC 7638 thumbprint of the key that authenticated the `private_key_jwt`. That thumbprint is the
exact sender-constraint the per-request proof carries (§8.6), closing L1 → L3. Where the AS does not
emit `cnf`, verification degrades to **L3-minus** (§8.6, §9.4) rather than failing.

---

## 8. Per-Request Holder-of-Key Proof (NORMATIVE) [TAAWG-NORMATIVE]

`org.kya-os/proof@1` is a **self-contained**, **sender-constrained**, fail-closed proof that rides
its own `_meta["org.kya-os/proof@1"]` key. There is no session establishment and no handshake;
every request carries its own proof.

A note on the word "stateless", which earlier drafts used for this profile: the proof *object* is
stateless (it references no session and no prior request, and the minter keeps nothing between
requests), but the verification *protocol* is not. Replay prevention requires the Verifier to keep
a nonce store (§11.2 step 8, §12.2), and a Verifier without one MUST fail closed
(`nonce_seam_missing`) rather than skip the check. Where this document says "stateless" it means
stateless proof construction, never stateless verification.

### 8.1 Two proof eras, one key each (coexistence)

Two orthogonal proof profiles may appear on one server, each under its OWN `_meta` key: the
**legacy session-bound** `ProofMeta` (carrying `sessionId` + a handshake nonce; retained untouched
for 1.x back-compat) under `_meta["org.kya-os/proof"]`, and the **self-contained** `org.kya-os/proof@1`
specified here under `_meta["org.kya-os/proof@1"]` - the key equals the profile id, so it is
self-describing and versioned. Distinct keys let both regimes coexist without either guard seeing -
or rejecting - the other's proof (a shared key made them mutually exclusive: a legacy proof failed
the card schema and a card proof failed the legacy structure check). A Verifier reads the key for
the profile it implements; the object still carries `prf` as a self-describing discriminator. This
document specifies only `org.kya-os/proof@1`.

### 8.2 Object

```jsonc
{
  "prf": "org.kya-os/proof@1",           // profile discriminator (literal)
  "alg": "EdDSA",                         // "EdDSA" (Ed25519) | "ES256" (P-256) - allow-list, no negotiation
  "did": "did:web:…",                     // caller DID (the accountable principal)
  "kid": "did:web:…#key-1",               // signing key id; kid.split('#')[0] MUST == did
  "audience": "did:web:…",                // recipient DID (from its Card) - anti-relay
  "nonce": "<128-bit, client-random or server-issued>",
  "created": 1782820800,                  // epoch seconds
  "expires": 1782820860,                  // epoch seconds; expires-created ≤ 60
  "requestHash": "sha-256=:<b64>:",       // §8.3
  "cnf": { "jkt": "<RFC 7638 thumbprint>" },  // OPTIONAL - §8.6
  "jws": "<detached JWS (EdDSA|ES256): protected..signature>",  // §8.4
  "httpSig": "<raw sig base64url (ed25519 | ecdsa-p256-sha256)>" // OPTIONAL - §8.5 dual carrier
}
```

Lifetime: `expires > created`, and `expires - created` MUST NOT exceed **60 seconds**
(`MAX_TTL_SEC`; default 60). Freshness is checked with a default clock skew of **±5 seconds**
(`DEFAULT_SKEW_SEC`).

### 8.3 Request binding (`requestHash`, RFC 8785 + RFC 9421)

`requestHash` binds the proof to THIS request body.

**Pre-signing transformation (exact).** The covered request is derived from the JSON-RPC call, and
the minter and the Verifier MUST apply the same derivation:

1. Start from the call's `{ method, params }`.
2. Remove the `_meta` member of `params`, if present. `_meta` is the transport-metadata carrier:
   it carries this proof itself (§8.2), and hosts may add their own members to it (MCP's
   `progressToken`, for example), so it can never be part of the signed material. Nothing else is
   removed, and values nested below the other `params` members are not touched.
3. When `params` is absent, the covered request is `{ method }` (the `params` key is omitted, not
   set to `null`).

The hash is then computed over the covered request:

```
requestHash = "sha-256=:" || base64( SHA-256( JCS(coveredRequest) ) ) || ":"
```

where `JCS` is RFC 8785 [RFC8785] JSON Canonicalization. The result is emitted in the RFC 9421
[RFC9421] Content-Digest structured-field form `sha-256=:<base64>:` so the HTTP Message Signature
sibling (§8.5) can carry it verbatim.

Step 2 is what makes the definition non-circular: the proof rides `params._meta`, so a Verifier
that hashed the received `params` verbatim would be hashing a structure that contains the proof,
and the result could never equal the hash the minter signed (the minter signs before the proof
exists). A Verifier recomputes this exact derivation over the request it received (§11.2 step 6).
The same canonicalizer and request shape are used by the legacy hasher, so a proof minted here
recomputes stably cross-implementation (proven by Appendix C).

### 8.4 Detached JWS carrier (canonical)

The **covered claims** are every proof field EXCEPT the two signatures (`jws`, `httpSig`), i.e.
`{prf, alg, did, kid, audience, nonce, created, expires, requestHash}` plus `cnf` when present. The
detached JWS signs the RFC 8785 (JCS) canonical bytes of the covered claims with the proof's
algorithm, serialized detached: `<protected>..<signature>` (empty payload segment).

The signing algorithm is an ALLOW-LIST of exactly two - `EdDSA` (Ed25519) and `ES256` (ECDSA
P-256, FIPS-eligible) - never negotiated. On verification: the (schema-validated, itself
covered/signed) `alg` MUST be one of the two; the resolved key type MUST match it (an `ES256` proof
MUST carry a P-256 key, an `EdDSA` proof an Ed25519 key, else `alg_key_mismatch`); the JWS protected
header's `alg` MUST equal the proof `alg` and its `kid` the proof `kid`; and verification is PINNED to
that single `alg`. The payload is RECOMPUTED from the covered claims (JCS), so any tampered covered
field (including `alg`) yields a different signing input and fails.

### 8.5 RFC 9421 HTTP Message Signature sibling (dual carrier)

The proof MAY additionally carry `httpSig`: a **RAW EdDSA or ES256 signature** (base64url, NOT
JWS-framed, matching `alg`) made by the SAME DID key over the RFC 9421 signature base. Because a JWS signature also covers its
protected header, its bytes can never satisfy a stock RFC 9421 verifier reconstructing a bare
signature base - the two carriers therefore require two signatures over one semantic set. The
signature base is deterministic and self-contained from the proof:

```
"content-digest": sha-256=:<b64>:
"kya-audience": <audience>
"kya-nonce": <nonce>
"kya-cnf": <cnf.jkt>                       ← only when cnf is present
"@signature-params": ("content-digest" "kya-audience" "kya-nonce" ["kya-cnf"]);created=…;expires=…;keyid="<kid>";alg="ed25519"
```

where `alg` follows RFC 9421 naming for the proof's `alg`: `ed25519` for an EdDSA proof,
`ecdsa-p256-sha256` for an ES256 proof. Projected under the label `kyaos`. A stock RFC 9421 verifier (SEP-1960, Cloudflare Web Bot Auth)
reconstructs this base and verifies `httpSig` against the resolved DID key with zero new code. A
signer without a raw-signature seam mints a JWS-only proof and the sibling simply degrades away
(never a failure).

### 8.6 `cnf.jkt` fusion (RFC 9449 + RFC 7638) - the spine

`cnf.jkt`, when present, MUST equal the RFC 7638 thumbprint of the signing key. When the AS supplies
a token `cnf.jkt` (§7.5), the three MUST fuse:

```
token.cnf.jkt  ===  proof.cnf.jkt  ===  thumbprint( resolve(kid) )
```

for **L3**. If the AS supplies no token `cnf`, verification degrades to **L3-minus** (still bound by
request + audience + nonce + key). If the AS supplies a token `cnf` but the proof carries none, that
is a downgrade attempt and MUST fail closed (`cnf_required_by_token`, §11.2, §12.7). One DID key thus
threads L1 token possession (§7) to L3 per-request proof-of-possession: **a stolen bearer token is
inert without live possession of the DID key.**

Where a proof DOES carry a `cnf` but the verifier is given no token `cnf.jkt` to fuse it against, the
degradation to L3-minus is legitimate but easy to cause by misconfiguration (a verifier that simply
never extracted the token's `cnf`). A verifier SHOULD therefore emit a **non-fatal** diagnostic -
`cnf_present_but_token_unfused` - in that case. It does not affect validity (the proof is a sound
L3-minus proof) and is distinct from the fail-closed `reasons`; its only purpose is to let an
integrator who intended L3 observe the downgrade rather than have it pass silently.

### 8.7 Bindings summary

| Binding | Defends against |
|---------|-----------------|
| `requestHash` → THIS body (JCS) | request tampering |
| `audience` → THIS recipient | relay / confused-deputy (§12.3) |
| `nonce` + `created`/`expires` → NOW | replay (§12.2) |
| `kid` → a DID verification method (and `kid.split('#')[0] === did`) | forged principal (§11.2, §12.1) |
| `cnf.jkt` fusion | session-carry / stolen bearer token (§12.4) |

### 8.8 Relationship to RFC 9449 (DPoP)

`org.kya-os/proof@1` is a per-request proof-of-possession mechanism and it deliberately overlaps with
DPoP [RFC9449]: both bind a fresh, short-lived proof to every request, both carry a nonce and a
validity window, and both express the sender-constraint as an RFC 7638 [RFC7638] `cnf.jkt` thumbprint.
This profile does **not** aim to replace DPoP. Where an authorization server issues DPoP-sender-
constrained tokens, the two **compose** (see *Composition* below). This section records the specific
points where the binding differs, and why, so that the mechanisms are not conflated.

- **Request binding.** DPoP binds the HTTP method and target URI (`htm`/`htu`). An MCP tool call is a
  JSON-RPC message, and under the Streamable HTTP transport such calls are typically `POST`ed to a
  single `/mcp` endpoint - so `htm`/`htu` are identical across every call and distinguish no
  operation; under the stdio transport there is no HTTP envelope to bind at all. The profile therefore
  binds the JSON-RPC operation directly - `requestHash` over the JCS of the covered request
  (§8.3) - which is the invariant that actually identifies the request across both transports.
- **Carrier.** DPoP travels as an HTTP header. This proof travels in the request's `_meta` (§8.2),
  in-band with the JSON-RPC message, so it is transport-agnostic - the same proof verifies over stdio
  and over Streamable HTTP. For deployments that terminate at an HTTP edge, §8.5 defines an OPTIONAL
  RFC 9421 [RFC9421] HTTP Message Signature sibling over the same covered claims, so a
  message-signature-aware intermediary can additionally check the proof at that layer.
- **Key-to-principal anchoring.** A DPoP proof carries its public key inline (the JWT header `jwk`),
  and the sender-constraint is that the token was issued bound to that key. This proof additionally
  requires the signing key to be a verification method published by the caller's DID document
  (`kid.split('#')[0] === did` plus RFC 7638 thumbprint membership, §8.4, §11.2), so possession is
  bound not only to a token but to a discoverable, accountable **principal** (the Entity's Card DID) -
  the identity axis DPoP does not itself address.
- **Audience.** The proof binds a recipient `audience` DID (§8.4) - the intended recipient Entity -
  closing relay / confused-deputy at the level of a principal's identity, which DPoP's `htu` (a URI)
  does not express.
- **Composition (§7.5, §8.6).** Where the authorization server does issue a DPoP-sender-constrained
  access token, its `cnf.jkt` is fused with the proof's `cnf.jkt` and the resolved DID key to reach
  **L3**: one key threads token possession and per-request possession. DPoP then operates at the token
  layer and this proof at the per-request JSON-RPC layer - complementary, not competing. Absent an AS
  `cnf`, the proof degrades to L3-minus (§8.6); it never requires DPoP and never conflicts with it.

For a conventional HTTP resource server, DPoP remains the appropriate mechanism. This profile targets
the MCP/JSON-RPC transport and the DID-anchored, typed-identity model, and reuses DPoP's
sender-constraint semantics wherever they are present.

---

## 9. Capabilities & Conformance Ladder (NORMATIVE)

Each rung is a named standard a Verifier independently RECOMPUTES; the Card's self-declared
`conformanceLevel` is NEVER trusted (recompute-on-verify). `L3 ⊇ L2 ⊇ L1`.

### 9.1 L1 - key possession

Evidence: a resolvable CIMD document whose `client_id` is the Card's `did:web` HTTPS form, a
`jwks_uri` resolving to DID keys, and a validated `private_key_jwt` (§7) - or a `did:key`
self-asserted Card. Capabilities are bare strings.

### 9.2 L2 - DID + VC, offline-verifiable

Evidence: a `did:web` anchor with a `KyaOsEntityCard` service on the DID document; every declared
capability backed by a trusted-issuer `CapabilityAttestationCredential`
(`credentialSubject.id === card.id`, capability name matches, `validUntil` in the future, not
revoked per a cached Bitstring Status List, §10.3); OPTIONALLY a KYC/KYB
`IdentityVerificationCredential` on the `responsibleParty` (§10.4).

Delegation-chain resolution (the attenuation invariants, `responsibleParty === issuer(rootVC)`, §10.2) is
NOT level evidence. When the Card carries a `responsibleParty`, chain resolution is a fail-closed
GATE on the `ok` verdict (§11.1 step 6): an unresolved chain sets `ok: false` and the Card is
rejected outright, but the derived level is computed by the §9.4 algorithm from the capability
floor, proof floor, and revocation freshness alone - never from accountability. A conforming
implementation MUST derive the level per §9.4 / §11.1 step 7, not from this prose.

### 9.3 L3 - live per-request proof-of-possession

Evidence: L2 **plus** a valid sender-constrained `org.kya-os/proof@1` (§8) - `audience` === self,
nonce fresh, `requestHash` recomputes, and the `cnf.jkt` fusion when the AS supplies a token `cnf`
(this is the proof floor that lifts the level to L3) - **plus** a LIVE Bitstring Status List
freshness check on the leaf delegation/capability credentials. The leaf-invoker === `proof.did`
join (§10.2), like delegation-chain resolution in §9.2, is a fail-closed GATE on `ok` (§11.1 step
6), not level evidence; the level is derived per §9.4 / §11.1 step 7.

### 9.4 Derivation algorithm

`deriveConformanceLevel(check, proofFloor, revocationFresh)` returns the monotone floor:

```
allAttested = check.verified.length > 0  AND  check.unverified.length === 0
if not allAttested:                 return L1
if proofFloor.ok AND revocationFresh: return L3
                                     return L2
```

`revocationFresh` defaults to `true` (so an unchecked card is not spuriously demoted and legacy
2-argument calls still compile). Fail-closed demotion is the invariant: a missing/expired/revoked
artifact DEMOTES the level (L3→L2→L1) and never errors open; an unreachable or stale status list
demotes L3→L2; a *revoked* Card credential collapses every attested capability to unverified so the
floor becomes L1 (§11.3). L3-minus (§8.6) satisfies the proof floor for the L3 rung; a caller policy
decides whether L3-minus vs L3 gates a given action.

### 9.5 Trusted issuers

The default trusted-issuer allowlist is `["did:web:example.com"]` (`DEFAULT_TRUSTED_ISSUERS`) and is
caller-overridable. A capability/attestation whose issuer is not on the allowlist is treated as
unverified.

---

## 10. Delegation & Accountability (NORMATIVE)

The Card asserts none of this; it carries locators (`responsibleParty`, `principal`,
`delegationRef`, `revocation`) that a Verifier resolves and recomputes. The delegation profile
itself - the `DelegationCredential` shape (a W3C VC 2.0 whose `credentialSubject` is an attenuated
ZCAP-LD capability), the delegate rules, and the attenuation invariants every hop must
satisfy - is specified in the core protocol's delegation chapter (SPEC.md §6.10, alongside the
legacy shape it succeeds). The rest of that chapter and the core delegation rules, including the
per-hop `audience` constraint on re-delegation (SPEC.md §11.6), apply unchanged. This section
keeps only what Card verification consumes directly.

### 10.1 The delegation profile, by reference

One `DelegationCredential` per delegation hop; a chain runs `root → … → leaf`, each hop's delegate
being the next hop's issuer, under the `https://kya-os.org/ns/delegation/v1` JSON-LD context. A
chain is valid only if every hop attenuates its parent (actions, caveats, validity) and preserves
continuity and a constant `invocationTarget`; any broadening hop invalidates the whole chain.
Shape, fields, worked example, and the full invariant list: SPEC.md §6.10.

### 10.2 The join - recomputed, asserted nowhere

Two equalities gate accountability and are RECOMPUTED (never trusted on the Card):

```
responsibleParty  ===  issuer( rootVC )         // the ultimately-accountable root
leafInvoker       ===  proof.did                // you can only invoke what was delegated to YOUR key
```

The `leafInvoker === proof.did` join ties the delegation chain (§10) to the live per-request proof
(§8): the accountability verifier is threaded the verified `proof.did` and asserts it equals the
leaf delegate.

### 10.3 Revocation

The Card's `revocation` field is a W3C Bitstring Status List v1.0 [BITSTRING-STATUS-LIST] entry
(`statusListCredential`, `statusListIndex`) for the Card's backing credential. Checks are
fail-closed (an unreachable or malformed list reads as revoked) and report freshness; L2 accepts a
cached non-revoked verdict, L3 requires a live one (§9). The chain walk is cascading: a revoked
ancestor invalidates the subtree. Mechanics, the `RevocationChecker` seam, and the fail-closed
rules: SPEC.md §6.10.

### 10.4 KYC/KYB

KYC/KYB rides the same rail as an `IdentityVerificationCredential` on the `responsibleParty`,
asserting the verification fact and level, never raw PII, surfaced through the Card's
`attestations[]`. Shape: SPEC.md §6.10.

---

## 11. Verification Algorithm (NORMATIVE, fail-closed)

A Verifier MUST recompute in the exact order below and reject on the first broken binding. Fail-closed
is the invariant throughout: a rejected/throwing seam DEMOTES the level (or fails the check) rather
than erroring open.

### 11.1 Card verification (`verifyCard`)

1. **Capabilities** - run the capability verifier over `card.capabilities` for `subjectDid =
   card.id`; with no verifier injected, all capabilities are floored to *unverified* (L1).
2. **Live proof** - if a proof + request + proof-verifier are supplied, RECOMPUTE the proof (§11.2);
   a throwing verifier yields `{ ok: false, reasons: ["proof_verifier_threw"] }` (a demotion, not an
   escape). Let `proofDid = proof.ok ? proof.did : undefined`.
3. **Accountability** - if `card.responsibleParty` is present, run the accountability verifier with
   `{ trustedIssuers, proofDid }` (threading `proofDid` for the §10.2 leaf-invoker join).
4. **Attestations** - recompute each `card.attestations[]` via the attestation verifier.
5. **Card revocation** - if a status-list checker is supplied and the Card declares `revocation`,
   live-check it; unreachable ⇒ `{ revoked: true, fresh: false }` (fail-closed).
6. **`ok`** = `accountabilityOk AND attestationsOk AND NOT revocation.revoked`, where
   `accountabilityOk = (no responsibleParty) OR accountability.verified` and `attestationsOk` is the
   conjunction over present attestations. A per-request proof affects the LEVEL, not `ok`; a revoked
   Card credential fails closed (`ok: false`).
7. **Level** = `deriveConformanceLevel(demoteOnRevocation(check, revoked), proofFloor,
   !revocation.checked OR revocation.fresh)` (§9.4). A revoked Card credential collapses `check` to
   all-unverified before derivation.

### 11.2 Proof verification (`verifyCardProof`), exact order

1. Schema-parse the proof; on failure return `["malformed_proof"]`.
2. `kid.split('#')[0] === did`, else `kid_did_mismatch`.
3. Resolve the signing key for `kid`; a throw records `key_unresolvable`.
4. **DID membership (secure by default)** - if a `resolveDidKeys` seam is present, the resolved key's
   RFC 7638 thumbprint MUST be among the DID document's published keys, else `kid_not_in_did_document`
   (a throw records `did_keys_unresolvable`). If the seam is ABSENT there is no independent membership
   proof, so a verifier MUST fail closed with `did_membership_unverifiable` UNLESS it explicitly attests
   its `resolveKey` is authoritative (`trustResolveKeyAuthority`), in which case binding rests on step 2
   plus that contract. A conformant production verifier SHOULD supply `resolveDidKeys`.
5. `audience === expectedAudience`, else `audience_mismatch`.
6. `requestHash === recompute(request)` after the §8.3 pre-signing transformation (strip
   `params._meta` before canonicalizing), else `request_hash_mismatch`.
7. **Window** - `expires > created` (`invalid_window`); `expires - created ≤ 60` (`ttl_too_long`);
   `created ≤ now + skew` (`created_in_future`); `expires ≥ now - skew` (`expired`).
8. **Replay** - `nonce` unseen for `did`, else `nonce_replayed`. If the `consumeNonceIfFresh` seam
   is ABSENT there is no replay defense to run, so a verifier MUST fail closed with
   `nonce_seam_missing` rather than skip the check (mirrors step 4's seam-absent posture).
9. Detached JWS verifies over the recomputed covered claims (§8.4), else `invalid_signature`.
10. **`cnf` fusion** (§8.6) → level: a present `cnf.jkt ≠` key thumbprint ⇒ `cnf_key_mismatch`; no
    token `cnf` ⇒ `L3-minus`; token `cnf` but no proof `cnf` ⇒ `cnf_required_by_token`; `cnf.jkt ≠
    token cnf` ⇒ `cnf_token_mismatch`; all fuse ⇒ `L3`.

`ok` is true iff there are no reasons; on success the result carries the derived assurance
(`L3` / `L3-minus`) and the accountable `did`.

### 11.3 Fail-closed demotion matrix

| Condition | Effect |
|-----------|--------|
| No capability verifier / any unverified capability | floor L1 |
| All capabilities attested, no valid live proof | L2 |
| All attested + valid live proof + fresh revocation | L3 (or L3-minus without AS `cnf`) |
| Stale (readable, past validity window) status list | L3 → L2 (`revocationFresh = false`; `revoked: false`, so `ok` unaffected) |
| Unreachable / non-2xx / malformed / wrong-purpose / out-of-range status list | `{ revoked: true, fresh: false }` (fail-closed) ⇒ collapse to L1, `ok: false` |
| Revoked Card / delegation credential | collapse to L1, `ok: false` |
| Proof verifier throws | proof floor `{ ok: false }` (demotion) |

---

## 12. Security Considerations

### 12.0 Trust model

Verification work is distributed across boundaries. **The Entity process** holds its own Ed25519
secret key; compromise there compromises every chain it can sign under (mitigations are platform
key-custody choices: software, proxy-managed, or TEE-bound). **The Verifier** is in the trusted
computing base for any resource it gates when it verifies at the edge (L1); moving verification into
the resource boundary (L2+) shrinks that TCB. **The resource owner** decides accepted scopes and
trusted issuers; the cryptographic checks (delegation, proof) are load-bearing while the registry is
a friction signal. Services SHOULD be addressable by a DID and mutually authenticated before
sensitive payloads flow.

### 12.1 Impersonation (forged principal)

A process claims to be an Entity it is not. Mitigation: the per-request proof's `kid` MUST resolve to
a verification method of `proof.did` (`kid.split('#')[0] === did` PLUS, with `resolveDidKeys`, RFC
7638 thumbprint membership in the DID document, §11.2 steps 2/4). This closes the "claim a victim
`did` while `kid` points elsewhere" gap. Residual: compromise of the Entity's secret key, or of an
L1 edge Verifier.

### 12.2 Replay

Capturing a valid signed request and re-sending it. Mitigation: `nonce` freshness scoped to `did`,
`created`/`expires` bounded to ≤60 s with ±5 s skew (§8.2, §11.2 steps 7–8). A server-issued
single-use nonce is the strong policy; a client-random nonce with a short window is the default.
Under either policy the Verifier keeps a nonce store and consumes from it atomically - replay
prevention is stateful even though the proof is self-contained (§8). Residual: a race inside
the nonce window; distributed deployments MUST use atomic check-and-set on the nonce cache.

### 12.3 Confused deputy / relay

A proof or delegation is repurposed against a recipient the delegator did not intend. Mitigations:
`audience` binds a proof to THIS recipient DID (§8.4); the designation/continuity invariants
bind a delegation to a specific resource and delegate, and the verifying resource asserts
itself as the expected `invocationTarget` (SPEC.md §6.10); the `leafInvoker === proof.did` join
(§10.2) prevents a delegation to key A being exercised by key B. For re-delegated credentials, the
core protocol's per-hop `audience` constraint (SPEC.md §11.6) applies unchanged alongside this
profile.

### 12.4 Session-carry / stolen bearer token

A bearer token captured in transit or from a log is replayed by an attacker. Mitigation: the
`cnf.jkt` fusion (§8.6) sender-constrains the token to the DID key; a Verifier asserts `token.cnf.jkt
=== proof.cnf.jkt === thumbprint(resolve(kid))`, so the token is **inert without live possession of
the DID key**. Residual where the AS does not emit RFC 9449 `cnf`: L3-minus (still request-,
audience-, nonce-, and key-bound).

### 12.5 Key compromise

An Entity's secret key is exfiltrated. Mitigations: short-lived proofs and delegations; explicit
revocation (§10.3); key rotation via DID-document update (old keys SHOULD remain for historical proof
verification; reissue delegations bound to specific `kid`s). Residual: the window between compromise
and detection/revocation.

### 12.6 Revocation freshness

An invocation arrives while a revocation propagates (a Lamport-concurrent race). Mitigations: L3
requires a LIVE, in-window status check (§10.3); status-list cache TTL SHOULD be short (≤60 s) for
high-privilege scopes; cascading revocation is atomic over the subtree; expiry is the primary
revocation mechanism. Residual: the unavoidable race window operators bound but cannot eliminate.

**`did:key` revocation limitation.** A `did:key` Entity has no domain-anchored authoritative Card to
dereference, so an inline `_meta` discovery summary is parsed as presented (a `did:web` summary, by
contrast, is always dereferenced from its origin-served `card.json`, §6.5). A discovery intermediary
that strips the `revocation` pointer from an *unsigned* `did:key` summary can therefore make a
revoked-but-key-holding `did:key` Entity verify `ok:true`. This is inherent to the self-asserted
`did:key` tier: **`did:web` is REQUIRED (§5) for any Entity that MUST be revocable or accountable** -
its `card.json` cannot be tampered without controlling the origin. `did:key` remains dev/ephemeral and
self-asserted; operators needing revocable ephemeral identities SHOULD integrity-bind the `did:key`
discovery channel (a signed summary) or use `did:web`. In the embedded model (an Entity serves its own
`_meta`) this is identical to omitting `revocation` from a `did:web` `card.json`.

### 12.7 Downgrade

A client strips the KYA-OS layer, or an intermediary strips the proof `cnf` while keeping a token
`cnf`. Mitigations: **fail-closed** servers requiring identity MUST reject unproven calls; a token
`cnf` with no proof `cnf` MUST fail (`cnf_required_by_token`, §8.6); discovery projections advertise
`proofProfile` so a Verifier knows a proof is expected. Residual: a non-compliant client the operator
has not configured to require identity.

### 12.8 did:web DNS trust

`did:web` resolution trusts DNS+TLS; a domain takeover can silently forge the anchor (§5.2).
Mitigations/guidance: operators SHOULD deploy DNSSEC and CAA; a registry MAY publish an offline
key-pin (a "tier 1.5" out-of-band anchor) so a takeover does not silently re-key; the reciprocal
CIMD `alsoKnownAs` bind (§7.4) raises the bar on substitution. Residual: without an out-of-band pin,
anchor authenticity is bounded by DNS+TLS.

### 12.9 SSRF via attacker-influenced resolution

Resolution follows URLs from four discovery surfaces plus JWKS and status lists. Mitigation:
**MANDATORY** SafeFetch (§6.6) - https-only, public-unicast-only with the cloud-metadata endpoint
`169.254.169.254` explicitly denied, resolve-once-and-pin against DNS rebinding, no cross-origin
redirects, size/time caps. Residual: standard transport-layer DoS is out of scope.

### 12.10 Threat model summary

| Threat | Mitigation (§) | Residual |
|--------|----------------|----------|
| Impersonation | `kid`↔`did` binding + DID membership (§12.1) | key/edge-Verifier compromise |
| Replay | nonce + bounded window (§12.2) | nonce-window race |
| Confused deputy / relay | `audience` + attenuation invariants + leaf-invoker join (§12.3) | check-implementation bugs |
| Session-carry | `cnf.jkt` fusion (§12.4) | L3-minus where AS omits `cnf` |
| Key compromise | short TTL + revocation + rotation (§12.5) | compromise→detection window |
| Revocation race | live status + short TTL + cascading (§12.6) | Lamport-concurrent race |
| Downgrade | fail-closed + `cnf_required_by_token` (§12.7) | unconfigured non-compliant client |
| did:web DNS | DNSSEC/CAA + key-pin + `alsoKnownAs` (§12.8) | DNS+TLS trust floor |
| SSRF | mandatory SafeFetch (§12.9) | transport-layer DoS |
| did:key revocation via unauthenticated discovery | `did:web` REQUIRED for revocable Entities (§12.6) | `did:key` is self-asserted, non-revocable through unauthenticated discovery |

---

## 13. Privacy Considerations

- **Claim-minimalism (§4.2).** The Card asserts only identity + type + declared capabilities +
  accountability locators. Trust-bearing claims are referenced credentials, resolved on demand.
- **PII off-card.** KYC/KYB is asserted as a fact + level (`basic | enhanced | loa3`), never raw PII;
  DUNS/legal-name/etc. stay in the registry, off the Card and off every projection (§10.4).
- **Selective disclosure (forward seam).** The delegation/attestation rail is VC 2.0, so
  selective-disclosure / BBS unlinkable proofs are a forward-compatible upgrade path; a Verifier
  that receives an SD credential MUST NOT require full disclosure where a predicate proof suffices.
- **DID correlation.** A persistent `did:web`/`did:key` is a pseudonym; reuse across recipients
  enables cross-recipient correlation. Privacy-sensitive Entities SHOULD consider per-recipient DID
  rotation.
- **Per-delegation keys.** A delegate MAY present a fresh single-purpose key per delegation it
  receives (the delegator issues the ZCAP to that one-off key), keeping activity unlinkable across
  delegations.
- **Proof retention.** Proofs are audit records containing DIDs; operators retaining proof logs
  SHOULD apply data-protection retention policies (e.g. GDPR Art. 17, CCPA) and avoid co-logging
  DIDs with PII.

---

## 14. IANA & Registry Considerations

### 14.1 Reverse-DNS `_meta` keys (`org.kya-os/*`)

| Key | Carries | Section |
|-----|---------|---------|
| `org.kya-os/card` | inline Card summary or a `cardRef` on MCP `server.json`/`catalog.json` | §6.1 |
| `org.kya-os/cardRef` | a lazy-fetch `card.json` URL (inside `org.kya-os/card`) | §6.1 |
| `org.kya-os/proof@1` | the self-contained per-request holder-of-key proof (§8); the key equals the profile id | §8 |
| `org.kya-os/proof` | the legacy session-bound proof (`ProofMeta`); a distinct key, so the two coexist | §8.1 |
| `org.kya-os/did` | the Entity's DID inside a CIMD document | §7.3 |

The `org.kya-os` reverse-DNS label is outside the reserved `modelcontextprotocol/mcp` `_meta`
namespace; the graceful-degradation contract (§6) covers a registry that strips unknown `_meta`
(degrades to a fetch, not a reject). Registry acceptance of unknown `_meta` MUST be re-verified at
use-time (§15.7).

### 14.2 A2A extension URI

`https://kya-os.org/a2a/ext/entity-card/v1` - version pinned in the URI (§6.2). Registration venue
(DIF vs an A2A extension registry) is an open coordination item (§15.7).

### 14.3 JSON-LD `@context`s

- AgentFacts axes: `https://kya-os.org/ns/agentfacts/v1#` (prefix `kya:`, §6.3).
- Delegation namespace: `https://kya-os.org/ns/delegation/v1` (§10.1), alongside
  `https://www.w3.org/ns/credentials/v2` and `https://w3id.org/security/zcap/v1`.

### 14.4 DID service type

`KyaOsEntityCard` - the single service-`type` string KYA-OS owns (§5.3). W3C decentralizes DID
service types; no central registration is required.

---

## 15. Interoperability & Related Work

Each moving target below is pinned **verified-at 2026-06-30**; re-verify at use-time.

### 15.1 MCP - server.json, SEP-2127, SEP-991 (CIMD)

`server.json` (MCP Registry) is distribution + namespace trust, no crypto. **SEP-2127** Server Card
is now an Extensions-Track charter (`io.modelcontextprotocol/server-card`); the canonical path has
drifted to `/.well-known/mcp/catalog.json` - an INDEX of cards - and its identity fields are
"advisory, not authoritative." KYA-OS co-locates under that rail's `_meta` (§6.1, §6.4). **SEP-991 /
CIMD** is the L1 on-ramp (§7); the IETF draft is
`draft-ietf-oauth-client-id-metadata-document-01` (2026-03-02, pre-WGLC).

### 15.2 A2A

A2A Agent Card v1.0 (Linux Foundation, Apache-2.0, `/.well-known/agent-card.json`, JWS-signed,
first-class `AgentExtension` + `A2A-Extensions` header) is the momentum leader but has **no type,
no DID/VC, and no per-request proof-of-possession**. KYA-OS projects an `AgentExtension` (§6.2)
scoped to `entityType: "agent"`.

### 15.3 NANDA

NANDA AgentFacts (MIT, arXiv:2507.14263, v1.2 schema; VC + ZK selective disclosure slated v1.3)
already ships an `owner: did:org` accountability slot and positions AgentFacts as a superset of the
A2A card. KYA-OS **populates** `owner` from `responsibleParty` rather than re-claiming it, and adds
its unique axes under the `kya:` context (§6.3).

### 15.4 AIP - distinguished

The AIP "Agent Interaction Protocol" capability-token work (**arXiv:2603.24775**) is
**Invocation-Bound Capability Tokens** (Biscuit / Datalog attenuation) - capability tokens, **not**
typed entities and **not** DID-anchored discoverable cards. It is complementary, not overlapping:
it constrains *what a token may invoke*; KYA-OS types the *principal* and proves the *live caller*.
AIP defines neither typed entities nor DID-anchored discoverable cards, so it does not overlap
with either primitive this document marks for ratification.

### 15.5 ANP and legacy KYA-OS session profile

ANP (Agent Network Protocol) is an informative peer in the discovery-rail landscape. Within KYA-OS,
the **legacy session-bound proof** (`ProofMeta` with `sessionId` + handshake nonce) under
`_meta["org.kya-os/proof"]` coexists with `org.kya-os/proof@1` under its own distinct
`_meta["org.kya-os/proof@1"]` key (§8.1); it is retained unchanged for the 1.x line and is expected
to be deprecated at 2.0 in favour of the self-contained profile.

### 15.6 Governance - standardize exactly two primitives

KYA-OS marks **[TAAWG-NORMATIVE]** exactly two sub-primitives - the entity **type axis** (§3) and the
per-request holder-of-key **binding** `client_id → did:web → mandate-VC` (§7–§8) - and nothing else.
These are the only two properties this survey (§15.1–§15.5) confirmed *unfilled*: nobody else types
the principal, and nobody else proves the live caller per request. Every other requirement in this
document is KYA-OS **profiling or projecting** standards it does not own, so it ships as
implementation, not as a new primitive to ratify.

**The standardize-now / ship-now split.**

| Standardize now (seek DIF TAAWG ratification) | Ship now (DIF reference implementation) |
|---|---|
| The `entityType` vocabulary and its closed value space (§3). | Discovery projections onto MCP `_meta`, A2A, NANDA, catalog (§6). |
| The `client_id → did:web → mandate-VC` binding and its `cnf.jkt` fusion (§7–§8, §8.6). | The CIMD document, proof wire-format, and RFC 9421 sibling mechanics (§7–§8). |
| The machine-checkable conformance vectors that pin both (Appendix C). | The L1/L2/L3 ladder (§9), ZCAP-LD delegation (§10), revocation (§10.3), verification order (§11), SafeFetch (§6.6). |

Standardizing the vectors alongside the two primitives is deliberate: a vocabulary and a binding are
only interoperable once a second implementation can reproduce them byte-for-byte (§8.3), so the
vectors *are* the ratifiable artifact.

**Timing.** NANDA v1.3 (VC + ZK selective disclosure, §15.3) and A2A's `AgentExtension` momentum
(§15.2) are converging on the same identity seam, so the working group should treat recognition of
the two primitives (type vocabulary first, then the binding, then the vectors) as time-sensitive:
once a peer rail ships an equivalent, the axis stops being available to standardize here.

### 15.7 Open coordination items

The A2A extension-URI registration venue (§14.2); MCP registry acceptance of unknown `_meta`
(§14.1); whether the AS (`example.com` / Vouched) emits RFC 9449 `cnf.jkt` today (else L3-minus,
§8.6); status-list hosting + cascading-walk cost (§10.3); a registry-signed offline `did:web`
key-pin (§12.8); the per-route nonce policy (§12.2, §12.9); and whether the Card should carry a
field enumerating the access-control mechanisms an Entity supports (raised in review; today the
mechanisms are implied by `proofProfile`, `cimd`, and the delegation locators rather than named).

---

## Appendix A: JSON Schema

The normative Card schema is published at `schemas/kya-os-card.schema.json`
(`$id: https://schema.kya-os.org/v1/protocol/identity/card/v1.1.0`), `additionalProperties: false`,
`required: ["id", "entityType", "name"]`, mirrored by the Zod `EntityCardSchema` in
`@kya-os/mcp/card`. It defines `$defs` for `Ed25519PublicJwk`, `Capability` (L1 string | L2 object),
`CapabilityAttestation`, `Attestation`, `CimdBinding`, and `BitstringStatusListEntry`. The
delegation credential shape is published at `schemas/card-delegation-credential.json` (the W3C
VC 2.0 + ZCAP-LD profile; the legacy VC 1.0 delegation shape stays at
`schemas/delegation-credential.json`); the legacy detached proof at `schemas/detached-proof.json`.

---

## Appendix B: Worked Examples (per `entityType`)

Golden, `parseCard`-valid Cards, one per type (full fixtures: the `entity-card` vectors in
`conformance/vectors/entity-card.json`).

**`mcp`**
```json
{ "id": "did:web:example.com:mcp:server", "entityType": "mcp", "name": "Acme MCP Server",
  "capabilities": ["tools/list", "tools/call"], "proofProfile": "org.kya-os/proof@1" }
```

**`agent`** (L2 attested capability + accountability + revocation)
```json
{ "id": "did:web:example.com:agents:acme-pay", "entityType": "agent", "name": "Acme Pay Agent",
  "kid": "did:web:example.com:agents:acme-pay#key-1",
  "capabilities": ["handshake",
    { "name": "payments.transfer", "attestations": [ { "vc": "<VC-JWT>" } ] }],
  "responsibleParty": "did:web:api.example",
  "principal": "did:web:example.com:users:alice",
  "delegationRef": "urn:zcap:root>urn:zcap:del1",
  "proofProfile": "org.kya-os/proof@1",
  "revocation": { "statusListCredential": "https://example.com/status/cards", "statusListIndex": "3" } }
```

**`client`** (CIMD on-ramp)
```json
{ "id": "did:web:app.example:clients:acme-cli", "entityType": "client", "name": "Acme CLI",
  "proofProfile": "org.kya-os/proof@1",
  "cimd": { "clientId": "https://app.example/clients/acme-cli",
    "jwksUri": "https://app.example/clients/acme-cli/jwks.json" } }
```

**`verifier`**
```json
{ "id": "did:web:verifier.example", "entityType": "verifier", "name": "Acme Verifier",
  "capabilities": ["proof.verify"] }
```

**`human`** (`did:key`, delegating principal)
```json
{ "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "entityType": "human", "name": "Alice (delegating principal)" }
```

The Ed25519 verification key the proof resolves against is carried as the DID-keyed JWKS embedded
in each `conformance/vectors/card-proof.json` vector (`input.jwks`), so the vector is self-contained.

---

## Appendix C: Conformance Vectors

The Entity Card fixtures are integrated into the implementation-agnostic conformance harness under
`conformance/vectors/` (the `card-proof` and `entity-card` categories), so a **second implementation**
proves interoperability through the SAME `ConformanceAdapter` contract as every other category (see
`CONFORMANCE.md`), and so the RFC 8785 (JCS) canonicalization the per-request proof depends on is
verified **across languages** - closing the cross-language JCS drift risk for the polyglot CLI. The
card vectors are signed with FIXED test keys and a FIXED clock, so the files are byte-reproducible
(`npm run conformance:generate:card`). The keys are TEST-ONLY (their private `d` is committed); never
reuse them.

| Vector file | Contents |
|-------------|----------|
| `conformance/vectors/card-proof.json` | Signed `org.kya-os/proof@1` proofs + their RFC 9421 siblings, each carrying its request, the DID-keyed JWKS (`input.jwks`), audience, and window. One positive vector + five negatives (tampered body, tampered signature, wrong audience, expired, kid⇄did forgery). |
| `conformance/vectors/entity-card.json` | Golden `parseCard`-valid Cards, one per `entityType`, plus the multi-hop VC 2.0 + ZCAP-LD delegation chain (attenuation invariants; leaf invoker === proof `did`) carried by the agent accountability vector. |
| `conformance/card-vectors.ts` | Deterministic regenerator (TypeScript). |
| `conformance/verify.py` | The INDEPENDENT cross-language verifier (pure Python stdlib). |

**Two independent verifications:**

1. **TypeScript reference** - the framework runner drives every card vector through the reference
   adapter (`npm run conformance`), and `src/card/__tests__/vectors.test.ts` additionally round-trips
   the positive vector through the shipped engine at a finer grain (`buildCardProof` /
   `verifyCardProof` / `verifyHttpSignature` / `validateDelegationChain` / `parseCard`).
2. **Cross-language (Python stdlib-only)** - a second implementation sharing no code with the TS
   reference; it re-derives `JCS({method,params})`, recomputes the SHA-256 `requestHash`, and verifies
   BOTH the detached EdDSA JWS and the RFC 9421 `httpSig` against the vector's embedded JWKS (Ed25519
   via the RFC 8032 reference): `python3 conformance/verify.py`. Expected:

```
KYA-OS cross-language verifier (Python 3.x, stdlib-only)
  proof: org.kya-os/proof@1  did: did:web:example.com:agents:acme-pay
  [PASS] requestHash JCS+SHA-256 recompute
  [PASS] detached EdDSA JWS over JCS(coveredClaims)
  [PASS] RFC 9421 httpSig over the signature base
  [PASS] RFC 7638 cnf.jkt thumbprint fusion
RESULT: PASS - cross-language JCS + Ed25519 parity confirmed
```

A green run of both proves cross-language canonicalization + Ed25519 signature parity.

---

## Appendix D: Error Codes

Codes are snake_case, aligned to the implementation.

### D.1 Per-request proof reasons (`verifyCardProof`, §11.2)

| Code | Meaning |
|------|---------|
| `malformed_proof` | The proof failed schema validation. |
| `kid_did_mismatch` | `kid.split('#')[0] !== did`. |
| `key_unresolvable` | The signing key for `kid` could not be resolved. |
| `did_membership_unverifiable` | No `resolveDidKeys` seam and no `trustResolveKeyAuthority` opt-out - membership cannot be proven, so fail closed. |
| `did_keys_unresolvable` | The DID document's keys could not be resolved. |
| `kid_not_in_did_document` | The signing key is not a published verification method of `did`. |
| `thumbprint_computation_failed` | A resolved JWK was structurally invalid, so its RFC 7638 thumbprint could not be computed - fail closed. |
| `audience_mismatch` | `audience !== expectedAudience`. |
| `request_hash_mismatch` | `requestHash` does not recompute over the request. |
| `invalid_window` | `expires <= created`. |
| `ttl_too_long` | `expires - created > 60`. |
| `created_in_future` | `created > now + skew`. |
| `expired` | `expires < now - skew`. |
| `nonce_replayed` | The nonce has been seen for this `did`. |
| `nonce_seam_missing` | No `consumeNonceIfFresh` seam supplied - replay freshness cannot be verified, so fail closed. |
| `alg_key_mismatch` | Proof `alg` (`EdDSA` \| `ES256`) does not match the resolved signing key type (Ed25519 / P-256). |
| `invalid_signature` | The detached JWS did not verify under the pinned `alg`. |
| `cnf_key_mismatch` | Proof `cnf.jkt` ≠ the signing key thumbprint. |
| `cnf_required_by_token` | Token supplied a `cnf` but the proof carries none (downgrade). |
| `cnf_token_mismatch` | Proof `cnf.jkt` ≠ the token `cnf.jkt`. |
| `proof_verifier_threw` | The injected proof verifier threw (fail-closed demotion). |

### D.2 Proof gate codes (`requireProof` middleware, §9, 401-shaped)

| Code | Meaning |
|------|---------|
| `proof_missing` | No `org.kya-os/proof@1` in `_meta`. |
| `proof_invalid` | The holder-of-key proof did not verify. |
| `proof_level_insufficient` | The proof assurance is below the required `minLevel`. |

### D.3 Delegation, revocation & CIMD reasons

`validateDelegationChain` / `evaluateDelegationChain` emit human-readable reasons for: allowedAction
escalation, caveat broadening/dropping, `validUntil` broadening, broken continuity (parent invoker ≠
child issuer; child `parentCapability` ≠ parent id), `invocationTarget` drift, depth-cap exceeded,
and root mismatches (SPEC.md §6.10). `evaluateRevocationChain` emits a fail-closed reason per revoked /
unresolvable hop (§10.3). `verifyCimdBind` emits origin-mismatch and missing-`alsoKnownAs` reasons
(§7.4).

### D.4 Legacy protocol error codes (1.x session profile)

Retained for the legacy session-bound path (§15.5): `handshake_failed`, `session_expired`,
`delegation_invalid`, `insufficient_scope`, `delegation_revoked`, `invalid_proof`, `did_not_found`.

---

## References

### Normative References

- **[RFC2119]** IETF. *Key words for use in RFCs to Indicate Requirement Levels*. https://datatracker.ietf.org/doc/html/rfc2119
- **[RFC8174]** IETF. *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words*. https://datatracker.ietf.org/doc/html/rfc8174
- **[RFC7517]** IETF. *JSON Web Key (JWK)*. https://datatracker.ietf.org/doc/html/rfc7517
- **[RFC7638]** IETF. *JSON Web Key (JWK) Thumbprint*. https://datatracker.ietf.org/doc/html/rfc7638
- **[RFC8032]** IETF. *Edwards-Curve Digital Signature Algorithm (EdDSA)*. https://datatracker.ietf.org/doc/html/rfc8032
- **[RFC8037]** IETF. *CFRG Elliptic Curve Signatures in JOSE*. https://datatracker.ietf.org/doc/html/rfc8037
- **[RFC8785]** IETF. *JSON Canonicalization Scheme (JCS)*. https://datatracker.ietf.org/doc/html/rfc8785
- **[RFC9421]** IETF. *HTTP Message Signatures*. https://datatracker.ietf.org/doc/html/rfc9421
- **[RFC9449]** IETF. *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*. https://datatracker.ietf.org/doc/html/rfc9449
- **[DID-CORE]** W3C. *Decentralized Identifiers (DIDs) v1.0*. https://www.w3.org/TR/did-core/
- **[DID-WEB]** W3C CCG. *did:web Method Specification*. https://w3c-ccg.github.io/did-method-web/
- **[DID-KEY]** W3C CCG. *did:key Method Specification*. https://w3c-ccg.github.io/did-method-key/
- **[VC-DATA-MODEL-2]** W3C. *Verifiable Credentials Data Model v2.0*. https://www.w3.org/TR/vc-data-model-2.0/
- **[ZCAP-LD]** W3C CCG. *Authorization Capabilities for Linked Data (ZCAP-LD)*. https://w3c-ccg.github.io/zcap-spec/
- **[BITSTRING-STATUS-LIST]** W3C. *Bitstring Status List v1.0*. https://www.w3.org/TR/vc-bitstring-status-list/
- **[CIMD]** IETF. *OAuth Client ID Metadata Document* (draft-ietf-oauth-client-id-metadata-document). https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/

### Informative References

- **[MCP]** Model Context Protocol Specification. https://modelcontextprotocol.io/
- **[SEP-2127]** MCP Server Card (Extensions-Track `io.modelcontextprotocol/server-card`).
- **[SEP-991]** MCP Client ID Metadata Document.
- **[A2A]** Agent2Agent Protocol (Linux Foundation). https://a2a-protocol.org/
- **[NANDA-AGENTFACTS]** *AgentFacts*. arXiv:2507.14263.
- **[AIP-IBCT]** *Invocation-Bound Capability Tokens*. arXiv:2603.24775.
- **[MULTIBASE]** Multiformats. *Multibase*. https://github.com/multiformats/multibase
</content>
