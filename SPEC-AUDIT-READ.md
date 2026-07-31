# KYA-OS Audit Read & Replay - Profile Specification

**Operator-facing read, proof, and replay contract over an authoritative audit ledger**

Version: 1.0 (Audit Read profile)
Reference implementation: `@kya-os/mcp` (subpath `@kya-os/mcp/audit`)
Status: **Draft / reference implementation**
Editors: KYA-OS Working Group
Repository: https://github.com/decentralized-identity/kya-os-mcp
Profiles: the KYA-OS Auditability Protocol (the `@kya-os/mcp/audit` recorder, checkpoint, and verifier types)

---

## Abstract

The KYA-OS Auditability Protocol defines how a producer emits signed, hash-chained audit entries and how a recorder seals them into an append-only, RFC 9162 Merkle-checkpointed ledger.
This profile specifies the complementary **read** surface: the operations by which an operator, a command-line tool, or a dashboard retrieves those signed artifacts for browsing, proof, and independent verification.
It is the counterpart to the producer-facing ingest contract.
Every response embeds the recorder's own signed objects, so a reader validates the transport envelope and then re-verifies the artifacts themselves; the read service is never a trusted intermediary.

---

## Conformance Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

---

## 1. Model

A **ledger** is identified by an `AuditLedgerRef` (`ledgerId` + `ledgerEpochId`).
Entries within a ledger epoch carry a strictly increasing decimal `sequence` and chain by `previousEntryDigest`.
A **checkpoint** is a signed RFC 9162 tree head over a prefix of the ledger; inclusion and consistency proofs are stated relative to a checkpoint.

The read surface is transport-agnostic.
An implementation MAY expose it over HTTP, an RPC channel, or in-process; the operation semantics and wire envelopes below are normative regardless of transport.

The read surface carries no privileged authority of its own.
A conforming reader MUST treat every returned artifact as untrusted until it has re-verified it against a trust policy with an `AuditArtifactVerifier` (or an equivalent independent verifier).

---

## 2. Operations

### 2.1 getHead

Returns the current chain head of a ledger, or `null` when the ledger has no entries.
The head binds the highest `sequence` to its `entryDigest`, letting a reader detect whether it holds the complete ledger.

### 2.2 listEntries

Returns a forward, `sequence`-ordered page of signed entries.
The request MAY carry `afterSequence` (an exclusive lower bound) and `limit`.
An implementation MUST clamp `limit` to an implementation-defined maximum and MUST NOT return more than `limit` entries.
The response echoes the ledger head at read time and a `nextAfterSequence` cursor.
`nextAfterSequence` is `null` if and only if the page reached the head; otherwise it is the `sequence` of the last returned entry and MUST be usable as the next request's `afterSequence`.
Stepping the cursor from the start MUST reconstruct the ledger exactly, with no gaps or duplicates.

### 2.3 getInclusionProof

Returns a self-contained Merkle inclusion proof binding one entry to the latest checkpoint's signed root.
The request names the entry by `sequence`.
The response is an `AuditBundleInclusionProofV1` carrying the ledger ref, the entry's `sequence` and `entryDigest`, the `checkpointDigest`, and the raw Merkle proof.
An implementation MUST reject the request when no checkpoint exists for the ledger, or when the sequence is not covered by the latest checkpoint.

### 2.4 getConsistencyProof

Returns a Merkle consistency proof that the ledger at an earlier checkpoint's `oldTreeSize` is an append-only prefix of the latest checkpoint.
The response is an `AuditBundleConsistencyProofV1` binding both checkpoint digests and the raw consistency proof.
An implementation MUST reject the request when no checkpoint exists at `oldTreeSize`.

---

## 3. Wire Envelopes

Each request and response is a schema-tagged envelope, mirroring the producer event and recorder receipt.
A transport MUST validate an inbound envelope against its schema before acting on it.

| Operation | Request schema | Response schema |
|---|---|---|
| getHead | `.../audit/head-request/v1.0.0` | `.../audit/head-response/v1.0.0` |
| listEntries | `.../audit/list-entries-request/v1.0.0` | `.../audit/list-entries-response/v1.0.0` |
| getInclusionProof | `.../audit/inclusion-proof-request/v1.0.0` | `.../audit/inclusion-proof-response/v1.0.0` |
| getConsistencyProof | `.../audit/consistency-proof-request/v1.0.0` | `.../audit/consistency-proof-response/v1.0.0` |

Schema identifiers are rooted at `https://schema.kya-os.org/v1/protocol/`.
All envelopes are `strict`: unknown fields MUST be rejected.

---

## 4. Verification

This profile assumes the "verify twice" model.
A serving implementation MAY assert its own verification result to a client, but a conforming client MUST be able to independently re-verify.

A client re-verifies a `listEntries` response by validating the response envelope, then verifying the embedded entries against a trust policy: signatures, digests, and chain continuity.
A client re-verifies an inclusion proof by confirming the entry's `entryDigest`, then checking that the proof's Merkle path closes to the `rootDigest` of the named, signature-verified checkpoint.
A client re-verifies a consistency proof by checking that the proof closes between the two named, signature-verified checkpoints.

Verification MUST succeed after transport serialization; a JSON round trip MUST NOT alter any digest or signature.

---

## 5. Reference Implementation

`@kya-os/mcp/audit` provides:

- `AuditReadService` and `LocalAuditReadService` - the operation contract over an `AuditJournalProvider` and optional checkpoint access.
- `read-contract` - the schema-tagged request/response types, Zod validators, parsers, and domain-to-envelope serializers.
- `createInMemoryReferenceRecorder` - a self-contained recorder that produces genuine signed entries and serves this contract, for conformance tests and local development.

The reference recorder and read service are the executable definition of this profile; where prose and code disagree, the conformance tests in `@kya-os/mcp` are authoritative for this draft.
