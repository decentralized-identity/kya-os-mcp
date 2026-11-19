# KYA-OS Auditability Protocol

This document is the implementation and operations guide for the auditability
domain exported by `@kya-os/mcp/audit`. The normative wire objects are the JSON
schemas under [`schemas/`](./schemas/), while this guide explains how the pieces
compose and what an assurance claim actually means.

The protocol provides evidence that supports audit, incident-response, and
regulatory-control workflows. It does not itself make an application compliant,
prove that an uninstrumented event never happened, or turn a storage receipt into
an independent non-equivocation guarantee.

## The result

The audit service combines four deliberately separate layers:

1. A privacy-minimal, strictly typed producer event.
2. An authoritative recorder that atomically assigns epoch, sequence,
   predecessor, service time, and a signed receipt.
3. RFC 9162 Merkle checkpoints, independently observed heads, and optional
   supporting WORM/RFC 3161/SCITT receipts.
4. A signed-inventory replay bundle verified against trust and authorization
   policy supplied outside that bundle.

Detached tool proofs remain origin evidence. They are not overloaded with log
state, and they do not assign chain position. The recorder envelope composes
proofs, authorization collateral, outcomes, and administrative events into one
replayable history.

## Public modules

```ts
import {
  createAuditTrail,
  createLocalAuditRecorder,
  AuditRecorderService,
  AuditCheckpointBuilder,
  AuditCheckpointCoordinator,
  AuditArtifactVerifier,
  AuditReplayBundleExporter,
  verifyAuditBundle,
} from '@kya-os/mcp/audit';

import {
  evaluateAuditJournalProviderContract,
  assertAuditProviderContract,
} from '@kya-os/mcp/audit/testing';
```

`@kya-os/mcp/audit` contains runtime contracts and reference implementations.
`@kya-os/mcp/audit/testing` is framework-neutral: adapter packages can run the
same executable provider contracts under Vitest, Jest, Node test, or their own
harness without taking a production dependency on a test framework.

## Local composition

The smallest complete topology runs the authoritative recorder in process. The
memory implementations are intentionally ephemeral and appropriate only for
tests, examples, and local development.

```ts
import { generateKeyPair } from 'jose';
import { NodeCryptoProvider } from '@kya-os/mcp';
import {
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
  MemoryAuditJournal,
  createLocalAuditRecorder,
  createAuditTrail,
} from '@kya-os/mcp/audit';

const crypto = new NodeCryptoProvider();
const hasher = new CryptoProviderAuditHasher(crypto);
const { privateKey } = await generateKeyPair('EdDSA');
const recorderRef = {
  did: 'did:web:audit.example',
  kid: 'did:web:audit.example#recorder-2026-01',
  alg: 'EdDSA',
} as const;
const journal = new MemoryAuditJournal();
const signer = new CompactJwsAuditSigner(recorderRef, privateKey);

const recorder = createLocalAuditRecorder({
  ledgerId: 'kya:tenant-opaque:prod:primary',
  ledgerEpochId: 'epoch-2026-07',
  tenantRef: {
    kind: 'keyed_commitment',
    value: `sha256:${'0'.repeat(64)}`,
    keyId: 'tenant-index-key-v3',
  },
  binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
  sourceId: 'authoritative-recorder',
  journal,
  signer,
  hasher,
  clock: Date,
}, () => ({
  producerAuthority: 'did:web:mcp.example',
  tenantAuthority: 'tenant-opaque',
}));

const audit = createAuditTrail({
  recorder,
  delivery: 'required',
  hasher,
  ledgerId: 'kya:tenant-opaque:prod:primary',
  expectedLedgerEpochId: 'epoch-2026-07',
  tenantRef: {
    kind: 'keyed_commitment',
    value: `sha256:${'0'.repeat(64)}`,
    keyId: 'tenant-index-key-v3',
  },
  producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
  sourceId: 'mcp-server-1',
  binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
  privacy: { classification: 'internal', retentionClass: 'audit-365d' },
  clock: Date,
});

await audit.record({
  eventType: 'tool.call.completed',
  action: { category: 'tool.call' },
  outcome: 'succeeded',
  evidence: [],
  details: { family: 'tool', phase: 'completed', attempt: '1' },
});
```

Pass `audit` to `withKyaOs(server, { crypto, audit })` or
`createKyaOsMiddleware({ identity, audit })`. Audit capability and profile data
are returned by the `_kyaos` identity action. `audit: false` advertises AAP-0.
The legacy `auditLog` option remains a migration-only capture sink; configuring
both old and new paths is rejected to prevent double counting.

See [`examples/audit-trail/`](./examples/audit-trail/) for an executable local
walkthrough.

## Recorder authority and topology

Exactly one logical authority assigns sequence and signs receipts for a
`(ledgerId, ledgerEpochId)` pair.

- In managed mode, a remote Checkpoint recorder implements
  `AuditRecorderClient`. Producers send only a frozen event and encrypted
  evidence; they cannot choose recorder time, sequence, predecessor, epoch, or
  signature.
- In self-hosted mode, `AuditRecorderService` is backed by a transactional
  journal owned by the tenant.
- In mirror mode, `AuditMirrorService` verifies and stores the exact signed
  envelope. A mirror never resequences, resigns, or promotes itself silently.

Failover, key rotation that changes authority, and sealed retention rollover
create a new `ledgerEpochId`. The new genesis commits the previous epoch ID and
terminal checkpoint digest. Logical-ledger idempotency remains scoped by
authenticated producer authority, source ID, and event ID across retained
epochs, so a retry cannot become a new event after rollover. The recorder
resolves that idempotency before enforcing the epoch envelope: a redelivered
submission still pinned to a retained earlier epoch resolves to its original
entry, and `expectedLedgerEpochId` fences only new appends. The producer
never pins buffered outbox submissions, because a durable item may be
delivered after rollover, where the idempotency scope above, not epoch
pinning, carries the retry guarantee.

## Atomic journal contract

`AuditJournalProvider` is purpose-specific. Generic CRUD is insufficient. A
production adapter must provide:

- one serialization point for expected-head comparison plus exact append;
- unique epoch sequence and logical-ledger idempotency constraints;
- same-ID/same-content return of the original stored receipt;
- same-ID/different-content rejection;
- ordered, snapshot-stable range reads;
- no ordinary update or delete operation;
- truthful durability and atomicity capabilities.

A head read is only a hint. When one is behind the highest head this recorder
has appended (a lagging read replica), the recorder compares-and-appends against
its own committed head instead, so a stale read costs a retry, as it always has.
If the journal's compare-and-append answer then reports a head below that
committed head, or a different digest at a sequence the journal already
reported (a failover to a lagging primary, or a restore), the recorder fails
closed with `AUDIT_JOURNAL_FAILURE` instead of signing a second entry at a
receipted sequence. Restoring a journal is an epoch transition, not a silent
rewind.

A head the recorder did not append in this process, and every leaf a checkpoint covers, is otherwise whatever the journal store holds.
A party that can write that store, and holds no key, can insert a well-formed entry with correct digests and a receipt the recorder never signed: the recorder would then sign a successor that commits to it, and the checkpoint builder a tree that holds it.
The recorder and the checkpoint builder therefore check each such entry before they build on it.
The recorder chains to such a head only once the stored entry at that head verifies as one it signed for its ledger epoch, and the builder signs a checkpoint only over leaves that verify as their recorder's and chain to the leaf before them; each refuses with `AUDIT_JOURNAL_FAILURE`, naming the entry's `sequence`, otherwise.
The builder verifies the leaves after the last checkpoint it verified in full, and every leaf after a restart.

They check with the `signatures` verifier when you give one.
Otherwise they ask their signer: a `CompactJwsAuditSigner` over a private JWK, a Node.js `KeyObject` or an extractable `CryptoKey` derives, from the public half of its key, a verifier of signatures under its own `ref`, and they use that.
A `CompactJwsAuditSigner` over a `CryptoKey` created non-extractable, from which WebCrypto reads no public key, derives none, and nor does a signer of your own unless it implements `verifier()`, as a signer backed by a remote key service can when it reads the public key from that service.
Give such a recorder and builder the `signatures` verifier you give `AuditArtifactVerifier`, resolving the recorder's key; without either, the journal is trusted as written, as in earlier releases.

```ts
// recorderKeys is an AuditVerificationKeyResolver that resolves the recorder's public key.
const signatures = new CompactJwsAuditSignatureVerifier(recorderKeys);
const recorder = new AuditRecorderService({ ...config, journal, signer, hasher, clock, signatures });
const checkpoints = new AuditCheckpointBuilder({ journal, store, signer, hasher, signatures });
```

A derived verifier checks only entries recorded under the signer's own key.
That covers the recorder, which chains only to entries recorded under its own key, as every entry of its epoch is.
A checkpoint builder may sign with a key of its own, and then cannot check the recorder's entries with its derived verifier: it trusts each leaf recorded under another key as written, as in earlier releases, still requires it to chain to the leaf before it, and warns once per process for each such key, naming it and saying to pass `signatures`.
A forged entry that claims another key is therefore checkpointed with only that warning, so give a builder `signatures` that resolve the recorder's key wherever you can; with `signatures` every leaf is verified, and one under a key they cannot resolve is refused.
The warning names at most 32 keys in a process, then says once that there are more.
When the signer fails to derive its verifier, the recorder or builder refuses the call with `AUDIT_INVALID_CONFIGURATION` and asks the signer again on the next one.
`createInMemoryReferenceRecorder` passes `signatures`.

Run the provider contract kit for every adapter:

```ts
const report = await evaluateAuditJournalProviderContract(
  () => new PostgresAuditJournal(pool),
);
assertAuditProviderContract(report);
```

The journal contract issues eight compare-and-append calls on one expected head at once.
Exactly one must commit, and each of the others must answer `head_conflict` with the head that won, or fail without committing.
A journal that reads the head, compares it and then inserts, with any await between the two steps, commits more than one, and the recorder would sign each of them at one sequence.
The contract also offers an expected head that is no longer the head, both the current sequence with another entry's digest and an earlier head, and requires a `head_conflict` that names the actual head.
Passing it shows that the adapter serializes appends under the contract's load; it does not prove the adapter atomic under every load, so keep the comparison and the insert in one transaction or one serialization point as below.

The package also includes distinct evidence, observer, and supporting-anchor
contract suites. Passing the anchor suite never qualifies an adapter as an
independent observer.

The observer contract takes checkpoints signed by the recorder key your observer trusts.
Besides `first`, `next`, `conflict`, `rollback` and the optional `gapped`, give it `fork`: a validly signed checkpoint of the same ledger epoch, larger than `first`, over a history that does not extend `first`'s tree, as a holder of the recorder key could sign after rewriting the observed history.
Sign it over a second journal with the same ledger ID, epoch and key, recorded with different events.
The observer must accept `fork` on its own and refuse it once it has observed `first`.
Without `fork` that check is not run: the report lists it with `skipped` set to the reason, and it does not fail the report or `assertAuditProviderContract`, but no other fixture shows that the observer checks an extension, so give `fork` to have it checked.
The contract also derives, from `first` and `next`, checkpoints whose signature does not verify, and requires the observer to refuse each and keep `first` as its latest observation; that check needs no fixture and always runs.

A check that a contract could not run, for want of a fixture, is reported with `passed: true` and `skipped` set to why and what to give it.
`passed` then means only that the check did not fail, so a CI job that must show every check ran can require that no check has `skipped` set:

```ts
const report = await evaluateAuditObserverProviderContract({ createProvider, fixtures });
assertAuditProviderContract(report);
expect(report.checks.filter((check) => check.skipped !== undefined)).toEqual([]);
```

For PostgreSQL, use a ledger-head row plus entry/idempotency unique constraints
inside one transaction. For Cloudflare, route one epoch to one Durable Object
serialization point. R2, KV, object lock, and a broker partition are useful
behind the design, but none alone satisfies authoritative compare-and-append.

## Delivery semantics

The producer declares one of three modes:

| Mode | Response boundary | Maximum honest claim |
|---|---|---|
| `best-effort` | append attempted | AAP-1 / capture only |
| `buffered` | durable producer outbox acknowledged | pending until receipt reconciliation |
| `required` | authoritative signed receipt obtained | chained/transparency profiles |

Buffered mode refuses an ephemeral outbox at startup. Required mode propagates
intent-append failure before the wrapped handler runs. If a terminal append
fails after an external side effect, middleware returns a degraded audit marker
instead of pretending the lifecycle is complete. Exactly-once behavior across
arbitrary external systems is not claimed; use a transactional outbox where the
host and producer outbox share a database, otherwise use intent, terminal event,
stable idempotency, and reconciliation.

Direct-mode retries are idempotent only when the rebuilt event is byte-stable:
a caller that retries `record()` with a stable event ID must also pin
`occurredAt`, otherwise the recorder rejects the drifted content as an
event-identity conflict. Buffered outbox redelivery is always byte-stable, and
`flush()` receipts each delivered item against the item's own producer source.
An event without a caller-supplied ID gets a random `audit_<uuid>` ID, so two
trails sharing an outbox or a recorder never mint the same one.

Evidence is persisted write-ahead of its committing entry. If the append then
permanently fails, the recorder best-effort disposes the ciphertext that this
submission newly stored, after re-confirming that no committed entry claims the
event identity. An object that already existed, such as an encrypted actor
reference shared by every event of a session, is never disposed, because a
committed entry may reference it. Nor is one that another submission to the
same recorder held while this one did: both may have seen it as new, and the
other may have committed a reference to it. A disposal failure retains the
orphan for operator retention tooling rather than risking a racing committed
reference.

The outbox contract persists an `attempts` count and yields only delivery-eligible
items. Retry cadence, attempt caps, and dead-letter routing are provider policy,
because they depend on the host's queue and operational controls. A durable
adapter must remove dead-lettered items from `pending()` while retaining them for
operator inspection and recovery; the in-memory development adapter intentionally
has no retry cap.

Event IDs are unique only within a producer source. An outbox that declares
`capabilities.keyedBySource` deduplicates, acknowledges, and fails items by
`(sourceId, eventId)` (`AuditOutboxItemKey`, see `auditOutboxItemKey`), and the
trail passes it that key. An adapter without the capability keeps receiving the
bare event ID its `markDelivered(eventId: string)` signature expects; the
interface accepts either. `MemoryAuditOutbox` declares the capability, except
in a subclass that overrides `markDelivered` or `markFailed`: such a subclass
may have been written for the bare event ID, so it keeps receiving one unless
it declares the capability itself. It still accepts a bare event ID from direct
callers, but only while exactly one pending item carries it: with several
sources pending, it throws rather than guess whose item to acknowledge. Once
the recorder has committed an item, `flush()` counts
it as delivered: a failure to acknowledge it reaches `onAcknowledgementFailure`,
never `markFailed` or `onDeliveryFailure`, and the item's later redelivery
resolves to the same receipt.

Each producer event receives an atomically claimed source sequence. Consecutive
events also carry `previousSourceEventDigest`. `recordSourceHighWater()` emits
the producer's current high-water mark through the same recorder path. The
source-state provider tracks highest emitted, highest contiguously receipted,
and explicit pending gaps. AAP-3 requires durable source state.

The trail validates an event (schema, canonical JSON, evidence references)
before it claims a source sequence, so rejected input never consumes a sequence
or breaks predecessor linkage; a claim whose event then fails to build is
released through the optional `abandonClaim` where the provider supports it.
Re-claiming an event ID the provider still retains returns the original claim,
so an at-least-once redelivery of a stable event ID rebuilds the identical
event and resolves to its original receipt. `MemoryAuditSourceState` retains
receipted claims for a bounded redelivery window (`redeliveryWindow`, default
1024 per source) and otherwise keeps only pending events, so one unreceipted
gap does not stop it from releasing memory.

## Event and privacy model

The event catalog is the `AUDIT_EVENT_TYPES` constant. It covers session, tool,
proof, delegation, authorization, consent/credential, key/configuration,
ledger/checkpoint, evidence/projection, and administrative lifecycle events.
Every detail payload is a strict discriminated union. Arbitrary integrity-core
metadata and unknown fields fail closed.

The MCP adapter excludes raw arguments, response bodies, error text, and tool names by default.
`includeToolNames` is an explicit policy decision.
References a caller presents (delegation, grant, consent, scope, and policy references, correlation and causation IDs, tool names) are untrusted: one that is empty, over the schema bound, not well-formed UTF-16, or holding a character that does not print (a control or format character, a line or paragraph separator, or a code point that renders as nothing by default, as SPEC.md §7.8 lists them) is recorded as the `sha256:` digest of its UTF-8 encoding, so a hostile identifier cannot keep the event out of the ledger, break a log line or show a reader another identifier than the one recorded, and a long reference handed to the adapter cannot collide with another that shares its prefix.
A delegation credential is recorded by the reference SPEC.md §7.8 defines, which `wrapWithDelegation` derives as a verifier derives a proof's `delegationRef`, so an event and a proof that names the credential carry one string.
It is the ID the credential shows, or the `sha256:` digest of an ID that is over 256 UTF-16 code units, holds a character that does not print or a surrogate without its pair, is itself written as such a digest (`sha256:` and 64 lowercase hex digits), or is the word `unknown`, so a `delegationRef` of that form always stands for the digest of an ID, and never for an ID a caller wrote to look like one, and `unknown` never stands for a credential.
A credential that shows no ID has no reference: its events carry no `authorization.delegationRef`, and its `delegation.verified` or `delegation.rejected` event names it `unknown`.

A delegated call's authorization evidence carries the presented credential's digest as well as its name: `delegationRef` and `delegationCredentialDigest` (SPEC.md §7.8 defines the digest).
`wrapWithDelegation` records the pair on the events of its decision, and puts it in the `context.authorization` it hands the handler of a call it allows, and of a retry it allows under a stored grant.
The events recorded with that context take their evidence from `context.authorization`, as in earlier releases: the tool call's and its proof's from `wrapWithProof`, and a nested `withPolicyGate`'s.
A presented value that has no signed form has no digest (SPEC.md §7.8): a credential object nested more than 64 levels deep, say, is recorded by its reference alone.
The events that record the gate's decision also list the chain, as `delegationChainDigests`, one digest per credential evaluated, root first.
They are `delegation.verified`, `delegation.rejected` and `grant.used`.
A call refused after its chain verified, on holder binding or scope, has no delegation event, and its refusal is recorded as in earlier releases, without the delegation.
On a refusal the list is of what the server had read when it refused: the ancestors up to and including the one it stopped at, root first, then the presented credential.
A refusal made before any ancestor was read lists the presented credential alone.
Where an ancestor the server read has no signed form, the chain has no digest: the events list no chain, and still carry the presented credential's own digest.
The reference and the digests of a refusal describe what was presented and examined, not a delegation that is valid: read them with the event's `decision`.
A chain of more than 256 credentials is not listed, and its events carry the presented credential's digest only.

An auditor holding those events can recompute the chain's `delegationChainDigest` (SPEC.md §7.8) without the credentials, and one holding the credentials can show which hop a substituted chain differs in.
Signing either claim of SPEC.md §7.8 from the server is not part of this release: its proofs carry neither `delegationRef` nor `delegationChainDigest`.

Identity and resource references declare their privacy form:

- `public_did` for intentionally public correlation;
- `pairwise_did` for relationship-specific identity;
- `keyed_commitment` for tenant-keyed indexing resistant to low-entropy
  dictionary attacks;
- `evidence_ref` for an encrypted object in a separate vault.

Do not put API keys, prompts, raw tool arguments, responses, access tokens, or
free-form exception text in the event core. Store allowed exact payloads as
encrypted evidence and commit only `EvidenceRef` metadata.

## Evidence, retention, and access

`WebCryptoEvidenceEncryptor` uses randomized AES-256-GCM, a random opaque object
ID, a 96-bit random nonce, authenticated-data digest, ciphertext digest, and key
version. Encryption and decryption reject empty AAD; callers must bind at least
the tenant/entity and evidence purpose into authenticated data. It does not use
convergent encryption. The producer and recorder both
reject encrypted objects that do not exactly match a unique reference in the
frozen event.

`AuditEvidenceProvider` separates ciphertext access from ledger verification.
Its retention commands support disposal, legal hold, and hold release. The
reference memory provider returns defensive byte copies, rejects object-ID
collisions, blocks disposal under legal hold, and can enforce an injected
actor/purpose access policy. Production retention schedulers translate a
deployment's retention classes into these explicit commands and append the
corresponding administration event.

Disposal removes ciphertext, not its commitment. Historical integrity remains
verifiable, while evidence availability becomes explicitly disposed,
redacted, unavailable, or policy-excluded in a bundle inventory.

## Checkpoints, observations, and anchors

`AuditCheckpointBuilder` takes a stable journal head, derives an RFC 9162 tree
over entry digests, signs an immutable checkpoint, and stores it with
put-if-absent conflict detection. It produces and verifies inclusion and
consistency proofs. Checkpoint lifecycle events are appended only after the
snapshot is signed, so they can appear in a later checkpoint and cannot recurse
into the checkpoint they describe.

Before signing, the builder confirms that the journal still contains the latest
checkpoint's exact tree as its prefix; a rewritten or restored history fails
with `AUDIT_CHECKPOINT_CONFLICT` instead of producing a signed checkpoint that
chains to a tree it does not extend. A builder serializes its calls per ledger
epoch, so concurrent calls chain in tree-size order rather than both naming the
same predecessor. If `onCheckpointCreated` throws after the checkpoint was
stored, the builder's next `createCheckpoint` call runs the hook again for that
checkpoint, before any newer one, even when the ledger has grown in between;
the hook must therefore be idempotent on the checkpoint digest.

Every `AUDIT_CHECKPOINT_CONFLICT` the builder and `MemoryAuditCheckpointObserver` raise names why in `details.reason`, one of `AUDIT_CHECKPOINT_CONFLICT_REASONS`:

| `details.reason` | Raised when | What it means |
| --- | --- | --- |
| `lost-race` | The store already holds a checkpoint at this tree size over the same tree the builder signed: another signer checkpointed the same journal first. | Nothing is wrong. The stored checkpoint stands, and calling `createCheckpoint` again returns it. |
| `fork` | The journal no longer holds the latest checkpoint's tree as its prefix, the store holds a checkpoint over another tree at this tree size, or an observer holds a view the checkpoint does not consistently extend. | Two signed views of the ledger disagree. Treat it as a security event and record it. A retry signs nothing until the history is reconciled, which for a restored journal is an epoch transition. |

Branch with `isLostCheckpointRace(error)`, which is true only for a `lost-race` conflict.
Any other `AUDIT_CHECKPOINT_CONFLICT` is a fork, including one with a reason this release does not list and one with no reason, such as an observer of your own may throw.
Do not tell the two apart by the message, or by `details.treeSize`, which both carry.
The reason belongs to this library's API, not to the wire protocol: no schema or conformance vector carries it.

`AuditCheckpointCoordinator` publishes a committed checkpoint to independent
observers and supporting anchors. Publication is retryable and may enforce a
minimum observer count and required anchor kinds. Failure does not roll back the
signed checkpoint.

A receipt counts only when it is for the checkpoint just published.
An observation must name that checkpoint's digest, ledger epoch and tree size, and an anchor receipt its digest and the kind its provider declares.
Any other answer, such as a lagging observer's receipt for an earlier checkpoint, is a failed publication for that provider, retried like a thrown one, and is never counted toward `minimumObservers` or `requiredAnchorKinds`.

The roles are not interchangeable:

- An independent observer validates, retains, chains, and compares checkpoint
  views. It detects rollback and conflicting same-size roots relative to the
  views it has independently learned. An observer that missed intermediate
  publications catches up on any gapped extension whose tree consistency with
  its last observation verifies; the consistency proof, not direct checkpoint
  chain linkage, is the split-view guarantee.
- A WORM, RFC 3161, or SCITT adapter provides supporting durability,
  registration, or time evidence. It does not by itself detect a split view.

## Replay bundles and offline verification

`AuditReplayBundleExporter` sorts component paths, canonicalizes included
content, records size and digest for every included item, records an explicit
disposition and reason for every omission, signs the manifest core, and binds
the verification-policy digest. Safe relative paths and duplicate inventory
entries are rejected.

`verifyAuditBundle()` is an offline, fail-closed verifier. It does not read live
nonce caches. It verifies:

- bundle schema, signed inventory, component bytes, scope, purpose, and exporter
  authority;
- strict event/entry/receipt schema, domain-separated hashes, signatures,
  recorder trust intervals, sequence, predecessor, and genesis;
- independent epoch sequence reset and predecessor-epoch checkpoint commitment;
- checkpoint root/range/signature, predecessor chain, fork conflicts, and
  bundle-bound inclusion/consistency proofs;
- observer trust/signature/freshness/receipt chain;
- supporting-anchor trust and an injected adapter verifier;
- declared range completeness and explicit omission dispositions.

Everything a bundle carries must sit inside a selection its signed manifest declares, because the exporter's grant is checked against those selections.
An entry outside every selected range, or a checkpoint, observation, or Merkle proof of a ledger epoch no selection names, makes committed-scope completeness `invalid` (`AUDIT_BUNDLE_CONTENT_OUTSIDE_SELECTION`).

Checkpoint and observation integrity speak for the entries a bundle selects.
A checkpoint covers a selection when it belongs to the selection's ledger epoch and its tree holds every entry selected.
Until a checkpoint in the bundle covers every selection, checkpoint integrity is at best `indeterminate` (`AUDIT_CHECKPOINT_MISSING`), and until an observation in the bundle names such a checkpoint for every selection, observation integrity is at best `indeterminate` (`AUDIT_OBSERVER_EVIDENCE_MISSING`).
A checkpoint over an earlier tree, or of another epoch, says nothing about entries it does not hold, so a bundle meant to meet AAP-3 or AAP-4 selects ranges that end inside a checkpoint's tree.

A subset export need not carry every leaf. A checkpoint whose complete prefix is
present has its root recomputed; otherwise its signature, digest, issuer trust,
and declared range are verified (`AuditArtifactVerifier.verifySignedCheckpoint`),
and every included entry it covers must carry a verified inclusion proof against
it (`AUDIT_MERKLE_PROOF_MISSING` otherwise). Two included checkpoints of one
epoch must either link directly through `previousCheckpointDigest`, or, when the
export omits checkpoints that could sit between them, be bound by a verified
consistency proof; the proof, not the chain link, is the split-view guarantee,
as for an observer catching up. A successor genesis commits where its
predecessor epoch ends, so a predecessor checkpoint over a larger tree than
that terminal checkpoint is reported as `AUDIT_CHECKPOINT_FORK_DETECTED`.
Predecessor entries past the terminal are not by themselves a fork: the
terminal checkpoint's own `checkpoint.created` event is appended after it is
signed.

The verifier enforces every verification-policy constraint it can evaluate and
never treats one it cannot evaluate as satisfied. No schema-valid policy is
rejected for the constraints it uses:

- `validFromCheckpoint` and `validUntilCheckpoint`, on a recorder or observer key
  or on a trusted ledger epoch, are resolved by digest against supplied
  checkpoints (`AuditVerificationContext`; a bundle supplies its own). An entry
  at sequence `s` sits at tree position `s + 1`, a checkpoint or an observation
  of one at its tree size; a key valid until checkpoint `C` covers positions up
  to `C`'s tree size, and a key valid from `C` covers positions after it.
  Outside the bound the signer is untrusted. A boundary that is absent, or that
  belongs to another ledger epoch, makes the dimension `indeterminate`
  (`AUDIT_KEY_BOUNDARY_UNRESOLVED`), never `valid`. An export has no ledger
  position, so a checkpoint bound on the exporter key that authorizes a bundle
  leaves cryptographic integrity `indeterminate` the same way.
- `requiredAuditProfile` marks every dimension the profile depends on
  `invalid` (`AUDIT_REQUIRED_PROFILE_UNMET`) unless it is `valid`: AAP-1 needs
  cryptographic integrity, AAP-2 adds chain integrity, AAP-3 checkpoint
  integrity, and AAP-4 observation integrity plus, for every selection, a
  supporting anchor receipt for a checkpoint that covers it.
- `keyRevocationMode` selects when key status is evaluated. The integrity
  dimensions always evaluate a key as observed, at the artifact's signing time
  and ledger position, because revocation does not rewrite what was observed;
  `as_observed` stops there. `current` and `both` also require every key that
  signed an entry, checkpoint, observation, or the bundle manifest to be valid
  at `verifiedAt` (within `validFrom`/`validUntil`, and without a
  `validUntilCheckpoint`, which names a checkpoint the key was retired at), and
  report the result in `currentAuthorization`: `invalid`
  (`AUDIT_KEY_NOT_CURRENT`) when a key is no longer valid, `indeterminate`
  (`AUDIT_NOT_EVALUATED`) when the verifier has no `verifiedAt` clock. As the
  as-observed check is never waived, `current` and `both` evaluate the same
  keys. Current key status alone never makes `currentAuthorization` `valid`;
  that still takes the injected authorization verifier.
  Under `as_observed` the signing time is the signer's own claim, so a key that may be compromised can still sign artifacts dated within its interval.
  Retire a suspect key by checkpoint, with `validUntilCheckpoint`, or verify under `current` or `both`.

When a policy requires observation freshness, an observation dated more than
the verifier's clock-skew allowance (`maxClockSkewMs`, default 120 s) after
`verifiedAt` is `invalid` (`AUDIT_OBSERVATION_FUTURE_DATED`), not fresh.

The report keeps these dimensions separate: cryptographic integrity, chain
integrity, checkpoint integrity, anchor/observation integrity, committed-scope
completeness, authorization as observed, and current authorization. Missing
collateral is `indeterminate`, never silently `valid`. Historical and current
authorization are separate injected policy ports because revocation today does
not rewrite what was observed at execution time.

Trust is always out of band. A bundle-supplied recorder key, observer key,
exporter key, DID document, genesis, or checkpoint cannot authorize itself.

CLI usage:

```bash
kya-audit verify bundle.json \
  --policy verification-policy.json \
  --keys trusted-public-keys.json
```

Exit code `0` means no dimension is invalid, `1` means at least one invalid
dimension, and `2` means usage/configuration/input processing failed. An
`indeterminate` dimension remains visible in the JSON report and must be handled
by the relying party's policy.

The CLI verifies at the present time.
Under a policy whose `keyRevocationMode` is `current` or `both`, each key the bundle was signed with must still be valid now, and `requiredCheckpointFreshnessMs` is measured to now, so a key whose validity has ended or a stale observation makes its dimension `invalid` and the exit code `1`.

A failure that exits `2` writes one line to standard error, naming the file it concerns: `bundle.json is not valid JSON`, `policy.json is not a valid verification policy: ...`, or `keys.json could not be read: ...`.
It quotes no bytes of a file that is not JSON, and every character that does not print, a terminal's escape sequences among them, is written as U+FFFD, so a bundle from a stranger cannot reach the operator's terminal.

## Projections and Checkpoint integration

`AuditProjectionWorker` derives a minimal timeline projection with an atomic
offset. It supports incremental synchronization, deterministic reset/rebuild,
and head reconciliation with four honest states: `empty`, `pending`,
`verified`, and `gap_detected`. A projection behind the journal is `pending`
only when its offset digest matches the journal entry at that sequence, and
synchronization refuses (`AUDIT_PROJECTION_CONFLICT`) to apply an entry whose
predecessor is not the projection offset; a projection built from a forked
history is never reported verified and must be rebuilt. The projection is
disposable. The journal plus declared enrichment inputs remain the source of
truth.

Checkpoint should ingest exact signed envelopes through the mirror or recorder
path, store raw integrity objects separately from query projections, and expose
legacy records as `unverified_legacy`. It should never convert old capture rows
into retroactively chained history. Bundle verification in the dashboard should
call the same pure verifier used by the CLI.

## Assurance profiles

Capabilities are machine-readable and validated at startup:

| Profile | Required basis | Claim |
|---|---|---|
| AAP-0 | audit disabled | no audit assurance |
| AAP-1 Recorded | typed capture | delivered instrumented events were recorded |
| AAP-2 Chained | durable atomic journal and non-best-effort delivery | ordered tamper-evident accepted history |
| AAP-3 Transparent | AAP-2, durable source high-water, RFC 9162 checkpoints | inclusion, consistency, and declared source-gap evidence |
| AAP-4 Observed | AAP-3, independent observation, supporting receipt | conflicting known views are detectable relative to independently retained checkpoints |

`assertAuditCapabilities()` rejects profiles whose configured mechanics do not
support their claim. A memory journal advertises `ephemeral`; a mirror advertises
`verified-mirror`; a supporting anchor never advertises independent observation.

## Cryptographic suites

All integrity-critical JSON is validated before RFC 8785 JCS. Unknown critical
fields, accessors, cycles, non-finite numbers, unsafe integers, sparse arrays,
and non-JSON values are rejected. Digest inputs are domain separated with the
UTF-8 bytes of `<domain> + NUL + JCS(value)`.

The initial domains and suites are exported constants:

- `org.kya-os.audit.event.v1`
- `org.kya-os.audit.entry.v1`
- `org.kya-os.audit.evidence-manifest.v1`
- `org.kya-os.audit.idempotency.v1`
- `org.kya-os.audit.checkpoint.v1`
- `org.kya-os.audit.observation.v1`
- `org.kya-os.audit.bundle-manifest.v1`
- `KYA-AUDIT-JCS-SHA256-JWS-2026`
- `KYA-AUDIT-RFC9162-SHA256-JWS-2026`
- `KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026`

The conformance harness contains positive and negative vectors for event JCS,
the domain-separated event digest, RFC 9162 root, inclusion, and consistency.
The Python standard-library verifier independently reproduces the positive
values.

## Migration

`LegacyAuditSinkAdapter` translates legacy `AuditLogProvider` capture into an
explicit `legacy-capture` boundary without copying raw request/response content
or claiming chain history. It does not deduplicate by session, so multiple calls
in one session remain multiple events. During migration:

1. deploy new event emission in shadow validation;
2. compare lifecycle counts and semantic outcomes;
3. move the authoritative writer to the new recorder;
4. retain a signed import boundary and show old data as `unverified_legacy`;
5. remove `auditLog` only after parity and retention obligations are met.

## Production checklist

- Run every provider contract suite and 100+ concurrent recorder submissions.
- Exercise commit-before-response, retry, stale-head, restart, outbox backlog,
  and DLQ recovery in the platform adapter repository.
- Pin recorder, observer, and exporter keys in an independently managed policy;
  define validity and compromise boundaries.
- Configure a durable source-state provider for AAP-3 and reconcile high-water
  gaps.
- Define checkpoint cadence, observer freshness, anchor retry, and alert bounds.
- Use pairwise/keyed references and an encrypted evidence vault with explicit
  access policy, retention, legal hold, and crypto-shredding procedures.
- Monitor append/duplicate/conflict/error rates, receipt latency, outbox depth
  and age, source gaps, checkpoint age, observer freshness, projection lag,
  evidence dispositions, exports/access, and signer expiry.
- Maintain runbooks for corruption, compromised keys, split views, failed
  anchors, evidence exposure, projection rebuild, legal hold, and offboarding.

The architecture supports evidence for controls such as NIST SP 800-53 AU,
SOC 2 logging/monitoring, ISO 27001 logging, and regulated recordkeeping. Any
compliance conclusion still depends on deployment, governance, access control,
retention, operating effectiveness, and the relying auditor.
