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
epochs, so a retry cannot become a new event after rollover.

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

Run the provider contract kit for every adapter:

```ts
const report = await evaluateAuditJournalProviderContract(
  () => new PostgresAuditJournal(pool),
);
assertAuditProviderContract(report);
```

The package also includes distinct evidence, observer, and supporting-anchor
contract suites. Passing the anchor suite never qualifies an adapter as an
independent observer.

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

Each producer event receives an atomically claimed source sequence. Consecutive
events also carry `previousSourceEventDigest`. `recordSourceHighWater()` emits
the producer's current high-water mark through the same recorder path. The
source-state provider tracks highest emitted, highest contiguously receipted,
and explicit pending gaps. AAP-3 requires durable source state.

## Event and privacy model

The event catalog is the `AUDIT_EVENT_TYPES` constant. It covers session, tool,
proof, delegation, authorization, consent/credential, key/configuration,
ledger/checkpoint, evidence/projection, and administrative lifecycle events.
Every detail payload is a strict discriminated union. Arbitrary integrity-core
metadata and unknown fields fail closed.

The MCP adapter excludes raw arguments, response bodies, error text, and tool
names by default. `includeToolNames` is an explicit policy decision. Identity
and resource references declare their privacy form:

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
version. It does not use convergent encryption. The producer and recorder both
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

`AuditCheckpointCoordinator` publishes a committed checkpoint to independent
observers and supporting anchors. Publication is retryable and may enforce a
minimum observer count and required anchor kinds. Failure does not roll back the
signed checkpoint.

The roles are not interchangeable:

- An independent observer validates, retains, chains, and compares checkpoint
  views. It detects rollback and conflicting same-size roots relative to the
  views it has independently learned.
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

## Projections and Checkpoint integration

`AuditProjectionWorker` derives a minimal timeline projection with an atomic
offset. It supports incremental synchronization, deterministic reset/rebuild,
and head reconciliation with four honest states: `empty`, `pending`,
`verified`, and `gap_detected`. The projection is disposable. The journal plus
declared enrichment inputs remain the source of truth.

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
