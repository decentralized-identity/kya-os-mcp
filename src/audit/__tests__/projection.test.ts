import { describe, expect, it } from 'vitest';
import type { AuditJournalProvider } from '../providers/journal.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import {
  AuditProjectionWorker,
  MemoryAuditProjectionProvider,
  type AuditProjectionProvider,
} from '../projection.js';
import type { AuditLedgerRef, Digest, SignedAuditEntryV1 } from '../types.js';

const ledger: AuditLedgerRef = { ledgerId: 'projection-ledger', ledgerEpochId: 'epoch-1' };
const digest = (character: string) => `sha256:${character.repeat(64)}` as Digest;

function entry(sequence: number, previous: Digest | null): SignedAuditEntryV1 {
  const entryDigest = digest(String(sequence + 1));
  const eventDigest = digest('a');
  const eventId = `projection-event-${sequence}`;
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
      ...ledger, sequence: String(sequence), previousEntryDigest: previous,
      recordedAt: 1_750_000_000_100 + sequence,
      recorder: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#key', alg: 'EdDSA' },
      eventDigest,
      event: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
        eventId,
        eventType: sequence === 0 ? 'ledger.epoch.started' : 'tool.call.completed',
        eventVersion: '1.0.0', binding: 'urn:kya-os:audit-binding:test:1',
        occurredAt: 1_750_000_000_000 + sequence,
        tenantRef: { kind: 'pairwise_did', did: 'did:key:zTenant' },
        source: { producer: { kind: 'pairwise_did', did: 'did:key:zProducer' }, sourceId: 'source', sourceSequence: String(sequence) },
        correlationId: 'correlation-1', action: { category: 'tool.call' }, outcome: 'succeeded',
        evidence: [],
        details: sequence === 0
          ? { family: 'ledger', phase: 'epoch_started' }
          : { family: 'tool', phase: 'completed', attempt: '1' },
        privacy: { classification: 'internal', retentionClass: 'audit' },
      },
      evidenceManifestDigest: digest('b'), integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
    },
    eventDigest, entryDigest,
    recorderReceipt: {
      core: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0',
        ...ledger, sequence: String(sequence), eventId, entryDigest,
        previousEntryDigest: previous, recordedAt: 1_750_000_000_100 + sequence,
        recorder: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#key', alg: 'EdDSA' },
        integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
      },
      jws: 'signature',
    },
  };
}

function passthrough(journal: MemoryAuditJournal): AuditJournalProvider {
  return {
    capabilities: journal.capabilities,
    getHead: (input) => journal.getHead(input),
    getByIdempotencyKey: (ledgerId, key) => journal.getByIdempotencyKey(ledgerId, key),
    compareAndAppend: (input) => journal.compareAndAppend(input),
    readRange: (query) => journal.readRange(query),
  };
}

async function append(journal: MemoryAuditJournal, value: SignedAuditEntryV1): Promise<void> {
  await journal.compareAndAppend({
    ledger,
    expectedHead: await journal.getHead(ledger),
    entry: value,
    idempotencyKey: digest(String(Number(value.core.sequence) + 4)),
  });
}

describe('audit projection worker', () => {
  it('incrementally projects and deterministically rebuilds a disposable timeline', async () => {
    const journal = new MemoryAuditJournal();
    const first = entry(0, null);
    const second = entry(1, first.entryDigest);
    await append(journal, first);
    const projections = new MemoryAuditProjectionProvider();
    const worker = new AuditProjectionWorker({
      projectionId: 'checkpoint-timeline-v1', journal, projections,
    });

    expect(await worker.synchronize(ledger)).toEqual({ applied: 1, duplicates: 0 });
    await append(journal, second);
    expect(await worker.synchronize(ledger)).toEqual({ applied: 1, duplicates: 0 });
    expect(await worker.reconcile(ledger)).toEqual({
      status: 'verified', journalHead: await journal.getHead(ledger),
      projectionHead: await projections.getOffset('checkpoint-timeline-v1', ledger),
    });
    const before = await projections.read('checkpoint-timeline-v1', ledger);
    await worker.rebuild(ledger);
    expect(await projections.read('checkpoint-timeline-v1', ledger)).toEqual(before);
    expect(before[1]).toMatchObject({
      eventId: 'projection-event-1', eventType: 'tool.call.completed',
      correlationId: 'correlation-1', chainStatus: 'chained',
    });
  });

  it('reports pending lag and detects a projection head mismatch without changing the journal', async () => {
    const journal = new MemoryAuditJournal();
    const first = entry(0, null);
    await append(journal, first);
    const projections = new MemoryAuditProjectionProvider();
    const worker = new AuditProjectionWorker({ projectionId: 'timeline', journal, projections });
    expect((await worker.reconcile(ledger)).status).toBe('pending');
    await worker.synchronize(ledger);
    projections.corruptOffsetForTesting('timeline', ledger, {
      sequence: '0', entryDigest: digest('f'),
    });
    expect((await worker.reconcile(ledger)).status).toBe('gap_detected');
    expect((await journal.getHead(ledger))?.entryDigest).toBe(first.entryDigest);
  });

  it('distinguishes empty, lagging, orphaned, and ahead projection states', async () => {
    const journal = new MemoryAuditJournal();
    const projections = new MemoryAuditProjectionProvider();
    const worker = new AuditProjectionWorker({ projectionId: 'timeline', journal, projections });
    expect((await worker.reconcile(ledger)).status).toBe('empty');

    projections.corruptOffsetForTesting('timeline', ledger, {
      sequence: '0', entryDigest: digest('e'),
    });
    expect((await worker.reconcile(ledger)).status).toBe('gap_detected');
    await projections.reset('timeline', ledger);

    const first = entry(0, null);
    const second = entry(1, first.entryDigest);
    await append(journal, first);
    await append(journal, second);
    await worker.synchronize(ledger);
    projections.corruptOffsetForTesting('timeline', ledger, {
      sequence: '0', entryDigest: first.entryDigest,
    });
    expect((await worker.reconcile(ledger)).status).toBe('pending');
    projections.corruptOffsetForTesting('timeline', ledger, {
      sequence: '2', entryDigest: digest('f'),
    });
    expect((await worker.reconcile(ledger)).status).toBe('gap_detected');
  });

  it('never verifies or extends a projection whose prefix is not on the journal chain', async () => {
    const genesis = entry(0, null);
    const forked = { ...entry(1, genesis.entryDigest), entryDigest: digest('c') };
    const forkedJournal = new MemoryAuditJournal();
    await append(forkedJournal, genesis);
    await append(forkedJournal, forked);
    const projections = new MemoryAuditProjectionProvider();
    await new AuditProjectionWorker({
      projectionId: 'timeline', journal: forkedJournal, projections,
    }).synchronize(ledger);

    const authoritative = new MemoryAuditJournal();
    const one = entry(1, genesis.entryDigest);
    await append(authoritative, genesis);
    await append(authoritative, one);
    await append(authoritative, entry(2, one.entryDigest));
    const worker = new AuditProjectionWorker({
      projectionId: 'timeline', journal: authoritative, projections,
    });

    // Behind is not "pending" when the projected sequence-1 digest is foreign.
    expect((await worker.reconcile(ledger)).status).toBe('gap_detected');
    await expect(worker.synchronize(ledger)).rejects.toMatchObject({
      code: 'AUDIT_PROJECTION_CONFLICT',
    });
    expect(await projections.read('timeline', ledger)).toHaveLength(2);
    await worker.rebuild(ledger);
    expect((await worker.reconcile(ledger)).status).toBe('verified');
  });

  it('never reports a lagging projection pending when the journal cannot show its offset', async () => {
    const journal = new MemoryAuditJournal();
    const first = entry(0, null);
    const second = entry(1, first.entryDigest);
    await append(journal, first);
    await append(journal, second);
    await append(journal, entry(2, second.entryDigest));
    const projections = new MemoryAuditProjectionProvider();
    projections.corruptOffsetForTesting('timeline', ledger, {
      sequence: '1', entryDigest: second.entryDigest,
    });
    const reconcileAgainst = (readRange: AuditJournalProvider['readRange']) =>
      new AuditProjectionWorker({
        projectionId: 'timeline', projections, journal: { ...passthrough(journal), readRange },
      }).reconcile(ledger);

    // A lagging replica that returns nothing at the offset, and one that
    // returns a different sequence there, both leave the prefix unproven.
    expect((await reconcileAgainst(async function* () {})).status).toBe('gap_detected');
    expect((await reconcileAgainst(async function* () { yield first; })).status)
      .toBe('gap_detected');
    expect((await reconcileAgainst((query) => journal.readRange(query))).status).toBe('pending');
  });

  it('counts entries another worker applied as duplicates and fails when the offset moves', async () => {
    const journal = new MemoryAuditJournal();
    const first = entry(0, null);
    await append(journal, first);
    await append(journal, entry(1, first.entryDigest));
    const projections = new MemoryAuditProjectionProvider();
    await new AuditProjectionWorker({ projectionId: 'timeline', journal, projections })
      .synchronize(ledger);

    // A worker that read the offset before the other one applied anything.
    const stale: AuditProjectionProvider = {
      capabilities: projections.capabilities,
      getOffset: async () => null,
      compareAndApply: (input) => projections.compareAndApply(input),
      reset: (projectionId, input) => projections.reset(projectionId, input),
      read: (projectionId, input) => projections.read(projectionId, input),
    };
    await expect(new AuditProjectionWorker({
      projectionId: 'timeline', journal, projections: stale,
    }).synchronize(ledger)).resolves.toEqual({ applied: 0, duplicates: 2 });

    // A concurrent rebuild resets the offset between this worker's read and apply.
    const resetting: AuditProjectionProvider = {
      ...stale,
      getOffset: (projectionId, input) => projections.getOffset(projectionId, input),
      compareAndApply: async (input) => {
        await projections.reset(input.projectionId, input.ledger);
        return projections.compareAndApply(input);
      },
    };
    await append(journal, entry(2, digest('2')));
    await expect(new AuditProjectionWorker({
      projectionId: 'timeline', journal, projections: resetting,
    }).synchronize(ledger)).rejects.toMatchObject({
      code: 'AUDIT_PROJECTION_CONFLICT',
      details: { actualOffset: null },
    });
  });

  it('enforces projection identity, offset CAS, sequence order, and duplicate semantics', async () => {
    const journal = new MemoryAuditJournal();
    const projections = new MemoryAuditProjectionProvider();
    expect(() => new AuditProjectionWorker({
      projectionId: '', journal, projections,
    })).toThrow(/Projection ID is required/);

    const first = entry(0, null);
    await append(journal, first);
    const worker = new AuditProjectionWorker({ projectionId: 'timeline', journal, projections });
    await worker.synchronize(ledger);
    const [record] = await projections.read('timeline', ledger);
    expect(record).toBeDefined();

    await expect(projections.compareAndApply({
      projectionId: 'timeline', ledger,
      expectedOffset: await projections.getOffset('timeline', ledger),
      entry: first, record: record!,
    })).resolves.toEqual({ kind: 'duplicate' });

    const conflicting = structuredClone(first);
    conflicting.entryDigest = digest('f');
    await expect(projections.compareAndApply({
      projectionId: 'timeline', ledger,
      expectedOffset: await projections.getOffset('timeline', ledger),
      entry: conflicting, record: { ...record!, entryDigest: conflicting.entryDigest },
    })).resolves.toMatchObject({ kind: 'conflict' });

    const second = entry(1, first.entryDigest);
    await expect(projections.compareAndApply({
      projectionId: 'timeline', ledger, expectedOffset: null,
      entry: second, record: { ...record!, sequence: '1', entryDigest: second.entryDigest },
    })).resolves.toMatchObject({ kind: 'conflict' });

    const skipped = entry(2, first.entryDigest);
    await expect(projections.compareAndApply({
      projectionId: 'timeline', ledger,
      expectedOffset: await projections.getOffset('timeline', ledger),
      entry: skipped, record: { ...record!, sequence: '2', entryDigest: skipped.entryDigest },
    })).resolves.toMatchObject({ kind: 'conflict' });
  });
});
