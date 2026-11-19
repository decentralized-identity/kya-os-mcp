import { describe, expect, it } from 'vitest';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import type { AuditSignatureVerifier } from '../crypto.js';
import { AUDIT_ERROR_CODES } from '../errors.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { LocalAuditReadService } from '../read-service.js';
import { AuditRecorderService } from '../recorder-service.js';
import { createInMemoryReferenceRecorder, sampleAuditEvent } from '../reference-recorder.js';
import { verifyStoredAuditEntry } from '../stored-entry.js';
import type { AuditHead, SignedAuditEntryV1, SignerRef } from '../types.js';
import { producerEvent, tenantRef, TestSignatureVerifier, TestSigner } from './audit-fixtures.js';
import { hasher, ledger } from './observer-fixtures.js';
import { insert, unsignedEntryAfter } from './stored-entry-fixtures.js';

const submitter = { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef };
const signatures = new TestSignatureVerifier();

/** A recorder on `journal`; `verify: null` gives it no verifier. */
function recorderOn(journal: MemoryAuditJournal, verify: AuditSignatureVerifier | null = signatures) {
  return new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
    journal, signer: new TestSigner(), hasher, clock: { now: () => 1_750_000_001_000 },
    ...(verify === null ? {} : { signatures: verify }),
  });
}

function builderOn(journal: MemoryAuditJournal, verify: AuditSignatureVerifier | null = signatures) {
  const store = new MemoryAuditCheckpointStore();
  const builder = new AuditCheckpointBuilder({
    journal, store, signer: new TestSigner(), hasher, clock: { now: () => 1_750_000_002_000 },
    ...(verify === null ? {} : { signatures: verify }),
  });
  return { builder, store };
}

async function record(recorder: AuditRecorderService, id: string, sequence: number) {
  return recorder.submitAuthenticated(
    { ledgerId: ledger.ledgerId, producerEvent: producerEvent(id, sequence), encryptedEvidence: [] },
    submitter,
  );
}

describe('a stored entry the recorder did not sign', () => {
  it('is not chained to by a recorder given its signature verifier', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = recorderOn(journal);
    await record(recorder, 'evt_1', 1);
    const forged = await unsignedEntryAfter((await journal.getHead(ledger))!);
    await insert(journal, forged, '9');

    await expect(record(recorder, 'evt_2', 2)).rejects.toMatchObject({
      code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      details: { sequence: forged.core.sequence },
    });
    expect((await journal.getHead(ledger))?.entryDigest).toBe(forged.entryDigest);
  });

  it('is not covered by a checkpoint from a builder given the verifier, nor proved included', async () => {
    const journal = new MemoryAuditJournal();
    await record(recorderOn(journal), 'evt_1', 1);
    const forged = await unsignedEntryAfter((await journal.getHead(ledger))!);
    await insert(journal, forged, '9');
    const { builder, store } = builderOn(journal);

    await expect(builder.createCheckpoint(ledger)).rejects.toMatchObject({
      code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      details: { sequence: forged.core.sequence },
    });
    expect(await store.getLatest(ledger)).toBeNull();
    await expect(new LocalAuditReadService({ journal, checkpoints: { builder, store } })
      .getInclusionProof({ ...ledger, sequence: forged.core.sequence })).rejects.toThrow();
  });

  it('is found by the builder among the leaves after a checkpoint it signed', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = recorderOn(journal);
    await record(recorder, 'evt_1', 1);
    const { builder } = builderOn(journal);
    await builder.createCheckpoint(ledger);
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!), '9');

    await expect(builder.createCheckpoint(ledger))
      .rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, details: { sequence: '2' } });
  });

  it('is found by a builder that did not sign the checkpoint below it', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = recorderOn(journal);
    await record(recorder, 'evt_1', 1);
    // Written below a checkpoint signed by a builder that trusted the journal as written.
    const forged = await unsignedEntryAfter((await journal.getHead(ledger))!);
    await insert(journal, forged, '9');
    const shared = new MemoryAuditCheckpointStore();
    await new AuditCheckpointBuilder({
      journal, store: shared, signer: new TestSigner(), hasher, clock: { now: () => 1 },
    }).createCheckpoint(ledger);
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { jws: 'x' }), '8');

    const checking = new AuditCheckpointBuilder({
      journal, store: shared, signer: new TestSigner(), hasher, clock: { now: () => 2 }, signatures,
    });
    await expect(checking.createCheckpoint(ledger))
      .rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, details: { sequence: '2' } });
  });

  it('is refused whatever part of it was not made by this recorder', async () => {
    const otherRecorder: SignerRef = { did: 'did:key:zOther', kid: 'did:key:zOther#zOther', alg: 'EdDSA' };
    const acceptsAny: AuditSignatureVerifier = { verify: async () => true };
    const variants: Array<[string, (head: AuditHead) => Promise<SignedAuditEntryV1>]> = [
      ['a receipt signed by another trusted key', (head) => unsignedEntryAfter(head, { recorder: otherRecorder })],
      ['an entry of another ledger epoch', (head) => unsignedEntryAfter(head, {
        ledgerRef: { ...ledger, ledgerEpochId: 'epoch_0' },
      })],
      ['a core changed after it was digested', async (head) => {
        const entry = await unsignedEntryAfter(head);
        return { ...entry, core: { ...entry.core, recordedAt: entry.core.recordedAt + 1 } };
      }],
      ['an evidence-manifest digest that is not its event\'s, under an entry digest and receipt made for it', (head) =>
        unsignedEntryAfter(head, { evidenceManifestDigest: `sha256:${'6'.repeat(64)}` })],
      ['a receipt core that is not the one built for its entry', async (head) => {
        const entry = await unsignedEntryAfter(head);
        return { ...entry, recorderReceipt: { ...entry.recorderReceipt, core: { ...entry.recorderReceipt.core, eventId: 'other' } } };
      }],
    ];
    for (const [name, build] of variants) {
      const journal = new MemoryAuditJournal();
      const recorder = recorderOn(journal, acceptsAny);
      await record(recorder, 'evt_1', 1);
      await insert(journal, await build((await journal.getHead(ledger))!), '9');
      await expect(record(recorder, 'evt_2', 2), name)
        .rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE });
    }
  });

  it('is not covered by a checkpoint when it does not chain to the leaf before it', async () => {
    const journal = new MemoryAuditJournal();
    await record(recorderOn(journal), 'evt_1', 1);
    const head = (await journal.getHead(ledger))!;
    await insert(journal, await unsignedEntryAfter(head, { previousEntryDigest: `sha256:${'7'.repeat(64)}` }), '9');
    const acceptsAny: AuditSignatureVerifier = { verify: async () => true };

    await expect(builderOn(journal, acceptsAny).builder.createCheckpoint(ledger))
      .rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, details: { sequence: '2' } });
  });

  it('is refused when the journal cannot return the entry its head names', async () => {
    const journal = new MemoryAuditJournal();
    await record(recorderOn(journal), 'evt_1', 1);
    const head = (await journal.getHead(ledger))!;
    const variants: Array<[string, Partial<MemoryAuditJournal>]> = [
      ['a head whose digest is not the stored entry\'s', {
        getHead: async () => ({ ...head, entryDigest: `sha256:${'6'.repeat(64)}` }),
      }],
      ['a range that skips the head entry', {
        readRange: async function* (query) {
          for await (const entry of journal.readRange(query)) {
            if (entry.core.sequence !== head.sequence) yield entry;
          }
        },
      }],
      ['a range that ignores where it should start', {
        readRange: (query) => journal.readRange({ ledgerId: query.ledgerId, ledgerEpochId: query.ledgerEpochId }),
      }],
    ];
    for (const [name, overrides] of variants) {
      const wrapped = Object.assign(Object.create(journal) as MemoryAuditJournal, overrides);
      await expect(record(recorderOn(wrapped), 'evt_2', 2), name)
        .rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE, details: { sequence: '1' } });
    }
  });

  it('is reported with its cause when the verifier itself fails', async () => {
    const journal = new MemoryAuditJournal();
    await record(recorderOn(journal), 'evt_1', 1);
    const failing: AuditSignatureVerifier = { verify: async () => { throw new Error('key service down'); } };
    const failure = await record(recorderOn(journal, failing), 'evt_2', 2).catch((error: unknown) => error);
    expect(failure).toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE });
    expect((failure as Error).cause).toMatchObject({ message: 'key service down' });
    const builderFailure = await builderOn(journal, failing).builder.createCheckpoint(ledger)
      .catch((error: unknown) => error);
    expect(builderFailure).toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE });
    expect((builderFailure as Error).cause).toMatchObject({ message: 'key service down' });
  });
});

describe('a journal the recorder signed', () => {
  it('is extended by a new recorder process, a replica, and checkpointed again and again', async () => {
    const journal = new MemoryAuditJournal();
    await record(recorderOn(journal), 'evt_1', 1);
    // A restarted or second process: the head was not appended by this instance.
    const replica = recorderOn(journal);
    await record(replica, 'evt_2', 2);
    await record(replica, 'evt_3', 3);
    await record(recorderOn(journal), 'evt_4', 4);
    const { builder } = builderOn(journal);
    expect((await builder.createCheckpoint(ledger)).core.treeSize).toBe('5');
    await record(replica, 'evt_5', 5);
    expect((await builder.createCheckpoint(ledger)).core.treeSize).toBe('6');
    expect((await builderOn(journal).builder.createCheckpoint(ledger)).core.treeSize).toBe('6');
  });

  it('is extended from its genesis by a process that did not write it', async () => {
    const journal = new MemoryAuditJournal();
    // A first submission writes the genesis, then fails on evidence the recorder has no store for.
    const first = await recorderOn(journal).submitAuthenticated({
      ledgerId: ledger.ledgerId, producerEvent: producerEvent('evt_1', 1),
      encryptedEvidence: [{ ref: { objectId: 'evi_1' } as never, ciphertext: new Uint8Array() }],
    }, submitter).catch((error: unknown) => error);
    expect(first).toMatchObject({ code: AUDIT_ERROR_CODES.EVIDENCE_FAILURE });
    expect((await journal.getHead(ledger))?.sequence).toBe('0');

    await expect(record(recorderOn(journal), 'evt_1', 1)).resolves.toMatchObject({ core: { sequence: '1' } });
  });

  it('is still trusted as written by a recorder and builder given no verifier', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = recorderOn(journal, null);
    await record(recorder, 'evt_1', 1);
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!), '9');
    await expect(record(recorder, 'evt_2', 2)).resolves.toMatchObject({ core: { sequence: '3' } });
    await expect(builderOn(journal, null).builder.createCheckpoint(ledger))
      .resolves.toMatchObject({ core: { treeSize: '4' } });
  });

  it('verifies as stored, entry by entry', async () => {
    const journal = new MemoryAuditJournal();
    await record(recorderOn(journal), 'evt_1', 1);
    const entries = await journal.snapshot(ledger);
    for (const entry of entries) {
      await expect(verifyStoredAuditEntry(entry, ledger, { hasher, signatures })).resolves.toBe(true);
    }
    const entry = entries[1]!;
    const other = `sha256:${'5'.repeat(64)}` as const;
    for (const changed of [
      { ...entry, eventDigest: other },
      { ...entry, core: { ...entry.core, eventDigest: other } },
      { ...entry, core: { ...entry.core, evidenceManifestDigest: other } },
      { ...entry, entryDigest: other },
      { ...entry, recorderReceipt: { ...entry.recorderReceipt, jws: 'x' } },
    ]) {
      await expect(verifyStoredAuditEntry(changed, ledger, { hasher, signatures })).resolves.toBe(false);
    }
  });
});

describe('the reference recorder', () => {
  it('refuses to extend or checkpoint an entry its journal holds unsigned', async () => {
    const reference = await createInMemoryReferenceRecorder({ clock: { now: () => 1_750_000_001_000 } });
    await reference.submit(sampleAuditEvent(1));
    // The reference recorder keeps its journal to itself; its read service holds the same one.
    const journal = (reference.read as unknown as { journal: MemoryAuditJournal }).journal;
    const head = (await journal.getHead(reference.ledger))!;
    const forged = await unsignedEntryAfter(head, { recorder: reference.signerRef, ledgerRef: reference.ledger });
    await journal.compareAndAppend({
      ledger: reference.ledger, expectedHead: head, entry: forged, idempotencyKey: `sha256:${'9'.repeat(64)}`,
    });
    await expect(reference.submit(sampleAuditEvent(2))).rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE });
    await expect(reference.checkpoint()).rejects.toMatchObject({ code: AUDIT_ERROR_CODES.JOURNAL_FAILURE });
  });
});
