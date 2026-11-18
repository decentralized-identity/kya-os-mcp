/**
 * Two events refuse a checkpoint with `AUDIT_CHECKPOINT_CONFLICT`: a lost race, where another
 * signer stored a checkpoint over the same tree first, and a fork, where two signed views of the
 * ledger disagree. The first is benign and the second is a security event. These tests produce
 * each through the recorder, journal, builder and store a deployment runs, and check that a
 * consumer tells them apart without reading the message.
 */

import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import {
  AuditCheckpointBuilder,
  MemoryAuditCheckpointStore,
  type AuditCheckpointStore,
} from '../checkpoint.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import {
  AUDIT_CHECKPOINT_CONFLICT_REASONS,
  AUDIT_ERROR_CODES,
  AuditProtocolError,
  isLostCheckpointRace,
} from '../errors.js';
import type { AuditJournalProvider } from '../providers/journal.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { SignedAuditCheckpointV1 } from '../types.js';
import { producerEvent, tenantRef, TestSigner } from './audit-fixtures.js';

const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
const LOST_RACE_MESSAGE = 'A different checkpoint already exists at this tree size';
const FORKED_JOURNAL_MESSAGE = 'Journal content forked at or below the latest checkpointed tree size';

/** A journal one recorder has recorded `eventIds` into, after its genesis. */
async function recordedJournal(eventIds: readonly string[]): Promise<MemoryAuditJournal> {
  const journal = new MemoryAuditJournal();
  const recorder = new AuditRecorderService({
    ...ledger,
    tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1',
    journal,
    signer: new TestSigner(),
    hasher,
    clock: { now: () => 1_750_000_001_000 },
  });
  for (const [index, eventId] of eventIds.entries()) {
    await recorder.submitAuthenticated({
      ledgerId: ledger.ledgerId,
      producerEvent: producerEvent(eventId, index + 1),
      encryptedEvidence: [],
    }, { producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef });
  }
  return journal;
}

/** One signer process: a checkpoint builder over its journal and the shared store. */
function signerProcess(
  journal: AuditJournalProvider,
  store: AuditCheckpointStore,
  now: number,
): AuditCheckpointBuilder {
  return new AuditCheckpointBuilder({
    journal, store, signer: new TestSigner(), hasher, clock: { now: () => now },
  });
}

/**
 * The store two signer processes share, as each sees it while they race: both read the latest
 * checkpoint before either stores one.
 */
function racedStore(inner: AuditCheckpointStore): AuditCheckpointStore {
  let readers = 0;
  let bothRead!: () => void;
  const ready = new Promise<void>((resolve) => { bothRead = resolve; });
  return {
    getByTreeSize: (input, treeSize) => inner.getByTreeSize(input, treeSize),
    putIfAbsent: (checkpoint) => inner.putIfAbsent(checkpoint),
    async getLatest(input) {
      const latest = await inner.getLatest(input);
      readers += 1;
      if (readers === 2) bothRead();
      await ready;
      return latest;
    },
  };
}

/** Two signer processes checkpoint at once, one over each journal; one of them stores first. */
async function race(journals: readonly [AuditJournalProvider, AuditJournalProvider]): Promise<{
  error: AuditProtocolError;
  stored: SignedAuditCheckpointV1;
  loser: AuditCheckpointBuilder;
  store: AuditCheckpointStore;
}> {
  const inner = new MemoryAuditCheckpointStore();
  const store = racedStore(inner);
  const builders = journals.map((journal, index) =>
    signerProcess(journal, store, 1_750_000_002_000 + index));
  const settled = await Promise.allSettled(
    builders.map((builder) => builder.createCheckpoint(ledger)),
  );
  const lost = settled.findIndex((result) => result.status === 'rejected');
  const won = settled.find((result) => result.status === 'fulfilled');
  if (lost < 0 || won === undefined) throw new Error('expected one signer to win and one to lose');
  const { reason } = settled[lost] as PromiseRejectedResult;
  expect(reason).toBeInstanceOf(AuditProtocolError);
  return { error: reason as AuditProtocolError, stored: won.value, loser: builders[lost]!, store: inner };
}

/**
 * A journal restored from a backup taken after `evt_1`, then written to again, under a store
 * that holds a checkpoint over the journal as it was before.
 */
async function forkedJournal(): Promise<{
  error: AuditProtocolError;
  signed: SignedAuditCheckpointV1;
  store: AuditCheckpointStore;
}> {
  const store = new MemoryAuditCheckpointStore();
  const original = await recordedJournal(['evt_1', 'evt_2', 'evt_3']);
  const signed = await signerProcess(original, store, 1_750_000_002_000).createCheckpoint(ledger);
  const restored = await recordedJournal(['evt_1', 'evt_2b', 'evt_3b', 'evt_4b']);
  const error = await signerProcess(restored, store, 1_750_000_003_000).createCheckpoint(ledger)
    .then(() => { throw new Error('expected the forked journal to be refused'); }, (e: unknown) => e);
  expect(error).toBeInstanceOf(AuditProtocolError);
  return { error: error as AuditProtocolError, signed, store };
}

describe('checkpoint conflicts', () => {
  it('tells a lost race from a forked journal by code and details alone', async () => {
    const journal = await recordedJournal(['evt_1', 'evt_2', 'evt_3']);
    const { error: lost } = await race([journal, journal]);
    const { error: forked } = await forkedJournal();

    // Both refuse at tree size 4, with the code a consumer already handles.
    expect(lost).toMatchObject({
      code: AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT, details: { treeSize: '4' },
    });
    expect(forked).toMatchObject({
      code: AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT, details: { treeSize: '4' },
    });
    expect({ code: lost.code, details: lost.details })
      .not.toEqual({ code: forked.code, details: forked.details });
  });

  it('names a lost race, and a retry returns the checkpoint the other signer stored', async () => {
    const journal = await recordedJournal(['evt_1', 'evt_2', 'evt_3']);
    const { error, stored, loser, store } = await race([journal, journal]);

    expect(error.message).toBe(LOST_RACE_MESSAGE);
    expect(error.details).toEqual({ treeSize: '4', reason: 'lost-race' });
    expect(isLostCheckpointRace(error)).toBe(true);
    await expect(loser.createCheckpoint(ledger)).resolves.toEqual(stored);
    await expect(store.getLatest(ledger)).resolves.toEqual(stored);
  });

  it('names a journal rewritten under a stored checkpoint a fork, and signs nothing over it', async () => {
    const { error, signed, store } = await forkedJournal();

    expect(error.message).toBe(FORKED_JOURNAL_MESSAGE);
    expect(error.details).toEqual({ treeSize: '4', reason: 'fork' });
    expect(isLostCheckpointRace(error)).toBe(false);
    await expect(store.getLatest(ledger)).resolves.toEqual(signed);
  });

  it('names a fork when another signer stored a checkpoint over another tree at that size', async () => {
    // Two copies of the journal that diverged after evt_1, each the same size.
    const { error, stored, store } = await race([
      await recordedJournal(['evt_1', 'evt_2', 'evt_3']),
      await recordedJournal(['evt_1', 'evt_2b', 'evt_3b']),
    ]);

    expect(error.details).toEqual({ treeSize: '4', reason: 'fork' });
    expect(isLostCheckpointRace(error)).toBe(false);
    // Code that matches the lost-race message no longer takes this fork for one.
    expect(error.message).not.toBe(LOST_RACE_MESSAGE);
    await expect(store.getLatest(ledger)).resolves.toEqual(stored);
  });
});

describe('isLostCheckpointRace', () => {
  const conflict = (details?: Record<string, unknown>) =>
    new AuditProtocolError(AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT, 'conflict', details);

  it('lists the closed set of conflict reasons', () => {
    expect(AUDIT_CHECKPOINT_CONFLICT_REASONS).toEqual({ LOST_RACE: 'lost-race', FORK: 'fork' });
  });

  it('accepts only a checkpoint conflict that names a lost race', () => {
    expect(isLostCheckpointRace(conflict({ treeSize: '4', reason: 'lost-race' }))).toBe(true);
  });

  it('reads every other conflict as a fork, a reason it does not know and none included', () => {
    expect(isLostCheckpointRace(conflict({ treeSize: '4', reason: 'fork' }))).toBe(false);
    expect(isLostCheckpointRace(conflict({ treeSize: '4', reason: 'a-reason-added-later' })))
      .toBe(false);
    // As an observer of your own, or a release before reasons, may throw it.
    expect(isLostCheckpointRace(conflict({ treeSize: '4' }))).toBe(false);
    expect(isLostCheckpointRace(conflict())).toBe(false);
  });

  it('accepts no other error, nor an object that only looks like one', () => {
    expect(isLostCheckpointRace(new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'journal', { reason: 'lost-race' },
    ))).toBe(false);
    expect(isLostCheckpointRace({
      code: AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT, details: { reason: 'lost-race' },
    })).toBe(false);
    expect(isLostCheckpointRace(new Error(LOST_RACE_MESSAGE))).toBe(false);
    expect(isLostCheckpointRace(undefined)).toBe(false);
  });
});
