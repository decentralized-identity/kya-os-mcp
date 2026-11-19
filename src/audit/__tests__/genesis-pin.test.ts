/**
 * The genesis of a ledger epoch names the key a checkpoint builder holds every leaf to, and the
 * builder trusts the leaves as written when that key is not its own. A journal writer that could
 * rewrite the genesis core's `recorder` and keep its `entryDigest`, which the latest checkpoint's
 * root covers, would choose that key, and have a forged leaf checkpointed with only a warning. So
 * the builder recomputes the genesis digest on every run, and the digest of each leaf it trusts as
 * written: the checkpoint's root then pins the genesis key, and each leaf's core is the one its
 * digest was made from.
 */
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { logger } from '../../logging/index.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { AUDIT_ERROR_CODES } from '../errors.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import type { SignedAuditEntryV1, SignerRef } from '../types.js';
import { hasher, ledger } from './observer-fixtures.js';
import { builderWith, insert, jwkSigner, record, recorderWith, unsignedEntryAfter } from './stored-entry-fixtures.js';

const WARNED = Symbol.for('@kya-os/mcp/audit-unverified-recorder-keys');
const registry = globalThis as { [key: symbol]: unknown };

let warn: MockInstance<typeof logger.warn>;

beforeEach(() => {
  delete registry[WARNED];
  warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  delete registry[WARNED];
  vi.restoreAllMocks();
});

const claimed: SignerRef = { did: 'did:key:zElsewhere', kid: 'did:key:zElsewhere#k', alg: 'EdDSA' };

/** Rewrite, in the journal's store, the core of each entry `which` picks, keeping its digests. */
function rewrite(
  journal: MemoryAuditJournal,
  which: (index: number) => boolean,
  change: (entry: SignedAuditEntryV1) => SignedAuditEntryV1['core'],
): void {
  const stored = (journal as unknown as { entriesByLedger: Map<string, SignedAuditEntryV1[]> }).entriesByLedger;
  for (const entries of stored.values()) {
    entries.forEach((entry, index) => {
      if (which(index)) entries[index] = { ...entry, core: change(entry) };
    });
  }
}

const naming = (recorder: SignerRef) => (entry: SignedAuditEntryV1): SignedAuditEntryV1['core'] =>
  ({ ...entry.core, recorder });

/** The refusal of the stored entry at `sequence`. */
const refusedAt = (sequence: string) => ({
  code: AUDIT_ERROR_CODES.JOURNAL_FAILURE,
  message: 'Audit journal entry is not one its recorder signed',
  details: { sequence },
});

describe('a checkpoint builder over a genesis rewritten under its checkpointed digest', () => {
  it('refuses the genesis on its next run, and checkpoints no leaf forged under the key it names', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    const store = new MemoryAuditCheckpointStore();
    const builder = new AuditCheckpointBuilder({ journal, store, signer, hasher, clock: { now: () => 1_750_000_002_000 } });
    await expect(builder.createCheckpoint(ledger)).resolves.toMatchObject({ core: { treeSize: '2' } });

    rewrite(journal, (index) => index === 0, naming(claimed));
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: claimed }), '9');

    await expect(builder.createCheckpoint(ledger)).rejects.toMatchObject(refusedAt('0'));
    expect((await store.getLatest(ledger))?.core.treeSize).toBe('2');
    expect(warn).not.toHaveBeenCalled();
  });

  it('refuses it for a fresh builder over the stored checkpoint, with every recorder rewritten', async () => {
    const signer = await jwkSigner();
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, signer), 'evt_1', 1);
    const store = new MemoryAuditCheckpointStore();
    const fresh = () => new AuditCheckpointBuilder({ journal, store, signer, hasher, clock: { now: () => 1_750_000_002_000 } });
    await expect(fresh().createCheckpoint(ledger)).resolves.toMatchObject({ core: { treeSize: '2' } });

    rewrite(journal, () => true, naming(claimed));
    await insert(journal, await unsignedEntryAfter((await journal.getHead(ledger))!, { recorder: claimed }), '9');

    await expect(fresh().createCheckpoint(ledger)).rejects.toMatchObject(refusedAt('0'));
    expect((await store.getLatest(ledger))?.core.treeSize).toBe('2');
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('a checkpoint builder that trusts an epoch as written', () => {
  it('refuses a leaf whose core is not the one its digest was made from', async () => {
    const recorderKey = await jwkSigner('recorder');
    const journal = new MemoryAuditJournal();
    await record(recorderWith(journal, recorderKey), 'evt_1', 1);
    rewrite(journal, (index) => index === 1, (entry) => ({ ...entry.core, event: { ...entry.core.event, outcome: 'failed' } }));

    await expect(builderWith(journal, await jwkSigner('checkpoints')).createCheckpoint(ledger))
      .rejects.toMatchObject(refusedAt('1'));
  });
});
