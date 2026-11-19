import { describe, expect, it } from 'vitest';
import type {
  AuditAppendResult,
  AuditJournalProvider,
  AuditRangeQuery,
} from '../providers/journal.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { evaluateAuditJournalProviderContract } from '../testing/provider-contracts.js';
import type { AuditHead, AuditLedgerRef, Digest, SignedAuditEntryV1 } from '../types.js';

const concurrentCheck = 'commits exactly one of several concurrent appends on one expected head';
const staleCheck = 'rejects an expected head that is no longer the head';

interface FlawedJournalOptions {
  /** What the journal awaits between comparing the head and inserting, as two statements would. */
  between?: () => Promise<void>;
  /** Compare only the sequence of the expected head, never its digest. */
  sequenceOnly?: boolean;
  /** Throw, without committing, instead of reporting a lost compare-and-append. */
  throwOnConflict?: boolean;
}

/**
 * A journal written the way an adapter might be over a key-value store or two SQL statements:
 * idempotency, epoch scoping and ordered snapshot reads are right, and the compare-and-append is
 * as the options make it.
 */
class FlawedJournal implements AuditJournalProvider {
  readonly capabilities = {
    durability: 'durable' as const,
    atomicAppend: true as const,
    orderedRead: true as const,
  };
  private readonly rows = new Map<string, SignedAuditEntryV1[]>();
  private readonly byIdempotencyKey = new Map<string, SignedAuditEntryV1>();

  constructor(private readonly options: FlawedJournalOptions = {}) {}

  private key(ledger: AuditLedgerRef): string {
    return `${ledger.ledgerId}\0${ledger.ledgerEpochId}`;
  }

  async getHead(ledger: AuditLedgerRef): Promise<AuditHead | null> {
    const last = (this.rows.get(this.key(ledger)) ?? []).at(-1);
    return last === undefined
      ? null
      : {
          ledgerId: ledger.ledgerId,
          ledgerEpochId: ledger.ledgerEpochId,
          sequence: last.core.sequence,
          entryDigest: last.entryDigest,
        };
  }

  async getByIdempotencyKey(ledgerId: string, key: Digest): Promise<SignedAuditEntryV1 | null> {
    return this.byIdempotencyKey.get(`${ledgerId}\0${key}`) ?? null;
  }

  async compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntryV1;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult> {
    const idempotencyKey = `${input.ledger.ledgerId}\0${input.idempotencyKey}`;
    const existing = this.byIdempotencyKey.get(idempotencyKey);
    if (existing !== undefined) {
      return existing.eventDigest === input.entry.eventDigest
        ? { kind: 'duplicate', entry: existing }
        : { kind: 'idempotency_conflict', existing };
    }
    const actualHead = await this.getHead(input.ledger);
    const expected = input.expectedHead;
    const same = actualHead === null || expected === null
      ? actualHead === expected
      : actualHead.sequence === expected.sequence &&
        (this.options.sequenceOnly === true || actualHead.entryDigest === expected.entryDigest);
    if (!same) {
      if (this.options.throwOnConflict === true) throw new Error('serialization failure');
      return { kind: 'head_conflict', actualHead };
    }
    await this.options.between?.();
    const rows = this.rows.get(this.key(input.ledger)) ?? [];
    rows.push(input.entry);
    this.rows.set(this.key(input.ledger), rows);
    this.byIdempotencyKey.set(idempotencyKey, input.entry);
    return { kind: 'appended', entry: input.entry };
  }

  async *readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntryV1> {
    const snapshot = [...(this.rows.get(this.key(query)) ?? [])];
    const after = query.afterSequence === undefined ? null : BigInt(query.afterSequence);
    let yielded = 0;
    for (const entry of snapshot) {
      if (after !== null && BigInt(entry.core.sequence) <= after) continue;
      if (query.limit !== undefined && yielded >= query.limit) return;
      yielded += 1;
      yield entry;
    }
  }
}

/** A journal that serializes its compare-and-append, and answers a lost one with `throws`. */
class SerializedJournal extends FlawedJournal {
  private turn: Promise<unknown> = Promise.resolve();

  override compareAndAppend(
    input: Parameters<FlawedJournal['compareAndAppend']>[0],
  ): Promise<AuditAppendResult> {
    const result = this.turn.then(() => super.compareAndAppend(input));
    this.turn = result.catch(() => undefined);
    return result;
  }
}

function checkOf(report: Awaited<ReturnType<typeof evaluateAuditJournalProviderContract>>, name: string) {
  return report.checks.find((item) => item.name === name);
}

describe('journal provider contract: compare-and-append', () => {
  it('passes the memory journal on every check', async () => {
    const report = await evaluateAuditJournalProviderContract(() => new MemoryAuditJournal());
    expect(report.checks.map((item) => [item.name, item.passed]))
      .toContainEqual([concurrentCheck, true]);
    expect(report.checks.map((item) => [item.name, item.passed]))
      .toContainEqual([staleCheck, true]);
    expect(report.passed).toBe(true);
  });

  it('fails a journal that compares and inserts in two steps with a round trip between', async () => {
    const report = await evaluateAuditJournalProviderContract(() => new FlawedJournal({
      between: () => new Promise((resolve) => setTimeout(resolve, 1)),
    }));
    expect(report.passed).toBe(false);
    expect(checkOf(report, concurrentCheck)).toMatchObject({ passed: false });
    expect(String((checkOf(report, concurrentCheck)?.error as Error).message))
      .toMatch(/concurrent appends on one expected head were committed/);
  });

  it('fails a journal that awaits only its own head read between comparing and inserting', async () => {
    const report = await evaluateAuditJournalProviderContract(() => new FlawedJournal());
    expect(checkOf(report, concurrentCheck)).toMatchObject({ passed: false });
  });

  it('fails a journal that compares only the sequence of the expected head', async () => {
    const report = await evaluateAuditJournalProviderContract(
      () => new SerializedJournal({ sequenceOnly: true }),
    );
    expect(checkOf(report, concurrentCheck)).toMatchObject({ passed: true });
    expect(checkOf(report, staleCheck)).toMatchObject({ passed: false });
    expect(report.passed).toBe(false);
  });

  it('passes a serialized journal that throws, without committing, on a lost append', async () => {
    const report = await evaluateAuditJournalProviderContract(
      () => new SerializedJournal({ throwOnConflict: true }),
    );
    expect(checkOf(report, concurrentCheck)).toMatchObject({ passed: true });
  });

  it('fails a journal whose losing append reports a head other than the winner', async () => {
    class StaleConflictJournal extends SerializedJournal {
      override async compareAndAppend(
        input: Parameters<FlawedJournal['compareAndAppend']>[0],
      ): Promise<AuditAppendResult> {
        const result = await super.compareAndAppend(input);
        return result.kind === 'head_conflict' ? { kind: 'head_conflict', actualHead: input.expectedHead } : result;
      }
    }
    const report = await evaluateAuditJournalProviderContract(() => new StaleConflictJournal());
    expect(checkOf(report, concurrentCheck)).toMatchObject({ passed: false });
    expect(checkOf(report, staleCheck)).toMatchObject({ passed: false });
  });

  it('fails a journal that commits an append it reports as lost', async () => {
    class CommitsLosersJournal extends SerializedJournal {
      private readonly inner = new FlawedJournal();
      override async compareAndAppend(
        input: Parameters<FlawedJournal['compareAndAppend']>[0],
      ): Promise<AuditAppendResult> {
        const result = await super.compareAndAppend(input);
        if (result.kind !== 'head_conflict') return result;
        // Writes the entry anyway, under the head the caller expected, and reports a conflict.
        await this.inner.compareAndAppend({ ...input, expectedHead: null });
        return result;
      }
      override async *readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntryV1> {
        yield* super.readRange(query);
        for await (const entry of this.inner.readRange(query)) {
          if (entry.core.sequence !== '0') yield entry;
        }
      }
    }
    const report = await evaluateAuditJournalProviderContract(() => new CommitsLosersJournal());
    expect(checkOf(report, concurrentCheck)).toMatchObject({ passed: false });
    expect(String((checkOf(report, concurrentCheck)?.error as Error).message))
      .toMatch(/more than one entry at one sequence/);
  });
});
