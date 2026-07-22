import type { AuditAppendResult, AuditJournalProvider, AuditRangeQuery } from './journal.js';
import type { AuditHead, AuditLedgerRef, Digest, SignedAuditEntryV1 } from '../types.js';

function ledgerKey(ledger: AuditLedgerRef): string {
  return `${ledger.ledgerId}\0${ledger.ledgerEpochId}`;
}

function idempotencyKey(ledgerId: string, key: Digest): string {
  return `${ledgerId}\0${key}`;
}

function headsEqual(left: AuditHead | null, right: AuditHead | null): boolean {
  if (left === null || right === null) return left === right;
  return left.ledgerId === right.ledgerId &&
    left.ledgerEpochId === right.ledgerEpochId &&
    left.sequence === right.sequence &&
    left.entryDigest === right.entryDigest;
}

/** Ephemeral reference journal with the same atomic contract as durable adapters. */
export class MemoryAuditJournal implements AuditJournalProvider {
  readonly capabilities = {
    durability: 'ephemeral' as const,
    atomicAppend: true as const,
    orderedRead: true as const,
  };

  private readonly entriesByLedger = new Map<string, SignedAuditEntryV1[]>();
  private readonly entriesByIdempotency = new Map<string, SignedAuditEntryV1>();
  private readonly heads = new Map<string, AuditHead>();

  async getHead(ledger: AuditLedgerRef): Promise<AuditHead | null> {
    return this.heads.get(ledgerKey(ledger)) ?? null;
  }

  async getByIdempotencyKey(
    ledgerId: string,
    key: Digest,
  ): Promise<SignedAuditEntryV1 | null> {
    return this.entriesByIdempotency.get(idempotencyKey(ledgerId, key)) ?? null;
  }

  async compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntryV1;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult> {
    const idKey = idempotencyKey(input.ledger.ledgerId, input.idempotencyKey);
    const existing = this.entriesByIdempotency.get(idKey);
    if (existing !== undefined) {
      return existing.eventDigest === input.entry.eventDigest
        ? { kind: 'duplicate', entry: existing }
        : { kind: 'idempotency_conflict', existing };
    }

    const key = ledgerKey(input.ledger);
    const actualHead = this.heads.get(key) ?? null;
    if (!headsEqual(input.expectedHead, actualHead)) {
      return { kind: 'head_conflict', actualHead };
    }

    const entries = this.entriesByLedger.get(key) ?? [];
    entries.push(input.entry);
    this.entriesByLedger.set(key, entries);
    this.entriesByIdempotency.set(idKey, input.entry);
    this.heads.set(key, {
      ledgerId: input.ledger.ledgerId,
      ledgerEpochId: input.ledger.ledgerEpochId,
      sequence: input.entry.core.sequence,
      entryDigest: input.entry.entryDigest,
    });
    return { kind: 'appended', entry: input.entry };
  }

  async *readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntryV1> {
    const snapshot = await this.snapshot(query);
    const after = query.afterSequence === undefined ? null : BigInt(query.afterSequence);
    let yielded = 0;
    for (const entry of snapshot) {
      if (after !== null && BigInt(entry.core.sequence) <= after) continue;
      if (query.limit !== undefined && yielded >= query.limit) return;
      yielded += 1;
      yield entry;
    }
  }

  async snapshot(ledger: AuditLedgerRef): Promise<SignedAuditEntryV1[]> {
    return [...(this.entriesByLedger.get(ledgerKey(ledger)) ?? [])];
  }
}
