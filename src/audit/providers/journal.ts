import type { AuditHead, AuditLedgerRef, Digest, SignedAuditEntryV1 } from '../types.js';

export type AuditAppendResult =
  | { kind: 'appended'; entry: SignedAuditEntryV1 }
  | { kind: 'duplicate'; entry: SignedAuditEntryV1 }
  | { kind: 'head_conflict'; actualHead: AuditHead | null }
  | { kind: 'idempotency_conflict'; existing: SignedAuditEntryV1 };

export interface AuditRangeQuery extends AuditLedgerRef {
  afterSequence?: string;
  limit?: number;
}

export interface AuditJournalProvider {
  readonly capabilities: {
    durability: 'ephemeral' | 'durable';
    atomicAppend: true;
    orderedRead: true;
  };

  getHead(ledger: AuditLedgerRef): Promise<AuditHead | null>;
  getByIdempotencyKey(ledgerId: string, idempotencyKey: Digest): Promise<SignedAuditEntryV1 | null>;
  compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntryV1;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult>;
  readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntryV1>;
}
