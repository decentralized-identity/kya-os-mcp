import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type {
  AuditLedgerRef,
  AuditProducerEventCoreV1,
  Digest,
  SignedAuditEntryV1,
} from './types.js';

export interface AuditProjectionOffset {
  sequence: string;
  entryDigest: Digest;
}

export interface AuditTimelineProjectionV1 {
  ledgerId: string;
  ledgerEpochId: string;
  sequence: string;
  entryDigest: Digest;
  eventId: string;
  eventType: AuditProducerEventCoreV1['eventType'];
  occurredAt: number;
  recordedAt: number;
  outcome: AuditProducerEventCoreV1['outcome'];
  correlationId?: string;
  causationId?: string;
  chainStatus: 'chained';
}

export type AuditProjectionApplyResult =
  | { kind: 'applied' }
  | { kind: 'duplicate' }
  | { kind: 'conflict'; actualOffset: AuditProjectionOffset | null };

export interface AuditProjectionProvider {
  readonly capabilities: { durability: 'ephemeral' | 'durable'; atomicOffset: true };
  getOffset(projectionId: string, ledger: AuditLedgerRef): Promise<AuditProjectionOffset | null>;
  compareAndApply(input: {
    projectionId: string;
    ledger: AuditLedgerRef;
    expectedOffset: AuditProjectionOffset | null;
    entry: SignedAuditEntryV1;
    record: AuditTimelineProjectionV1;
  }): Promise<AuditProjectionApplyResult>;
  reset(projectionId: string, ledger: AuditLedgerRef): Promise<void>;
  read(projectionId: string, ledger: AuditLedgerRef): Promise<AuditTimelineProjectionV1[]>;
}

function key(projectionId: string, ledger: AuditLedgerRef): string {
  return `${projectionId}\0${ledger.ledgerId}\0${ledger.ledgerEpochId}`;
}

function offsetsEqual(
  left: AuditProjectionOffset | null,
  right: AuditProjectionOffset | null,
): boolean {
  if (left === null || right === null) return left === right;
  return left.sequence === right.sequence && left.entryDigest === right.entryDigest;
}

function project(entry: SignedAuditEntryV1): AuditTimelineProjectionV1 {
  const event = entry.core.event;
  return Object.freeze({
    ledgerId: entry.core.ledgerId,
    ledgerEpochId: entry.core.ledgerEpochId,
    sequence: entry.core.sequence,
    entryDigest: entry.entryDigest,
    eventId: event.eventId,
    eventType: event.eventType,
    occurredAt: event.occurredAt,
    recordedAt: entry.core.recordedAt,
    outcome: event.outcome,
    ...(event.correlationId === undefined ? {} : { correlationId: event.correlationId }),
    ...(event.causationId === undefined ? {} : { causationId: event.causationId }),
    chainStatus: 'chained' as const,
  });
}

/** Ephemeral reference projection. It is disposable and never an integrity authority. */
export class MemoryAuditProjectionProvider implements AuditProjectionProvider {
  readonly capabilities = { durability: 'ephemeral' as const, atomicOffset: true as const };
  private readonly offsets = new Map<string, AuditProjectionOffset>();
  private readonly records = new Map<string, AuditTimelineProjectionV1[]>();

  async getOffset(
    projectionId: string,
    ledger: AuditLedgerRef,
  ): Promise<AuditProjectionOffset | null> {
    const offset = this.offsets.get(key(projectionId, ledger));
    return offset === undefined ? null : { ...offset };
  }

  async compareAndApply(input: {
    projectionId: string;
    ledger: AuditLedgerRef;
    expectedOffset: AuditProjectionOffset | null;
    entry: SignedAuditEntryV1;
    record: AuditTimelineProjectionV1;
  }): Promise<AuditProjectionApplyResult> {
    const projectionKey = key(input.projectionId, input.ledger);
    const actualOffset = this.offsets.get(projectionKey) ?? null;
    const existing = this.records.get(projectionKey)?.find((record) =>
      record.sequence === input.entry.core.sequence);
    if (existing !== undefined) {
      return existing.entryDigest === input.entry.entryDigest
        ? { kind: 'duplicate' }
        : { kind: 'conflict', actualOffset };
    }
    if (!offsetsEqual(actualOffset, input.expectedOffset)) {
      return { kind: 'conflict', actualOffset };
    }
    const expectedSequence = actualOffset === null ? 0n : BigInt(actualOffset.sequence) + 1n;
    if (BigInt(input.entry.core.sequence) !== expectedSequence) {
      return { kind: 'conflict', actualOffset };
    }
    const records = this.records.get(projectionKey) ?? [];
    records.push(Object.freeze({ ...input.record }));
    this.records.set(projectionKey, records);
    this.offsets.set(projectionKey, {
      sequence: input.entry.core.sequence,
      entryDigest: input.entry.entryDigest,
    });
    return { kind: 'applied' };
  }

  async reset(projectionId: string, ledger: AuditLedgerRef): Promise<void> {
    const projectionKey = key(projectionId, ledger);
    this.offsets.delete(projectionKey);
    this.records.delete(projectionKey);
  }

  async read(
    projectionId: string,
    ledger: AuditLedgerRef,
  ): Promise<AuditTimelineProjectionV1[]> {
    return (this.records.get(key(projectionId, ledger)) ?? []).map((record) => ({ ...record }));
  }

  /** Explicit fault-injection seam for adapter conformance and recovery tests. */
  corruptOffsetForTesting(
    projectionId: string,
    ledger: AuditLedgerRef,
    offset: AuditProjectionOffset,
  ): void {
    this.offsets.set(key(projectionId, ledger), { ...offset });
  }
}

export interface AuditProjectionWorkerOptions {
  projectionId: string;
  journal: AuditJournalProvider;
  projections: AuditProjectionProvider;
}

export interface AuditProjectionReconciliation {
  status: 'empty' | 'pending' | 'verified' | 'gap_detected';
  journalHead: Awaited<ReturnType<AuditJournalProvider['getHead']>>;
  projectionHead: AuditProjectionOffset | null;
}

/** Deterministically derives query/UI state from the immutable ledger. */
export class AuditProjectionWorker {
  constructor(private readonly options: AuditProjectionWorkerOptions) {
    if (!options.projectionId) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Projection ID is required',
      );
    }
  }

  async synchronize(ledger: AuditLedgerRef): Promise<{ applied: number; duplicates: number }> {
    let offset = await this.options.projections.getOffset(this.options.projectionId, ledger);
    let applied = 0;
    let duplicates = 0;
    for await (const entry of this.options.journal.readRange({
      ...ledger,
      ...(offset === null ? {} : { afterSequence: offset.sequence }),
    })) {
      const result = await this.options.projections.compareAndApply({
        projectionId: this.options.projectionId,
        ledger,
        expectedOffset: offset,
        entry,
        record: project(entry),
      });
      if (result.kind === 'conflict') {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.PROJECTION_CONFLICT,
          'Projection offset conflicted with the ordered ledger',
          {
            sequence: entry.core.sequence,
            expectedOffset: offset,
            actualOffset: result.actualOffset,
          },
        );
      }
      if (result.kind === 'applied') applied += 1;
      else duplicates += 1;
      offset = { sequence: entry.core.sequence, entryDigest: entry.entryDigest };
    }
    return { applied, duplicates };
  }

  async rebuild(ledger: AuditLedgerRef): Promise<{ applied: number; duplicates: number }> {
    await this.options.projections.reset(this.options.projectionId, ledger);
    return this.synchronize(ledger);
  }

  async reconcile(ledger: AuditLedgerRef): Promise<AuditProjectionReconciliation> {
    const [journalHead, projectionHead] = await Promise.all([
      this.options.journal.getHead(ledger),
      this.options.projections.getOffset(this.options.projectionId, ledger),
    ]);
    let status: AuditProjectionReconciliation['status'];
    if (journalHead === null && projectionHead === null) status = 'empty';
    else if (journalHead !== null && projectionHead === null) status = 'pending';
    else if (journalHead === null || projectionHead === null) status = 'gap_detected';
    else if (journalHead.sequence === projectionHead.sequence) {
      status = journalHead.entryDigest === projectionHead.entryDigest
        ? 'verified'
        : 'gap_detected';
    } else {
      status = BigInt(projectionHead.sequence) < BigInt(journalHead.sequence)
        ? 'pending'
        : 'gap_detected';
    }
    return { status, journalHead, projectionHead };
  }
}
