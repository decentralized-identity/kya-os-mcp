import type { AuditCheckpointBuilder, AuditCheckpointStore } from './checkpoint.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type {
  AuditBundleConsistencyProofV1,
  AuditBundleInclusionProofV1,
  AuditHead,
  AuditLedgerRef,
  DecimalString,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';

/**
 * Operator-facing read surface over an authoritative audit ledger.
 *
 * This is the counterpart to the producer-facing {@link AuditRecorderClient}:
 * where that writes signed entries, this reads them back for browsing, replay,
 * and independent verification. It is deliberately transport-agnostic - an HTTP
 * or RPC boundary serialises to and from these methods - so the same contract
 * serves the in-process reference recorder, a hosted recorder, and a
 * dashboard client.
 *
 * Every returned artifact is the recorder's own signed object; a caller can
 * re-verify it with {@link AuditArtifactVerifier} without trusting this service.
 * Checkpoint-derived proofs are optional: a service built without checkpoint
 * access rejects those calls with {@link AUDIT_ERROR_CODES.INVALID_CONFIGURATION}
 * rather than fabricating a result.
 */
export interface AuditReadService {
  /** Current chain head (highest sequence + its entry digest), or null when empty. */
  getHead(ledger: AuditLedgerRef): Promise<AuditHead | null>;

  /**
   * A forward, sequence-ordered page of signed entries. The page echoes the
   * ledger {@link AuditHead} so a caller can tell whether it has reached the
   * tip, and a `nextAfterSequence` cursor for the following page (null at end).
   */
  listEntries(query: AuditReadEntriesQuery): Promise<AuditReadEntriesPage>;

  /** The latest signed checkpoint for the ledger, or null when none exists yet. */
  getLatestCheckpoint(ledger: AuditLedgerRef): Promise<SignedAuditCheckpointV1 | null>;

  /**
   * A self-contained Merkle inclusion proof binding one entry to the latest
   * checkpoint's signed root - the artifact a client uses to prove an entry is
   * in the ledger without downloading the whole ledger.
   */
  getInclusionProof(query: AuditInclusionProofQuery): Promise<AuditBundleInclusionProofV1>;

  /**
   * A Merkle consistency proof that the ledger at `oldTreeSize` is an append-only
   * prefix of the latest checkpoint - the artifact that proves history was never
   * rewritten between two checkpoints.
   */
  getConsistencyProof(query: AuditConsistencyProofQuery): Promise<AuditBundleConsistencyProofV1>;
}

export interface AuditReadEntriesQuery extends AuditLedgerRef {
  /** Exclusive lower bound: return entries whose sequence is strictly greater. */
  afterSequence?: DecimalString;
  /** Maximum entries to return; clamped to [1, {@link MAX_READ_ENTRIES_LIMIT}]. */
  limit?: number;
}

export interface AuditReadEntriesPage {
  entries: SignedAuditEntryV1[];
  /** The ledger head at read time, so a caller knows if more entries exist beyond this page. */
  head: AuditHead | null;
  /** Cursor for the next page (pass as `afterSequence`), or null when this page reached the head. */
  nextAfterSequence: DecimalString | null;
}

export interface AuditInclusionProofQuery extends AuditLedgerRef {
  sequence: DecimalString;
}

export interface AuditConsistencyProofQuery extends AuditLedgerRef {
  /** Tree size of an earlier signed checkpoint to prove the latest is consistent with. */
  oldTreeSize: DecimalString;
}

/** Checkpoint read access, injected to enable proof operations. */
export interface AuditCheckpointReadAccess {
  builder: AuditCheckpointBuilder;
  store: AuditCheckpointStore;
}

export interface AuditReadServiceDeps {
  journal: AuditJournalProvider;
  /** Enables `getLatestCheckpoint`/`getInclusionProof`/`getConsistencyProof`. */
  checkpoints?: AuditCheckpointReadAccess;
}

export const DEFAULT_READ_ENTRIES_LIMIT = 100;
export const MAX_READ_ENTRIES_LIMIT = 1000;

function clampLimit(limit: number | undefined): number {
  if (limit === undefined || !Number.isFinite(limit)) return DEFAULT_READ_ENTRIES_LIMIT;
  return Math.max(1, Math.min(MAX_READ_ENTRIES_LIMIT, Math.trunc(limit)));
}

function ledgerOf(ref: AuditLedgerRef): AuditLedgerRef {
  return { ledgerId: ref.ledgerId, ledgerEpochId: ref.ledgerEpochId };
}

function requireDecimal(value: DecimalString, label: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
      `${label} must be a canonical non-negative decimal string`,
      { [label]: value },
    );
  }
  return BigInt(value);
}

/**
 * Reference read service backed by an {@link AuditJournalProvider} and, when
 * proofs are needed, an {@link AuditCheckpointReadAccess}.
 *
 * Reads ride the journal's ordered `readRange`, so paging cost is independent of
 * ledger size. Pagination fetches one extra entry to detect a further page
 * without a second round trip.
 */
export class LocalAuditReadService implements AuditReadService {
  private readonly journal: AuditJournalProvider;
  private readonly checkpoints?: AuditCheckpointReadAccess;

  constructor(deps: AuditReadServiceDeps) {
    this.journal = deps.journal;
    this.checkpoints = deps.checkpoints;
  }

  getHead(ledger: AuditLedgerRef): Promise<AuditHead | null> {
    return this.journal.getHead(ledgerOf(ledger));
  }

  async listEntries(query: AuditReadEntriesQuery): Promise<AuditReadEntriesPage> {
    const limit = clampLimit(query.limit);
    const ledger = ledgerOf(query);

    // Over-fetch by one: if the journal yields limit+1, a further page exists.
    const collected: SignedAuditEntryV1[] = [];
    for await (const entry of this.journal.readRange({
      ...ledger,
      ...(query.afterSequence === undefined ? {} : { afterSequence: query.afterSequence }),
      limit: limit + 1,
    })) {
      collected.push(entry);
      if (collected.length > limit) break;
    }

    const hasMore = collected.length > limit;
    const entries = hasMore ? collected.slice(0, limit) : collected;
    const nextAfterSequence = hasMore ? entries[entries.length - 1]!.core.sequence : null;
    const head = await this.journal.getHead(ledger);

    return { entries, head, nextAfterSequence };
  }

  async getLatestCheckpoint(ledger: AuditLedgerRef): Promise<SignedAuditCheckpointV1 | null> {
    return this.requireCheckpoints().store.getLatest(ledgerOf(ledger));
  }

  async getInclusionProof(query: AuditInclusionProofQuery): Promise<AuditBundleInclusionProofV1> {
    const checkpoints = this.requireCheckpoints();
    const ledger = ledgerOf(query);
    const checkpoint = await this.requireLatestCheckpoint(checkpoints, ledger);
    const entry = await this.entryAtSequence(ledger, query.sequence);
    const proof = await checkpoints.builder.inclusionProof(ledger, query.sequence, checkpoint);
    return Object.freeze({
      ledgerId: ledger.ledgerId,
      ledgerEpochId: ledger.ledgerEpochId,
      sequence: query.sequence,
      entryDigest: entry.entryDigest,
      checkpointDigest: checkpoint.checkpointDigest,
      proof,
    });
  }

  async getConsistencyProof(
    query: AuditConsistencyProofQuery,
  ): Promise<AuditBundleConsistencyProofV1> {
    const checkpoints = this.requireCheckpoints();
    const ledger = ledgerOf(query);
    const newCheckpoint = await this.requireLatestCheckpoint(checkpoints, ledger);
    const oldCheckpoint = await checkpoints.store.getByTreeSize(ledger, query.oldTreeSize);
    if (oldCheckpoint === null) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'No signed checkpoint exists at the requested old tree size',
        { oldTreeSize: query.oldTreeSize },
      );
    }
    const proof = await checkpoints.builder.consistencyProof(
      ledger,
      query.oldTreeSize,
      newCheckpoint,
    );
    return Object.freeze({
      ledgerId: ledger.ledgerId,
      ledgerEpochId: ledger.ledgerEpochId,
      oldCheckpointDigest: oldCheckpoint.checkpointDigest,
      newCheckpointDigest: newCheckpoint.checkpointDigest,
      proof,
    });
  }

  private requireCheckpoints(): AuditCheckpointReadAccess {
    if (this.checkpoints === undefined) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'This read service was built without checkpoint access; proofs are unavailable',
      );
    }
    return this.checkpoints;
  }

  private async requireLatestCheckpoint(
    checkpoints: AuditCheckpointReadAccess,
    ledger: AuditLedgerRef,
  ): Promise<SignedAuditCheckpointV1> {
    const checkpoint = await checkpoints.store.getLatest(ledger);
    if (checkpoint === null) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'No signed checkpoint exists for this ledger yet',
        { ledgerId: ledger.ledgerId },
      );
    }
    return checkpoint;
  }

  private async entryAtSequence(
    ledger: AuditLedgerRef,
    sequence: DecimalString,
  ): Promise<SignedAuditEntryV1> {
    const value = requireDecimal(sequence, 'sequence');
    // `readRange` is exclusive on afterSequence, so start one below the target.
    const afterSequence = value > 1n ? String(value - 1n) : undefined;
    for await (const entry of this.journal.readRange({
      ...ledger,
      ...(afterSequence === undefined ? {} : { afterSequence }),
      limit: 1,
    })) {
      if (entry.core.sequence === sequence) return entry;
      break;
    }
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
      'No entry exists at the requested sequence',
      { sequence },
    );
  }
}

/** One-call composition helper mirroring {@link createLocalAuditRecorder}. */
export function createLocalAuditReadService(deps: AuditReadServiceDeps): AuditReadService {
  return new LocalAuditReadService(deps);
}
