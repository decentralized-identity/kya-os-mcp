import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import type { AuditHasher, AuditSigner } from './crypto.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_DIGEST_DOMAINS } from './integrity.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import { Rfc9162MerkleTree } from './merkle.js';
import { parseAuditCheckpointCore } from './schemas.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type {
  AuditLedgerRef,
  AuditMerkleConsistencyProofV1,
  AuditMerkleInclusionProofV1,
  DecimalString,
  Digest,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';

const CHECKPOINT_SCHEMA =
  'https://schema.kya-os.org/v1/protocol/audit/checkpoint/v1.0.0' as const;
const CHECKPOINT_SUITE = 'KYA-AUDIT-RFC9162-SHA256-JWS-2026' as const;

function ledgerKey(ledger: AuditLedgerRef): string {
  return `${ledger.ledgerId}\0${ledger.ledgerEpochId}`;
}

function checkpointKey(ledger: AuditLedgerRef, treeSize: DecimalString): string {
  return `${ledgerKey(ledger)}\0${treeSize}`;
}

function parseDecimal(value: DecimalString, label: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
      `${label} must be a canonical non-negative decimal string`,
    );
  }
  return BigInt(value);
}

function toSafeNumber(value: bigint, label: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
      `${label} exceeds this implementation's safe in-memory proof range`,
    );
  }
  return Number(value);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export type AuditCheckpointPutResult =
  | { kind: 'inserted'; checkpoint: SignedAuditCheckpointV1 }
  | { kind: 'existing'; checkpoint: SignedAuditCheckpointV1 }
  | { kind: 'conflict'; checkpoint: SignedAuditCheckpointV1 };

export interface AuditCheckpointStore {
  getLatest(ledger: AuditLedgerRef): Promise<SignedAuditCheckpointV1 | null>;
  getByTreeSize(
    ledger: AuditLedgerRef,
    treeSize: DecimalString,
  ): Promise<SignedAuditCheckpointV1 | null>;
  putIfAbsent(checkpoint: SignedAuditCheckpointV1): Promise<AuditCheckpointPutResult>;
}

/** Ephemeral reference store; durable adapters must preserve the same CAS semantics. */
export class MemoryAuditCheckpointStore implements AuditCheckpointStore {
  private readonly checkpoints = new Map<string, SignedAuditCheckpointV1>();
  private readonly latest = new Map<string, SignedAuditCheckpointV1>();

  async getLatest(ledger: AuditLedgerRef): Promise<SignedAuditCheckpointV1 | null> {
    return this.latest.get(ledgerKey(ledger)) ?? null;
  }

  async getByTreeSize(
    ledger: AuditLedgerRef,
    treeSize: DecimalString,
  ): Promise<SignedAuditCheckpointV1 | null> {
    return this.checkpoints.get(checkpointKey(ledger, treeSize)) ?? null;
  }

  async putIfAbsent(checkpoint: SignedAuditCheckpointV1): Promise<AuditCheckpointPutResult> {
    const ledger = checkpoint.core;
    const key = checkpointKey(ledger, checkpoint.core.treeSize);
    const existing = this.checkpoints.get(key);
    if (existing !== undefined) {
      return existing.checkpointDigest === checkpoint.checkpointDigest
        ? { kind: 'existing', checkpoint: existing }
        : { kind: 'conflict', checkpoint: existing };
    }

    const frozen = deepFreeze(checkpoint);
    this.checkpoints.set(key, frozen);
    const current = this.latest.get(ledgerKey(ledger));
    if (current === undefined ||
      BigInt(current.core.treeSize) < BigInt(checkpoint.core.treeSize)) {
      this.latest.set(ledgerKey(ledger), frozen);
    }
    return { kind: 'inserted', checkpoint: frozen };
  }
}

export interface AuditCheckpointBuilderOptions {
  journal: AuditJournalProvider;
  store: AuditCheckpointStore;
  signer: AuditSigner;
  hasher: AuditHasher;
  clock?: { now(): number };
  onCheckpointCreated?: (checkpoint: SignedAuditCheckpointV1) => Promise<void> | void;
}

/** Creates append-only RFC 9162 checkpoints from a stable journal high-water mark. */
export class AuditCheckpointBuilder {
  private readonly tree: Rfc9162MerkleTree;
  private readonly clock: { now(): number };

  constructor(private readonly options: AuditCheckpointBuilderOptions) {
    this.tree = new Rfc9162MerkleTree(options.hasher);
    this.clock = options.clock ?? Date;
  }

  async createCheckpoint(ledger: AuditLedgerRef): Promise<SignedAuditCheckpointV1> {
    const entries = await this.snapshotAtHead(ledger);
    if (entries.length === 0) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'Cannot checkpoint an empty audit epoch',
      );
    }

    const treeSize = String(entries.length);
    const previous = await this.options.store.getLatest(ledger);
    if (previous !== null) {
      const previousSize = parseDecimal(previous.core.treeSize, 'Previous tree size');
      if (previousSize > BigInt(entries.length)) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.CHECKPOINT_ROLLBACK,
          'Journal tree size is behind the latest signed checkpoint',
        );
      }
      if (previousSize === BigInt(entries.length)) return previous;
    }

    const first = entries[0]!;
    const last = entries[entries.length - 1]!;
    const core = parseAuditCheckpointCore({
      schema: CHECKPOINT_SCHEMA,
      checkpointId: `checkpoint:${ledger.ledgerId}:${ledger.ledgerEpochId}:${treeSize}`,
      ...ledger,
      treeSize,
      firstSequence: first.core.sequence,
      lastSequence: last.core.sequence,
      rootDigest: await this.tree.root(entries.map((entry) => entry.entryDigest)),
      headEntryDigest: last.entryDigest,
      previousCheckpointDigest: previous?.checkpointDigest ?? null,
      createdAt: this.clock.now(),
      issuer: this.options.signer.ref,
      integritySuite: CHECKPOINT_SUITE,
    });
    const checkpointDigest = await hashAuditValue(
      this.options.hasher,
      AUDIT_DIGEST_DOMAINS.checkpoint,
      core,
    );
    const candidate = deepFreeze({
      core,
      checkpointDigest,
      jws: await this.options.signer.sign(canonicalizeJsonBytes(core)),
    });
    const result = await this.options.store.putIfAbsent(candidate);
    if (result.kind === 'conflict') {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT,
        'A different checkpoint already exists at this tree size',
        { treeSize },
      );
    }
    if (result.kind === 'inserted') {
      await this.options.onCheckpointCreated?.(result.checkpoint);
    }
    return result.checkpoint;
  }

  async inclusionProof(
    ledger: AuditLedgerRef,
    sequence: DecimalString,
    checkpoint: SignedAuditCheckpointV1,
  ): Promise<AuditMerkleInclusionProofV1> {
    this.assertCheckpointLedger(ledger, checkpoint);
    const entries = await this.entriesForCheckpoint(ledger, checkpoint);
    const index = entries.findIndex((entry) => entry.core.sequence === sequence);
    if (index < 0) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'Sequence is not included in the checkpoint',
        { sequence, treeSize: checkpoint.core.treeSize },
      );
    }
    return deepFreeze({
      leafIndex: String(index),
      treeSize: checkpoint.core.treeSize,
      auditPath: await this.tree.inclusionProof(
        entries.map((entry) => entry.entryDigest),
        index,
      ),
    });
  }

  async consistencyProof(
    ledger: AuditLedgerRef,
    oldTreeSize: DecimalString,
    checkpoint: SignedAuditCheckpointV1,
  ): Promise<AuditMerkleConsistencyProofV1> {
    this.assertCheckpointLedger(ledger, checkpoint);
    const entries = await this.entriesForCheckpoint(ledger, checkpoint);
    const oldSize = toSafeNumber(parseDecimal(oldTreeSize, 'Old tree size'), 'Old tree size');
    return deepFreeze({
      oldTreeSize,
      newTreeSize: checkpoint.core.treeSize,
      auditPath: await this.tree.consistencyProof(
        entries.map((entry) => entry.entryDigest),
        oldSize,
      ),
    });
  }

  async rootForRange(ledger: AuditLedgerRef, treeSize: DecimalString): Promise<Digest> {
    const size = toSafeNumber(parseDecimal(treeSize, 'Tree size'), 'Tree size');
    if (size === 0) return this.tree.root([]);
    const entries = await this.readEntries(ledger, size);
    if (entries.length !== size) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'Journal does not contain the requested tree range',
        { treeSize },
      );
    }
    return this.tree.root(entries.map((entry) => entry.entryDigest));
  }

  async verifyInclusion(
    entryDigest: Digest,
    checkpoint: SignedAuditCheckpointV1,
    proof: AuditMerkleInclusionProofV1,
  ): Promise<boolean> {
    if (proof.treeSize !== checkpoint.core.treeSize) return false;
    return this.tree.verifyInclusion({
      leaf: entryDigest,
      leafIndex: toSafeNumber(parseDecimal(proof.leafIndex, 'Leaf index'), 'Leaf index'),
      treeSize: toSafeNumber(parseDecimal(proof.treeSize, 'Tree size'), 'Tree size'),
      root: checkpoint.core.rootDigest,
      auditPath: proof.auditPath,
    });
  }

  async verifyConsistency(input: {
    oldTreeSize: DecimalString;
    oldRoot: Digest;
    checkpoint: SignedAuditCheckpointV1;
    proof: AuditMerkleConsistencyProofV1;
  }): Promise<boolean> {
    if (input.proof.oldTreeSize !== input.oldTreeSize ||
      input.proof.newTreeSize !== input.checkpoint.core.treeSize) return false;
    return this.tree.verifyConsistency({
      oldSize: toSafeNumber(parseDecimal(input.oldTreeSize, 'Old tree size'), 'Old tree size'),
      newSize: toSafeNumber(
        parseDecimal(input.checkpoint.core.treeSize, 'New tree size'),
        'New tree size',
      ),
      oldRoot: input.oldRoot,
      newRoot: input.checkpoint.core.rootDigest,
      auditPath: input.proof.auditPath,
    });
  }

  private async snapshotAtHead(ledger: AuditLedgerRef): Promise<SignedAuditEntryV1[]> {
    const head = await this.options.journal.getHead(ledger);
    if (head === null) return [];
    const expectedCount = toSafeNumber(
      parseDecimal(head.sequence, 'Journal head sequence') + 1n,
      'Journal tree size',
    );
    const entries = await this.readEntries(ledger, expectedCount);
    const last = entries[entries.length - 1];
    if (entries.length !== expectedCount || last?.entryDigest !== head.entryDigest) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        'Journal could not provide a stable range through its reported head',
      );
    }
    return entries;
  }

  private async entriesForCheckpoint(
    ledger: AuditLedgerRef,
    checkpoint: SignedAuditCheckpointV1,
  ): Promise<SignedAuditEntryV1[]> {
    const size = toSafeNumber(
      parseDecimal(checkpoint.core.treeSize, 'Checkpoint tree size'),
      'Checkpoint tree size',
    );
    const entries = await this.readEntries(ledger, size);
    if (entries.length !== size || entries[entries.length - 1]?.entryDigest !==
      checkpoint.core.headEntryDigest) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'Journal range does not match the signed checkpoint head',
      );
    }
    return entries;
  }

  private async readEntries(
    ledger: AuditLedgerRef,
    limit: number,
  ): Promise<SignedAuditEntryV1[]> {
    const result: SignedAuditEntryV1[] = [];
    for await (const entry of this.options.journal.readRange({ ...ledger, limit })) {
      if (BigInt(entry.core.sequence) !== BigInt(result.length)) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.JOURNAL_FAILURE,
          'Audit journal range is not contiguous from sequence zero',
        );
      }
      result.push(entry);
    }
    return result;
  }

  private assertCheckpointLedger(
    ledger: AuditLedgerRef,
    checkpoint: SignedAuditCheckpointV1,
  ): void {
    if (checkpoint.core.ledgerId !== ledger.ledgerId ||
      checkpoint.core.ledgerEpochId !== ledger.ledgerEpochId) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.LEDGER_MISMATCH,
        'Checkpoint belongs to a different ledger or epoch',
      );
    }
  }
}
