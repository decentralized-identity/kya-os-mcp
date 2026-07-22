import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import { hashAuditValue, type AuditHasher, type AuditSigner } from '../crypto.js';
import { AUDIT_DIGEST_DOMAINS } from '../integrity.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from '../errors.js';
import type {
  AuditLedgerRef,
  AuditObservationReceiptCoreV1,
  AuditObservationReceiptV1,
  ObservedAuditCheckpoint,
  SignedAuditCheckpointV1,
} from '../types.js';

export interface AuditCheckpointObserverProvider {
  readonly capability: 'independent-observer';
  publish(checkpoint: SignedAuditCheckpointV1): Promise<AuditObservationReceiptV1>;
  latest(ledger: AuditLedgerRef): Promise<ObservedAuditCheckpoint | null>;
  verifyObservation(
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditObservationReceiptV1,
  ): Promise<boolean>;
}

export interface MemoryAuditCheckpointObserverConfig {
  observerId: string;
  signer: AuditSigner;
  hasher: AuditHasher;
  clock: { now(): number };
  verifyCheckpoint(checkpoint: SignedAuditCheckpointV1): Promise<boolean>;
  verifyConsistency(
    previous: SignedAuditCheckpointV1,
    next: SignedAuditCheckpointV1,
  ): Promise<boolean>;
}

function key(ledger: AuditLedgerRef): string {
  return `${ledger.ledgerId}\0${ledger.ledgerEpochId}`;
}

export class MemoryAuditCheckpointObserver implements AuditCheckpointObserverProvider {
  readonly capability = 'independent-observer' as const;
  private readonly observations = new Map<string, ObservedAuditCheckpoint>();
  private readonly publicationTails = new Map<string, Promise<void>>();

  constructor(private readonly config: MemoryAuditCheckpointObserverConfig) {}

  async publish(checkpoint: SignedAuditCheckpointV1): Promise<AuditObservationReceiptV1> {
    const publicationKey = key({
      ledgerId: checkpoint.core.ledgerId,
      ledgerEpochId: checkpoint.core.ledgerEpochId,
    });
    const previous = this.publicationTails.get(publicationKey) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.then(() => gate);
    this.publicationTails.set(publicationKey, tail);
    await previous;
    try {
      return await this.publishSerialized(checkpoint);
    } finally {
      release();
      if (this.publicationTails.get(publicationKey) === tail) {
        this.publicationTails.delete(publicationKey);
      }
    }
  }

  private async publishSerialized(
    checkpoint: SignedAuditCheckpointV1,
  ): Promise<AuditObservationReceiptV1> {
    if (!(await this.config.verifyCheckpoint(checkpoint))) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.CHECKPOINT_INVALID,
        'Observer rejected an invalid checkpoint',
      );
    }
    const ledger = {
      ledgerId: checkpoint.core.ledgerId,
      ledgerEpochId: checkpoint.core.ledgerEpochId,
    };
    const existing = this.observations.get(key(ledger));
    if (existing !== undefined) {
      const previousSize = BigInt(existing.checkpoint.core.treeSize);
      const nextSize = BigInt(checkpoint.core.treeSize);
      if (nextSize < previousSize) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.CHECKPOINT_ROLLBACK,
          'Observed checkpoint tree size moved backwards',
        );
      }
      if (nextSize === previousSize) {
        if (checkpoint.core.rootDigest !== existing.checkpoint.core.rootDigest ||
          checkpoint.checkpointDigest !== existing.checkpoint.checkpointDigest) {
          throw new AuditProtocolError(
            AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT,
            'Conflicting checkpoint roots were observed at the same tree size',
          );
        }
        return existing.receipt;
      }
      if (checkpoint.core.previousCheckpointDigest !==
        existing.checkpoint.checkpointDigest ||
        !(await this.config.verifyConsistency(existing.checkpoint, checkpoint))) {
        throw new AuditProtocolError(
          AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT,
          'Checkpoint does not consistently extend the previously observed tree',
        );
      }
    }

    const core: AuditObservationReceiptCoreV1 = {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/observation/v1.0.0',
      observerId: this.config.observerId,
      observer: this.config.signer.ref,
      ledgerId: checkpoint.core.ledgerId,
      ledgerEpochId: checkpoint.core.ledgerEpochId,
      checkpointDigest: checkpoint.checkpointDigest,
      treeSize: checkpoint.core.treeSize,
      observedAt: this.config.clock.now(),
      previousObservationDigest: existing?.receipt.observationDigest ?? null,
    };
    const observationDigest = await hashAuditValue(
      this.config.hasher,
      AUDIT_DIGEST_DOMAINS.observation,
      core,
    );
    const receipt = Object.freeze({
      core: Object.freeze(core),
      observationDigest,
      jws: await this.config.signer.sign(canonicalizeJsonBytes(core)),
    });
    this.observations.set(key(ledger), { checkpoint, receipt });
    return receipt;
  }

  async latest(ledger: AuditLedgerRef): Promise<ObservedAuditCheckpoint | null> {
    return this.observations.get(key(ledger)) ?? null;
  }

  async verifyObservation(
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditObservationReceiptV1,
  ): Promise<boolean> {
    const observed = await this.latest({
      ledgerId: checkpoint.core.ledgerId,
      ledgerEpochId: checkpoint.core.ledgerEpochId,
    });
    return observed?.checkpoint.checkpointDigest === checkpoint.checkpointDigest &&
      observed.receipt.observationDigest === receipt.observationDigest;
  }
}
