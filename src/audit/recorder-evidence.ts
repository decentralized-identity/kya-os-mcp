import { canonicalizeJson } from '../utils/canonical-json.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import { collectAuditEvidenceRefs } from './integrity.js';
import type { AuditEvidenceProvider, EncryptedEvidenceInput } from './providers/evidence.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type { AuditProducerEventCoreV1, Digest } from './types.js';

/** What the recorder's write-ahead evidence reads from the recorder's configuration. */
export interface RecorderEvidenceConfig {
  ledgerId: string;
  journal: AuditJournalProvider;
  evidence?: AuditEvidenceProvider;
}

/**
 * The recorder's write-ahead evidence: objects persisted before the entry
 * that commits them, and disposed again when that entry is never committed.
 */
export class RecorderWriteAheadEvidence {
  /** Write-ahead evidence objects held by submissions in flight, by object ID. */
  private readonly heldEvidence = new Map<string, { holders: number; shared: boolean }>();

  constructor(private readonly config: RecorderEvidenceConfig) {}

  /**
   * Registers this submission as a holder of each evidence object it carries.
   * An object two submissions hold at once is marked shared for as long as
   * either still holds it: both may have seen it as new, and the other may
   * already have committed a reference to it.
   */
  hold(evidence: readonly EncryptedEvidenceInput[]): string[] {
    const objectIds = [...new Set(evidence.map((item) => item.ref.objectId))];
    for (const objectId of objectIds) {
      const hold = this.heldEvidence.get(objectId);
      if (hold === undefined) this.heldEvidence.set(objectId, { holders: 1, shared: false });
      else this.heldEvidence.set(objectId, { holders: hold.holders + 1, shared: true });
    }
    return objectIds;
  }

  release(objectIds: readonly string[]): void {
    for (const objectId of objectIds) {
      const hold = this.heldEvidence.get(objectId)!;
      if (hold.holders === 1) this.heldEvidence.delete(objectId);
      else this.heldEvidence.set(objectId, { ...hold, holders: hold.holders - 1 });
    }
  }

  /**
   * Best-effort compensation for write-ahead evidence whose append failed. Only
   * objects this submission newly stored are disposed: an object that already
   * existed may be referenced by another committed entry, and so may one that
   * a concurrent submission held at the same time. They are disposed only
   * after re-confirming that no committed entry claims this event identity, so
   * a raced idempotent commit is never stripped of its evidence. Failures here
   * leave orphans for operator retention tooling.
   */
  async disposeUncommitted(
    stored: readonly EncryptedEvidenceInput[],
    identity: { idempotencyKey: Digest },
  ): Promise<void> {
    if (stored.length === 0 || this.config.evidence === undefined) return;
    try {
      const committed = await this.config.journal.getByIdempotencyKey(
        this.config.ledgerId,
        identity.idempotencyKey,
      );
      if (committed !== null) return;
      for (const item of stored) {
        if (this.heldEvidence.get(item.ref.objectId)?.shared === true) continue;
        await this.config.evidence.applyRetention({
          kind: 'dispose',
          ref: item.ref,
          authorizedBy: 'audit-recorder',
          reason: 'append_failed_uncommitted',
        });
      }
    } catch {
      // Retaining an orphan is preferable to disposing racing committed evidence.
    }
  }

  /** Persists write-ahead evidence and returns the objects that did not exist before. */
  async persist(
    evidence: readonly EncryptedEvidenceInput[],
    event: AuditProducerEventCoreV1,
  ): Promise<EncryptedEvidenceInput[]> {
    if (evidence.length === 0) return [];
    if (this.config.evidence === undefined) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
        'Encrypted evidence was submitted but no evidence provider is configured',
      );
    }
    try {
      const refs = new Map(collectAuditEvidenceRefs(event).map((ref) => [ref.objectId, ref]));
      const submitted = new Set<string>();
      const stored: EncryptedEvidenceInput[] = [];
      for (const item of evidence) {
        const referenced = refs.get(item.ref.objectId);
        if (submitted.has(item.ref.objectId) || referenced === undefined ||
          canonicalizeJson(referenced) !== canonicalizeJson(item.ref)) {
          throw new AuditProtocolError(
            AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
            'Submitted evidence does not exactly match a unique frozen event reference',
            { objectId: item.ref.objectId },
          );
        }
        submitted.add(item.ref.objectId);
        const existed = await this.config.evidence.has(item.ref);
        await this.config.evidence.putIfAbsent(item);
        if (!existed) stored.push(item);
      }
      return stored;
    } catch (error) {
      if (error instanceof AuditProtocolError &&
        error.code === AUDIT_ERROR_CODES.EVIDENCE_FAILURE) throw error;
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.EVIDENCE_FAILURE,
        'Required evidence could not be persisted',
        undefined,
        { cause: error },
      );
    }
  }
}
