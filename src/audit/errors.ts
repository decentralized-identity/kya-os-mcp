export const AUDIT_ERROR_CODES = {
  INVALID_EVENT: 'AUDIT_INVALID_EVENT',
  LEDGER_MISMATCH: 'AUDIT_LEDGER_MISMATCH',
  EPOCH_MISMATCH: 'AUDIT_EPOCH_MISMATCH',
  EVENT_ID_CONFLICT: 'AUDIT_EVENT_ID_CONFLICT',
  APPEND_CONFLICT_EXHAUSTED: 'AUDIT_APPEND_CONFLICT_EXHAUSTED',
  JOURNAL_FAILURE: 'AUDIT_JOURNAL_FAILURE',
  EVIDENCE_FAILURE: 'AUDIT_EVIDENCE_FAILURE',
  EVIDENCE_INTEGRITY: 'AUDIT_EVIDENCE_INTEGRITY',
  EVIDENCE_LEGAL_HOLD: 'AUDIT_EVIDENCE_LEGAL_HOLD',
  EVIDENCE_ACCESS_DENIED: 'AUDIT_EVIDENCE_ACCESS_DENIED',
  CHECKPOINT_INVALID: 'AUDIT_CHECKPOINT_INVALID',
  CHECKPOINT_ROLLBACK: 'AUDIT_CHECKPOINT_ROLLBACK',
  CHECKPOINT_CONFLICT: 'AUDIT_CHECKPOINT_CONFLICT',
  CHECKPOINT_PUBLICATION_FAILED: 'AUDIT_CHECKPOINT_PUBLICATION_FAILED',
  PROJECTION_CONFLICT: 'AUDIT_PROJECTION_CONFLICT',
  MIRROR_VERIFICATION_FAILED: 'AUDIT_MIRROR_VERIFICATION_FAILED',
  MIRROR_CONTINUITY_FAILED: 'AUDIT_MIRROR_CONTINUITY_FAILED',
  MIRROR_OUT_OF_ORDER: 'AUDIT_MIRROR_OUT_OF_ORDER',
  UNAUTHORIZED_SUBMISSION: 'AUDIT_UNAUTHORIZED_SUBMISSION',
  INVALID_CONFIGURATION: 'AUDIT_INVALID_CONFIGURATION',
} as const;

export type AuditErrorCode = (typeof AUDIT_ERROR_CODES)[keyof typeof AUDIT_ERROR_CODES];

export class AuditProtocolError extends Error {
  constructor(
    readonly code: AuditErrorCode,
    message: string,
    readonly details?: Readonly<Record<string, unknown>>,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'AuditProtocolError';
  }
}

/**
 * Why a checkpoint was refused with `AUDIT_CHECKPOINT_CONFLICT`, in its
 * `details.reason`. Every such error this library raises names one.
 *
 * - `lost-race`: the store already held a checkpoint at this tree size over
 *   the same tree. Another signer checkpointed the same journal first; the
 *   stored checkpoint stands, and calling `createCheckpoint` again returns it.
 * - `fork`: two signed views of the ledger disagree. The journal no longer
 *   holds the tree of a checkpoint already signed, the store holds one over
 *   another tree at this size, or an observer holds a view the checkpoint
 *   does not consistently extend. This is a security event.
 *
 * Read a conflict as a lost race only when its reason is `lost-race`, as
 * `isLostCheckpointRace` does: any other, or none, is a fork.
 */
export const AUDIT_CHECKPOINT_CONFLICT_REASONS = {
  LOST_RACE: 'lost-race',
  FORK: 'fork',
} as const;

export type AuditCheckpointConflictReason =
  (typeof AUDIT_CHECKPOINT_CONFLICT_REASONS)[keyof typeof AUDIT_CHECKPOINT_CONFLICT_REASONS];

/**
 * True only for an `AUDIT_CHECKPOINT_CONFLICT` this library raised for a lost
 * race, which is benign. False for every other error, so a fork, a conflict
 * that names no reason (such as one an observer of your own throws), and a
 * reason added later all read as not benign.
 */
export function isLostCheckpointRace(error: unknown): boolean {
  return error instanceof AuditProtocolError &&
    error.code === AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT &&
    error.details?.reason === AUDIT_CHECKPOINT_CONFLICT_REASONS.LOST_RACE;
}
