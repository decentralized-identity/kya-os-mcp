/**
 * The shapes `AuditArtifactVerifier` (`./verifier.ts`) takes: its options, the supporting
 * checkpoints a verification may resolve key bounds against, the signed artifacts whose keys it
 * relied on, and the injected authorization verifier. `./verifier.ts` re-exports them, so imports
 * from there are unchanged.
 */

import type { AuditHasher, AuditSignatureVerifier } from './crypto.js';
import type {
  AuditObservationReceiptV1,
  AuditVerificationDimension,
  AuditVerificationPolicyV1,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
  SignerRef,
} from './types.js';

export interface AuditArtifactVerifierOptions {
  hasher: AuditHasher;
  signatures: AuditSignatureVerifier;
  verifiedAt?: () => number;
  /** How far an observation may be dated ahead of `verifiedAt` (default 120 s). */
  maxClockSkewMs?: number;
  authorization?: AuditAuthorizationVerifier;
}

/**
 * Supporting artifacts that let a verifier resolve checkpoint-bounded key validity, and date
 * artifacts whose signing key has ended.
 */
export interface AuditVerificationContext {
  /**
   * Checkpoints that policy `validFromCheckpoint`/`validUntilCheckpoint` digests may name. They
   * also date the entries whose tree they hold, when signed by a key that is live.
   */
  checkpoints?: readonly SignedAuditCheckpointV1[];
  /**
   * Geneses of successor ledger epochs: each, signed by the epoch's own key, commits to the
   * terminal checkpoint of the epoch before it, and so dates every record that checkpoint holds
   * before the old key ended. Pass the terminal checkpoint in `checkpoints`, and the whole epoch's
   * entries, so its tree can be recomputed. A genesis that dates nothing is reported as
   * `AUDIT_SUCCESSOR_GENESIS_MISMATCH`.
   */
  successorGeneses?: readonly SignedAuditEntryV1[];
}

/** Artifacts whose signing keys a verification relied on. */
export interface AuditSignedArtifacts {
  entries?: readonly SignedAuditEntryV1[];
  checkpoints?: readonly SignedAuditCheckpointV1[];
  observations?: readonly AuditObservationReceiptV1[];
  /** The exporter that signed a replay-bundle manifest. */
  exporter?: SignerRef;
}

/** Optional collateral verifier kept separate from structural/cryptographic verification. */
export interface AuditAuthorizationVerifier {
  verifyAsObserved(
    entries: readonly SignedAuditEntryV1[],
    policy: AuditVerificationPolicyV1,
  ): Promise<AuditVerificationDimension>;
  verifyCurrent(
    entries: readonly SignedAuditEntryV1[],
    policy: AuditVerificationPolicyV1,
  ): Promise<AuditVerificationDimension>;
}
