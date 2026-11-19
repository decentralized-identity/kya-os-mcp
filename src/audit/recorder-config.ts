import type { AuditHasher, AuditSignatureVerifier, AuditSigner } from './crypto.js';
import type { AuditEvidenceProvider } from './providers/evidence.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type { AuditRecorderSubmission } from './providers/recorder-client.js';
import type { Digest, PartyRef, ProtocolBindingId } from './types.js';

export interface AuditClock {
  now(): number;
}

export interface AuthenticatedAuditSubmissionContext {
  producerAuthority: string;
  tenantAuthority: string;
  /** Exact authenticated producer binding for non-public or non-DID identifiers. */
  producerRef?: PartyRef;
  /** Exact authenticated tenant binding for opaque or commitment-based tenant identifiers. */
  tenantRef?: PartyRef;
}

export interface AuditSubmissionAuthorizer {
  authorize(input: {
    submission: AuditRecorderSubmission;
    context: AuthenticatedAuditSubmissionContext;
  }): Promise<boolean> | boolean;
}

/**
 * Authoritative epoch-transition port. A successful result means the predecessor terminal
 * checkpoint was verified and the predecessor epoch was atomically sealed against new appends.
 * Implementations must be idempotent for identical transition inputs.
 */
export interface AuditEpochTransitionGuard {
  verifyAndSeal(input: {
    ledgerId: string;
    previousEpochId: string;
    nextEpochId: string;
    previousTerminalCheckpointDigest: Digest;
  }): Promise<boolean>;
}

export interface AuditRecorderServiceConfig {
  ledgerId: string;
  ledgerEpochId: string;
  tenantRef: PartyRef;
  binding: ProtocolBindingId;
  sourceId: string;
  journal: AuditJournalProvider;
  signer: AuditSigner;
  hasher: AuditHasher;
  clock: AuditClock;
  evidence?: AuditEvidenceProvider;
  authorizer?: AuditSubmissionAuthorizer;
  previousEpochId?: string;
  previousTerminalCheckpointDigest?: Digest;
  epochTransitionGuard?: AuditEpochTransitionGuard;
  maxAppendConflicts?: number;
  /**
   * Verifies recorder receipt signatures. The recorder chains to a journal
   * head it did not append in this process only once the stored entry at that
   * head verifies as one its recorder signed for this ledger epoch, and
   * refuses with `AUDIT_JOURNAL_FAILURE` otherwise, so a party that can write
   * the journal store but holds no key cannot have the recorder sign a
   * successor to an entry it never made. Without it the recorder uses the
   * verifier `signer.verifier()` derives from its own key, which checks the
   * entries recorded under that key, the only key the recorder chains to in
   * its epoch; when the signer derives none, as a signer over a
   * non-extractable CryptoKey or a remote key service does not, the journal
   * is trusted as written. Pass it when the signer derives no verifier.
   * @since 1.26.0
   */
  signatures?: AuditSignatureVerifier;
}
