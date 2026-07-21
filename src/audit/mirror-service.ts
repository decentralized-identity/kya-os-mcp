import type { AuditHasher } from './crypto.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type { AuditJournalProvider } from './providers/journal.js';
import type {
  AuditLedgerRef,
  AuditVerificationPolicyV1,
  SignedAuditEntryV1,
} from './types.js';
import type { AuditArtifactVerifier } from './verifier.js';

export interface AuditMirrorServiceOptions {
  ledger: AuditLedgerRef;
  journal: AuditJournalProvider;
  verifier: AuditArtifactVerifier;
  verificationPolicy: AuditVerificationPolicyV1;
  hasher: AuditHasher;
}

/** Verified mirror ingestion. It persists exact recorder envelopes and never resequences/signs. */
export class AuditMirrorService {
  constructor(private readonly options: AuditMirrorServiceOptions) {}

  async ingest(entry: SignedAuditEntryV1): Promise<SignedAuditEntryV1> {
    if (entry.core.ledgerId !== this.options.ledger.ledgerId ||
      entry.core.ledgerEpochId !== this.options.ledger.ledgerEpochId) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.LEDGER_MISMATCH,
        'Mirror entry belongs to a different ledger epoch',
      );
    }
    const report = await this.options.verifier.verifyEntries(
      [entry],
      this.options.verificationPolicy,
    );
    if (report.cryptographicIntegrity.verdict !== 'valid') {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.MIRROR_VERIFICATION_FAILED,
        'Mirror rejected an entry that failed historical artifact verification',
        { reasonCodes: report.cryptographicIntegrity.reasonCodes },
      );
    }

    const idempotencyKey = await hashAuditValue(
      this.options.hasher,
      'org.kya-os.audit.mirror-idempotency.v1',
      { ledgerId: entry.core.ledgerId, entryDigest: entry.entryDigest },
    );
    const duplicate = await this.options.journal.getByIdempotencyKey(
      entry.core.ledgerId,
      idempotencyKey,
    );
    if (duplicate !== null) {
      if (duplicate.entryDigest !== entry.entryDigest) this.continuityFailure();
      return duplicate;
    }

    const head = await this.options.journal.getHead(this.options.ledger);
    const continuous = head === null
      ? entry.core.sequence === '0' && entry.core.previousEntryDigest === null
      : BigInt(entry.core.sequence) === BigInt(head.sequence) + 1n &&
        entry.core.previousEntryDigest === head.entryDigest;
    if (!continuous) this.continuityFailure();

    const result = await this.options.journal.compareAndAppend({
      ledger: this.options.ledger,
      expectedHead: head,
      entry,
      idempotencyKey,
    });
    if (result.kind === 'appended' || result.kind === 'duplicate') return result.entry;
    this.continuityFailure();
  }

  private continuityFailure(): never {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.MIRROR_CONTINUITY_FAILED,
      'Mirror entry does not exactly extend the observed recorder chain',
    );
  }
}
