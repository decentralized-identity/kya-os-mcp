import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import type { AuditHasher, AuditSignatureVerifier } from './crypto.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import {
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvent,
  digestAuditEvidenceManifest,
} from './integrity.js';
import type { AuditLedgerRef, DecimalString, SignedAuditEntryV1 } from './types.js';

/** What a stored entry is checked with before the recorder or a checkpoint builds on it. */
export interface StoredAuditEntryVerification {
  hasher: AuditHasher;
  signatures: AuditSignatureVerifier;
}

/**
 * Whether `entry`, as a journal returned it, is one its recorder made for
 * `ledger`: it belongs to that ledger epoch, its event, evidence-manifest and
 * entry digests recompute from its core, its receipt core is the one built for
 * that core, and the receipt's signature verifies under the recorder the core
 * names. A party that can write the journal store, and holds no recorder key,
 * cannot make an entry that passes. A verifier that throws is not caught: the
 * caller tells a failure to verify from an entry that does not verify.
 */
export async function verifyStoredAuditEntry(
  entry: SignedAuditEntryV1,
  ledger: AuditLedgerRef,
  { hasher, signatures }: StoredAuditEntryVerification,
): Promise<boolean> {
  const { core } = entry;
  if (core.ledgerId !== ledger.ledgerId || core.ledgerEpochId !== ledger.ledgerEpochId) return false;
  const eventDigest = await digestAuditEvent(hasher, core.event);
  if (eventDigest !== core.eventDigest || eventDigest !== entry.eventDigest) return false;
  if (await digestAuditEvidenceManifest(hasher, core.event) !== core.evidenceManifestDigest) return false;
  if (await digestAuditEntry(hasher, core) !== entry.entryDigest) return false;
  if (canonicalizeJson(buildAuditRecorderReceiptCore(core, entry.entryDigest)) !==
    canonicalizeJson(entry.recorderReceipt.core)) return false;
  return (await signatures.verify(
    canonicalizeJsonBytes(entry.recorderReceipt.core),
    entry.recorderReceipt.jws,
    core.recorder,
  )) === true;
}

/**
 * Refuses, with `AUDIT_JOURNAL_FAILURE` naming `sequence`, to build on the
 * stored entry at `sequence` unless `verified` answers true. A verifier or a
 * journal read that throws is the refusal's cause.
 */
export async function requireStoredAuditEntry(
  sequence: DecimalString,
  verified: () => Promise<boolean>,
): Promise<void> {
  let answer: boolean;
  try {
    answer = await verified();
  } catch (error) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      'Audit journal entry could not be verified as one its recorder signed',
      { sequence },
      { cause: error },
    );
  }
  if (!answer) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      'Audit journal entry is not one its recorder signed',
      { sequence },
    );
  }
}
