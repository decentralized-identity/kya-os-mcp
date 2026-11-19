import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import type { AuditHasher, AuditSignatureVerifier, AuditSigner } from './crypto.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import {
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvent,
  digestAuditEvidenceManifest,
} from './integrity.js';
import { sameSigner } from './recorder-authority.js';
import type { AuditLedgerRef, DecimalString, SignedAuditEntryV1, SignerRef } from './types.js';

/** What a stored entry is checked with before the recorder or a checkpoint builds on it. */
export interface StoredAuditEntryVerification {
  hasher: AuditHasher;
  signatures: AuditSignatureVerifier;
  /**
   * Set when `signatures` was derived from this signer's own key, the one key
   * it can check: an entry recorded under another key is then refused as one
   * it cannot check, not as one its recorder did not sign.
   */
  ownKey?: SignerRef;
}

/** What {@link checkStoredAuditEntry} found a stored entry to be. */
export type StoredAuditEntryVerdict = 'signed' | 'not-signed' | 'other-key';

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
 * `signed` when `entry` is one its recorder signed for `ledger`, as
 * {@link verifyStoredAuditEntry} decides, `other-key` when it was recorded
 * under a key `verification` cannot check, and `not-signed` otherwise.
 */
export async function checkStoredAuditEntry(
  entry: SignedAuditEntryV1,
  ledger: AuditLedgerRef,
  verification: StoredAuditEntryVerification,
): Promise<StoredAuditEntryVerdict> {
  if (verification.ownKey !== undefined && !sameSigner(entry.core.recorder, verification.ownKey)) {
    return 'other-key';
  }
  return await verifyStoredAuditEntry(entry, ledger, verification) ? 'signed' : 'not-signed';
}

/**
 * Refuses, with `AUDIT_JOURNAL_FAILURE` naming `sequence`, to build on the
 * stored entry at `sequence` unless `verdict` answers `signed`. A verifier or a
 * journal read that throws is the refusal's cause.
 */
export async function requireStoredAuditEntry(
  sequence: DecimalString,
  verdict: () => Promise<StoredAuditEntryVerdict>,
): Promise<void> {
  let answer: StoredAuditEntryVerdict;
  try {
    answer = await verdict();
  } catch (error) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      'Audit journal entry could not be verified as one its recorder signed',
      { sequence },
      { cause: error },
    );
  }
  if (answer === 'other-key') {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      'Audit journal entry was recorded under a key the signer cannot verify; pass signatures that resolve it',
      { sequence },
    );
  }
  if (answer !== 'signed') {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      'Audit journal entry is not one its recorder signed',
      { sequence },
    );
  }
}

/**
 * Refuses, as {@link requireStoredAuditEntry} does, unless each of `entries`
 * from index `from` is `signed` and chains to the entry before it.
 */
export async function requireStoredAuditLeaves(
  entries: readonly SignedAuditEntryV1[],
  from: number,
  ledger: AuditLedgerRef,
  verification: StoredAuditEntryVerification,
): Promise<void> {
  for (let index = from; index < entries.length; index += 1) {
    const entry = entries[index]!;
    await requireStoredAuditEntry(entry.core.sequence, async () =>
      entry.core.previousEntryDigest === (entries[index - 1]?.entryDigest ?? null)
        ? checkStoredAuditEntry(entry, ledger, verification)
        : 'not-signed');
  }
}

/** What the recorder or a checkpoint builder signs with, and any verifier it was given. */
export interface StoredAuditEntryVerifierConfig {
  hasher: AuditHasher;
  signer: AuditSigner;
  signatures?: AuditSignatureVerifier;
}

/**
 * How the recorder or a checkpoint builder that signs with `signer` checks the
 * stored entries it builds on: with `signatures` when it was given one, else
 * with the verifier its signer derives from its own key, else not at all, and
 * the journal is trusted as written. The signer is asked once, and asked
 * again only after it failed to answer.
 */
export class StoredAuditEntryVerifier {
  private derived?: Promise<StoredAuditEntryVerification | undefined>;

  constructor(private readonly config: StoredAuditEntryVerifierConfig) {}

  /**
   * The verification to apply, or undefined when there is none. A signer that
   * fails to derive its verifier is refused with `AUDIT_INVALID_CONFIGURATION`,
   * so nothing is built on the journal unchecked for want of an answer.
   */
  async verification(): Promise<StoredAuditEntryVerification | undefined> {
    const { hasher, signatures } = this.config;
    if (signatures !== undefined) return { hasher, signatures };
    const pending = this.derived ?? this.derive();
    this.derived = pending;
    try {
      return await pending;
    } catch (error) {
      if (this.derived === pending) this.derived = undefined;
      throw error;
    }
  }

  private async derive(): Promise<StoredAuditEntryVerification | undefined> {
    const { hasher, signer } = this.config;
    let signatures: AuditSignatureVerifier | undefined;
    try {
      signatures = await signer.verifier?.();
    } catch (error) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'The audit signer could not derive a verifier of its own signatures',
        undefined,
        { cause: error },
      );
    }
    return signatures === undefined ? undefined : { hasher, signatures, ownKey: signer.ref };
  }
}
