/**
 * The checks of one signed audit entry or checkpoint that need no other artifact: its suite and
 * algorithm, whether the policy places its signing key at the time and position it states, its
 * digests and its signature. `AuditArtifactVerifier` runs them, and so does dating evidence,
 * which must verify a successor genesis or a checkpoint before it dates anything. Each check also
 * returns when the signing key ended ({@link keyEnd}); whether something dates the artifact before
 * that end is for the caller to judge, against the evidence it holds.
 */

import { canonicalizeJsonBytes, sameCanonicalJson } from '../utils/canonical-json.js';
import { hashAuditValue } from './crypto.js';
import {
  AUDIT_DIGEST_DOMAINS,
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  digestAuditEvent,
} from './integrity.js';
import { keyEnd, keyTrust, withBoundary, type CheckpointBoundaries } from './key-trust.js';
import { auditVerificationPolicySchema, signedAuditCheckpointSchema } from './schemas.js';
import type {
  AuditCheckpointCoreV1,
  AuditLedgerRef,
  AuditVerificationDimension,
  AuditVerificationPolicyV1,
  Digest,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import { AUDIT_REASON_CODES, dimension } from './verdicts.js';
import type { AuditArtifactVerifierOptions } from './verifier-types.js';

export type ArtifactCheckOptions = Pick<
  AuditArtifactVerifierOptions,
  'hasher' | 'signatures' | 'verifiedAt'
>;

export type CheckpointCheck =
  | { kind: 'rejected'; result: AuditVerificationDimension }
  | {
      kind: 'checked';
      core: AuditCheckpointCoreV1;
      /** The digest recomputed from the core. */
      digest: Digest;
      reasons: Set<string>;
      /** When the issuer key ended, if it has ({@link keyEnd}). */
      until: number | undefined;
    };

function epochOf(
  policy: AuditVerificationPolicyV1,
  ledger: AuditLedgerRef,
): AuditVerificationPolicyV1['trustedLedgerEpochs'][number] | undefined {
  return policy.trustedLedgerEpochs.find((candidate) =>
    candidate.ledgerId === ledger.ledgerId &&
    candidate.ledgerEpochId === ledger.ledgerEpochId);
}

/**
 * Checks an entry on its own, adding a reason for each failure, and returns when its recorder key
 * ended, if it has and the policy places the entry within it.
 */
export async function checkEntry(
  options: ArtifactCheckOptions,
  entry: SignedAuditEntryV1,
  policy: AuditVerificationPolicyV1,
  boundaries: CheckpointBoundaries,
  reasons: Set<string>,
): Promise<number | undefined> {
  const { core } = entry;
  if (!policy.acceptedIntegritySuites.includes(core.integritySuite)) {
    reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_SUITE);
  }
  if (!policy.acceptedAlgorithms.includes(core.recorder.alg)) {
    reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM);
  }

  const epochPolicy = epochOf(policy, core);
  const keys = epochPolicy?.recorderKeys ?? [];
  const position = BigInt(core.sequence) + 1n;
  const trust = keyTrust(keys, core.recorder, core.recordedAt, core, position, boundaries, epochPolicy);
  if (trust === 'outside') reasons.add(AUDIT_REASON_CODES.UNTRUSTED_RECORDER);
  if (trust === 'unresolved') reasons.add(AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED);

  const eventDigest = await digestAuditEvent(options.hasher, core.event);
  if (eventDigest !== core.eventDigest || eventDigest !== entry.eventDigest) {
    reasons.add(AUDIT_REASON_CODES.EVENT_DIGEST_MISMATCH);
  }
  const evidenceDigest = await digestAuditEvidenceManifest(options.hasher, core.event);
  if (evidenceDigest !== core.evidenceManifestDigest) {
    reasons.add(AUDIT_REASON_CODES.EVIDENCE_MANIFEST_DIGEST_MISMATCH);
  }
  const entryDigest = await digestAuditEntry(options.hasher, core);
  if (entryDigest !== entry.entryDigest) reasons.add(AUDIT_REASON_CODES.ENTRY_DIGEST_MISMATCH);

  const expectedReceipt = buildAuditRecorderReceiptCore(core, entry.entryDigest);
  if (!sameCanonicalJson(expectedReceipt, entry.recorderReceipt.core)) {
    reasons.add(AUDIT_REASON_CODES.RECEIPT_MISMATCH);
  }
  if ((await options.signatures.verify(
    canonicalizeJsonBytes(entry.recorderReceipt.core),
    entry.recorderReceipt.jws,
    core.recorder,
  )) !== true) {
    reasons.add(AUDIT_REASON_CODES.SIGNATURE_INVALID);
  }
  return trust === 'within'
    ? keyEnd(keys, core.recorder, core.recordedAt, core, position, boundaries,
      epochPolicy ?? {}, options.verifiedAt?.())
    : undefined;
}

/**
 * Checks a checkpoint's schema, suite, issuer trust, digest and signature. `boundaries` are those
 * of the supporting checkpoints; the checkpoint's own digest is laid over them, as a policy bound
 * may name it.
 */
export async function checkCheckpoint(
  options: ArtifactCheckOptions,
  checkpoint: SignedAuditCheckpointV1,
  policy: AuditVerificationPolicyV1,
  boundaries: CheckpointBoundaries,
): Promise<CheckpointCheck> {
  if (!auditVerificationPolicySchema.safeParse(policy).success) {
    return {
      kind: 'rejected',
      result: dimension('invalid', [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID]),
    };
  }
  const parsedCheckpoint = signedAuditCheckpointSchema.safeParse(checkpoint);
  if (!parsedCheckpoint.success) {
    return { kind: 'rejected', result: dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]) };
  }
  const reasons = new Set<string>();
  const validated = parsedCheckpoint.data as SignedAuditCheckpointV1;
  const core = validated.core;
  if (!policy.acceptedIntegritySuites.includes(core.integritySuite)) {
    reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_SUITE);
  }
  if (!policy.acceptedAlgorithms.includes(core.issuer.alg)) {
    reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM);
  }
  const digest = await hashAuditValue(options.hasher, AUDIT_DIGEST_DOMAINS.checkpoint, core);
  const epochPolicy = epochOf(policy, core);
  const keys = epochPolicy?.recorderKeys ?? [];
  const position = BigInt(core.treeSize);
  const own = withBoundary(boundaries, digest, core);
  const trust = keyTrust(keys, core.issuer, core.createdAt, core, position, own, epochPolicy);
  if (trust === 'outside') reasons.add(AUDIT_REASON_CODES.UNTRUSTED_RECORDER);
  if (trust === 'unresolved') reasons.add(AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED);

  if (digest !== validated.checkpointDigest) {
    reasons.add(AUDIT_REASON_CODES.CHECKPOINT_DIGEST_MISMATCH);
  }
  if ((await options.signatures.verify(
    canonicalizeJsonBytes(core),
    validated.jws,
    core.issuer,
  )) !== true) {
    reasons.add(AUDIT_REASON_CODES.CHECKPOINT_SIGNATURE_INVALID);
  }
  const until = trust === 'within'
    ? keyEnd(keys, core.issuer, core.createdAt, core, position, own, epochPolicy ?? {},
      options.verifiedAt?.())
    : undefined;
  return { kind: 'checked', core, digest, reasons, until };
}

/** Checks that `entry` follows `previous`, the entry before it in the list at `index - 1`. */
export function checkChainPosition(
  entry: SignedAuditEntryV1,
  previous: SignedAuditEntryV1 | undefined,
  index: number,
  reasons: Set<string>,
): void {
  if (previous === undefined) {
    if (entry.core.sequence === '0') {
      if (entry.core.previousEntryDigest !== null ||
        entry.core.event.eventType !== 'ledger.epoch.started') {
        reasons.add(AUDIT_REASON_CODES.GENESIS_INVALID);
      }
    } else if (index === 0 && entry.core.previousEntryDigest === null) {
      reasons.add(AUDIT_REASON_CODES.PREDECESSOR_MISMATCH);
    }
    return;
  }
  if (entry.core.ledgerId !== previous.core.ledgerId ||
    entry.core.ledgerEpochId !== previous.core.ledgerEpochId) {
    reasons.add(AUDIT_REASON_CODES.LEDGER_SCOPE_MISMATCH);
  }
  try {
    if (BigInt(entry.core.sequence) !== BigInt(previous.core.sequence) + 1n) {
      reasons.add(AUDIT_REASON_CODES.SEQUENCE_GAP);
    }
  } catch {
    reasons.add(AUDIT_REASON_CODES.SEQUENCE_GAP);
  }
  if (entry.core.previousEntryDigest !== previous.entryDigest) {
    reasons.add(AUDIT_REASON_CODES.PREDECESSOR_MISMATCH);
  }
}
