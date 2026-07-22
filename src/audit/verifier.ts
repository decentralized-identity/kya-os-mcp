import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { hashAuditValue, type AuditHasher, type AuditSignatureVerifier } from './crypto.js';
import {
  AUDIT_DIGEST_DOMAINS,
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  digestAuditEvent,
} from './integrity.js';
import { Rfc9162MerkleTree } from './merkle.js';
import {
  auditObservationReceiptSchema,
  auditVerificationPolicySchema,
  signedAuditCheckpointSchema,
  signedAuditEntrySchema,
} from './schemas.js';
import type {
  AuditVerificationDimension,
  AuditObservationReceiptV1,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  HistoricalAuditKeyPolicy,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
  SignerRef,
} from './types.js';

export const AUDIT_REASON_CODES = Object.freeze({
  NOT_EVALUATED: 'AUDIT_NOT_EVALUATED',
  SCHEMA_INVALID: 'AUDIT_SCHEMA_INVALID',
  UNSUPPORTED_SUITE: 'AUDIT_UNSUPPORTED_SUITE',
  UNSUPPORTED_ALGORITHM: 'AUDIT_UNSUPPORTED_ALGORITHM',
  UNTRUSTED_RECORDER: 'AUDIT_UNTRUSTED_RECORDER',
  SIGNATURE_INVALID: 'AUDIT_SIGNATURE_INVALID',
  EVENT_DIGEST_MISMATCH: 'AUDIT_EVENT_DIGEST_MISMATCH',
  EVIDENCE_MANIFEST_DIGEST_MISMATCH: 'AUDIT_EVIDENCE_MANIFEST_DIGEST_MISMATCH',
  ENTRY_DIGEST_MISMATCH: 'AUDIT_ENTRY_DIGEST_MISMATCH',
  RECEIPT_MISMATCH: 'AUDIT_RECEIPT_MISMATCH',
  LEDGER_SCOPE_MISMATCH: 'AUDIT_LEDGER_SCOPE_MISMATCH',
  SEQUENCE_GAP: 'AUDIT_SEQUENCE_GAP',
  PREDECESSOR_MISMATCH: 'AUDIT_PREDECESSOR_MISMATCH',
  GENESIS_INVALID: 'AUDIT_GENESIS_INVALID',
  CHECKPOINT_MISSING: 'AUDIT_CHECKPOINT_MISSING',
  CHECKPOINT_DIGEST_MISMATCH: 'AUDIT_CHECKPOINT_DIGEST_MISMATCH',
  CHECKPOINT_SIGNATURE_INVALID: 'AUDIT_CHECKPOINT_SIGNATURE_INVALID',
  CHECKPOINT_ROOT_MISMATCH: 'AUDIT_CHECKPOINT_ROOT_MISMATCH',
  CHECKPOINT_RANGE_MISMATCH: 'AUDIT_CHECKPOINT_RANGE_MISMATCH',
  CHECKPOINT_CHAIN_MISMATCH: 'AUDIT_CHECKPOINT_CHAIN_MISMATCH',
  CHECKPOINT_FORK_DETECTED: 'AUDIT_CHECKPOINT_FORK_DETECTED',
  MERKLE_PROOF_INVALID: 'AUDIT_MERKLE_PROOF_INVALID',
  OBSERVER_EVIDENCE_MISSING: 'AUDIT_OBSERVER_EVIDENCE_MISSING',
  OBSERVATION_DIGEST_MISMATCH: 'AUDIT_OBSERVATION_DIGEST_MISMATCH',
  OBSERVATION_SIGNATURE_INVALID: 'AUDIT_OBSERVATION_SIGNATURE_INVALID',
  OBSERVATION_SCOPE_MISMATCH: 'AUDIT_OBSERVATION_SCOPE_MISMATCH',
  UNTRUSTED_OBSERVER: 'AUDIT_UNTRUSTED_OBSERVER',
  OBSERVATION_STALE: 'AUDIT_OBSERVATION_STALE',
  OBSERVATION_CHAIN_MISMATCH: 'AUDIT_OBSERVATION_CHAIN_MISMATCH',
  UNTRUSTED_SUPPORTING_ANCHOR: 'AUDIT_UNTRUSTED_SUPPORTING_ANCHOR',
  SUPPORTING_ANCHOR_INVALID: 'AUDIT_SUPPORTING_ANCHOR_INVALID',
  AUTHORIZATION_EVIDENCE_MISSING: 'AUDIT_AUTHORIZATION_EVIDENCE_MISSING',
  AUTHORIZATION_COLLATERAL_NOT_VERIFIED: 'AUDIT_AUTHORIZATION_COLLATERAL_NOT_VERIFIED',
  CURRENT_AUTHORIZATION_NOT_EVALUATED: 'AUDIT_CURRENT_AUTHORIZATION_NOT_EVALUATED',
  BUNDLE_SCHEMA_INVALID: 'AUDIT_BUNDLE_SCHEMA_INVALID',
  BUNDLE_MANIFEST_DIGEST_MISMATCH: 'AUDIT_BUNDLE_MANIFEST_DIGEST_MISMATCH',
  BUNDLE_SIGNATURE_INVALID: 'AUDIT_BUNDLE_SIGNATURE_INVALID',
  BUNDLE_EXPORTER_UNAUTHORIZED: 'AUDIT_BUNDLE_EXPORTER_UNAUTHORIZED',
  BUNDLE_INVENTORY_MISMATCH: 'AUDIT_BUNDLE_INVENTORY_MISMATCH',
  BUNDLE_COMPONENT_DIGEST_MISMATCH: 'AUDIT_BUNDLE_COMPONENT_DIGEST_MISMATCH',
  BUNDLE_SELECTION_INCOMPLETE: 'AUDIT_BUNDLE_SELECTION_INCOMPLETE',
  VERIFICATION_POLICY_MISMATCH: 'AUDIT_VERIFICATION_POLICY_MISMATCH',
  VERIFICATION_POLICY_INVALID: 'AUDIT_VERIFICATION_POLICY_INVALID',
  EXPLICITLY_REDACTED: 'AUDIT_EXPLICITLY_REDACTED',
  EXPLICITLY_DISPOSED: 'AUDIT_EXPLICITLY_DISPOSED',
  EXPLICITLY_UNAVAILABLE: 'AUDIT_EXPLICITLY_UNAVAILABLE',
} as const);

function dimension(
  verdict: AuditVerificationDimension['verdict'],
  reasonCodes: Iterable<string> = [],
): AuditVerificationDimension {
  return { verdict, reasonCodes: [...new Set(reasonCodes)].sort() };
}

function sameSigner(left: SignerRef, right: SignerRef): boolean {
  return left.did === right.did && left.kid === right.kid && left.alg === right.alg;
}

function keyIsValidAt(policy: HistoricalAuditKeyPolicy, at: number): boolean {
  return (policy.validFrom === undefined || at >= policy.validFrom) &&
    (policy.validUntil === undefined || at <= policy.validUntil);
}

function exactJson(left: unknown, right: unknown): boolean {
  try {
    return canonicalizeJson(left) === canonicalizeJson(right);
  } catch {
    return false;
  }
}

function invalidPolicyReport(policy: unknown): AuditVerificationReportV1 {
  const policyId = typeof policy === 'object' && policy !== null &&
    typeof (policy as { policyId?: unknown }).policyId === 'string'
    ? (policy as { policyId: string }).policyId
    : 'invalid-policy';
  const invalid = dimension('invalid', [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID]);
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0',
    policyId,
    cryptographicIntegrity: invalid,
    chainIntegrity: invalid,
    checkpointIntegrity: invalid,
    anchorIntegrity: invalid,
    scopeEvidenceCompleteness: invalid,
    authorizedAsObserved: dimension('indeterminate', [AUDIT_REASON_CODES.NOT_EVALUATED]),
    currentAuthorization: dimension('indeterminate', [AUDIT_REASON_CODES.NOT_EVALUATED]),
  };
}

export interface AuditArtifactVerifierOptions {
  hasher: AuditHasher;
  signatures: AuditSignatureVerifier;
  verifiedAt?: () => number;
  authorization?: AuditAuthorizationVerifier;
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

/** Pure historical verifier. It never reads live nonce state or applies current freshness. */
export class AuditArtifactVerifier {
  constructor(private readonly options: AuditArtifactVerifierOptions) {}

  async verifyEntries(
    entries: readonly unknown[],
    policy: AuditVerificationPolicyV1 | unknown,
  ): Promise<AuditVerificationReportV1> {
    if (!auditVerificationPolicySchema.safeParse(policy).success) {
      return invalidPolicyReport(policy);
    }
    const verificationPolicy = policy as AuditVerificationPolicyV1;
    const cryptoReasons = new Set<string>();
    const chainReasons = new Set<string>();
    const validatedEntries: SignedAuditEntryV1[] = [];

    if (entries.length === 0) {
      chainReasons.add(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE);
    }

    for (const candidate of entries) {
      const parsed = signedAuditEntrySchema.safeParse(candidate);
      if (!parsed.success) {
        cryptoReasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
        chainReasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
        continue;
      }
      const entry = parsed.data as SignedAuditEntryV1;
      const index = validatedEntries.length;
      await this.verifyEntry(entry, verificationPolicy, cryptoReasons);
      this.verifyChainPosition(entry, validatedEntries[index - 1], index, chainReasons);
      validatedEntries.push(entry);
    }

    const authorizationPresent = validatedEntries.some(
      (entry) => entry.core.event.authorization !== undefined,
    );
    const [authorizedAsObserved, currentAuthorization] =
      this.options.authorization === undefined
        ? [
            dimension('indeterminate', [
              authorizationPresent
                ? AUDIT_REASON_CODES.AUTHORIZATION_COLLATERAL_NOT_VERIFIED
                : AUDIT_REASON_CODES.AUTHORIZATION_EVIDENCE_MISSING,
            ]),
            dimension('indeterminate', [
              AUDIT_REASON_CODES.CURRENT_AUTHORIZATION_NOT_EVALUATED,
            ]),
          ]
        : await Promise.all([
            this.options.authorization.verifyAsObserved(validatedEntries, verificationPolicy),
            this.options.authorization.verifyCurrent(validatedEntries, verificationPolicy),
          ]);
    return {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0',
      policyId: verificationPolicy.policyId,
      ...(this.options.verifiedAt === undefined ? {} : { verifiedAt: this.options.verifiedAt() }),
      cryptographicIntegrity: dimension(
        cryptoReasons.size === 0 && entries.length > 0 ? 'valid' : 'invalid',
        cryptoReasons,
      ),
      chainIntegrity: dimension(
        chainReasons.size === 0 && entries.length > 0 ? 'valid' : 'invalid',
        chainReasons,
      ),
      checkpointIntegrity: dimension('indeterminate', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]),
      anchorIntegrity: dimension('indeterminate', [AUDIT_REASON_CODES.OBSERVER_EVIDENCE_MISSING]),
      scopeEvidenceCompleteness: dimension(
        entries.length > 0 ? 'indeterminate' : 'invalid',
        [AUDIT_REASON_CODES.NOT_EVALUATED],
      ),
      authorizedAsObserved,
      currentAuthorization,
    };
  }

  async verifyCheckpoint(
    checkpoint: SignedAuditCheckpointV1,
    entries: readonly SignedAuditEntryV1[],
    policy: AuditVerificationPolicyV1,
  ): Promise<AuditVerificationDimension> {
    const reasons = new Set<string>();
    if (!auditVerificationPolicySchema.safeParse(policy).success) {
      return dimension('invalid', [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID]);
    }
    const parsedCheckpoint = signedAuditCheckpointSchema.safeParse(checkpoint);
    if (!parsedCheckpoint.success) {
      return dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]);
    }
    const validated = parsedCheckpoint.data as SignedAuditCheckpointV1;
    const core = validated.core;
    if (!policy.acceptedIntegritySuites.includes(core.integritySuite)) {
      reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_SUITE);
    }
    if (!policy.acceptedAlgorithms.includes(core.issuer.alg)) {
      reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM);
    }
    const epochPolicy = policy.trustedLedgerEpochs.find((candidate) =>
      candidate.ledgerId === core.ledgerId &&
      candidate.ledgerEpochId === core.ledgerEpochId);
    if (!epochPolicy?.recorderKeys.some((candidate) =>
      sameSigner(candidate.signer, core.issuer) && keyIsValidAt(candidate, core.createdAt))) {
      reasons.add(AUDIT_REASON_CODES.UNTRUSTED_RECORDER);
    }

    const expectedDigest = await hashAuditValue(
      this.options.hasher,
      AUDIT_DIGEST_DOMAINS.checkpoint,
      core,
    );
    if (expectedDigest !== validated.checkpointDigest) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_DIGEST_MISMATCH);
    }
    if (!(await this.options.signatures.verify(
      canonicalizeJsonBytes(core),
      validated.jws,
      core.issuer,
    ))) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_SIGNATURE_INVALID);
    }

    const expectedSize = Number(core.treeSize);
    const first = entries[0];
    const last = entries[entries.length - 1];
    if (!Number.isSafeInteger(expectedSize) ||
      expectedSize !== entries.length ||
      first?.core.sequence !== core.firstSequence ||
      last?.core.sequence !== core.lastSequence ||
      last?.entryDigest !== core.headEntryDigest ||
      entries.some((entry) => entry.core.ledgerId !== core.ledgerId ||
        entry.core.ledgerEpochId !== core.ledgerEpochId)) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH);
    } else {
      const root = await new Rfc9162MerkleTree(this.options.hasher)
        .root(entries.map((entry) => entry.entryDigest));
      if (root !== core.rootDigest) reasons.add(AUDIT_REASON_CODES.CHECKPOINT_ROOT_MISMATCH);
    }
    return dimension(reasons.size === 0 ? 'valid' : 'invalid', reasons);
  }

  async verifyObservation(
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditObservationReceiptV1,
    policy: AuditVerificationPolicyV1,
  ): Promise<AuditVerificationDimension> {
    const reasons = new Set<string>();
    let freshnessIndeterminate = false;
    if (!auditVerificationPolicySchema.safeParse(policy).success) {
      return dimension('invalid', [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID]);
    }
    const parsedCheckpoint = signedAuditCheckpointSchema.safeParse(checkpoint);
    const parsedReceipt = auditObservationReceiptSchema.safeParse(receipt);
    if (!parsedCheckpoint.success || !parsedReceipt.success) {
      return dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]);
    }
    const validatedCheckpoint = parsedCheckpoint.data as SignedAuditCheckpointV1;
    const validatedReceipt = parsedReceipt.data as AuditObservationReceiptV1;
    const core = validatedReceipt.core;
    if (core.schema !==
      'https://schema.kya-os.org/v1/protocol/audit/observation/v1.0.0') {
      reasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
    }
    if (core.ledgerId !== validatedCheckpoint.core.ledgerId ||
      core.ledgerEpochId !== validatedCheckpoint.core.ledgerEpochId ||
      core.checkpointDigest !== validatedCheckpoint.checkpointDigest ||
      core.treeSize !== validatedCheckpoint.core.treeSize) {
      reasons.add(AUDIT_REASON_CODES.OBSERVATION_SCOPE_MISMATCH);
    }
    if (!policy.acceptedAlgorithms.includes(core.observer.alg)) {
      reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM);
    }
    if (!policy.trustedObservers.some((candidate) =>
      sameSigner(candidate.signer, core.observer) &&
      keyIsValidAt(candidate, core.observedAt))) {
      reasons.add(AUDIT_REASON_CODES.UNTRUSTED_OBSERVER);
    }
    if (policy.requiredCheckpointFreshnessMs !== undefined) {
      const now = this.options.verifiedAt?.();
      if (now === undefined) {
        reasons.add(AUDIT_REASON_CODES.NOT_EVALUATED);
        freshnessIndeterminate = true;
      } else if (now - core.observedAt > policy.requiredCheckpointFreshnessMs) {
        reasons.add(AUDIT_REASON_CODES.OBSERVATION_STALE);
      }
    }
    const digest = await hashAuditValue(
      this.options.hasher,
      AUDIT_DIGEST_DOMAINS.observation,
      core,
    );
    if (digest !== validatedReceipt.observationDigest) {
      reasons.add(AUDIT_REASON_CODES.OBSERVATION_DIGEST_MISMATCH);
    }
    if (!(await this.options.signatures.verify(
      canonicalizeJsonBytes(core),
      validatedReceipt.jws,
      core.observer,
    ))) {
      reasons.add(AUDIT_REASON_CODES.OBSERVATION_SIGNATURE_INVALID);
    }
    const onlyIndeterminate = freshnessIndeterminate &&
      [...reasons].every((reason) => reason === AUDIT_REASON_CODES.NOT_EVALUATED);
    return dimension(reasons.size === 0 ? 'valid' : onlyIndeterminate ? 'indeterminate' : 'invalid', reasons);
  }

  private async verifyEntry(
    entry: SignedAuditEntryV1,
    policy: AuditVerificationPolicyV1,
    reasons: Set<string>,
  ): Promise<void> {
    if (!policy.acceptedIntegritySuites.includes(entry.core.integritySuite)) {
      reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_SUITE);
    }
    if (!policy.acceptedAlgorithms.includes(entry.core.recorder.alg)) {
      reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM);
    }

    const epochPolicy = policy.trustedLedgerEpochs.find((candidate) =>
      candidate.ledgerId === entry.core.ledgerId &&
      candidate.ledgerEpochId === entry.core.ledgerEpochId);
    const trustedKey = epochPolicy?.recorderKeys.find((candidate) =>
      sameSigner(candidate.signer, entry.core.recorder) &&
      keyIsValidAt(candidate, entry.core.recordedAt));
    if (trustedKey === undefined) reasons.add(AUDIT_REASON_CODES.UNTRUSTED_RECORDER);

    const eventDigest = await digestAuditEvent(this.options.hasher, entry.core.event);
    if (eventDigest !== entry.core.eventDigest || eventDigest !== entry.eventDigest) {
      reasons.add(AUDIT_REASON_CODES.EVENT_DIGEST_MISMATCH);
    }
    const evidenceDigest = await digestAuditEvidenceManifest(
      this.options.hasher,
      entry.core.event,
    );
    if (evidenceDigest !== entry.core.evidenceManifestDigest) {
      reasons.add(AUDIT_REASON_CODES.EVIDENCE_MANIFEST_DIGEST_MISMATCH);
    }
    const entryDigest = await digestAuditEntry(this.options.hasher, entry.core);
    if (entryDigest !== entry.entryDigest) reasons.add(AUDIT_REASON_CODES.ENTRY_DIGEST_MISMATCH);

    const expectedReceipt = buildAuditRecorderReceiptCore(entry.core, entry.entryDigest);
    if (!exactJson(expectedReceipt, entry.recorderReceipt.core)) {
      reasons.add(AUDIT_REASON_CODES.RECEIPT_MISMATCH);
    }
    if (!(await this.options.signatures.verify(
      canonicalizeJsonBytes(entry.recorderReceipt.core),
      entry.recorderReceipt.jws,
      entry.core.recorder,
    ))) {
      reasons.add(AUDIT_REASON_CODES.SIGNATURE_INVALID);
    }
  }

  private verifyChainPosition(
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
}

export function mergeAuditDimensions(
  ...values: readonly AuditVerificationDimension[]
): AuditVerificationDimension {
  if (values.length === 0) {
    // An empty merge must never inherit a passing verdict by vacuous truth.
    return dimension('indeterminate', [AUDIT_REASON_CODES.NOT_EVALUATED]);
  }
  const verdict = values.some((value) => value.verdict === 'invalid')
    ? 'invalid'
    : values.every((value) => value.verdict === 'valid') ? 'valid' : 'indeterminate';
  return dimension(verdict, values.flatMap((value) => value.reasonCodes));
}
