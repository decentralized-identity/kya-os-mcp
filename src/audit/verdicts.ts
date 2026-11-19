/**
 * The vocabulary of an audit verification report: its reason codes, how a set of reasons becomes a
 * verdict, how dimensions merge, and how a policy's required audit profile is applied. The artifact
 * verifier (`./verifier.ts`) and the bundle verifier (`./replay-bundle.ts`) both build their
 * reports from here; `./verifier.ts` re-exports the public part, so imports from there are
 * unchanged.
 */

import type {
  AuditVerificationDimension,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
} from './types.js';

export const AUDIT_REASON_CODES = Object.freeze({
  NOT_EVALUATED: 'AUDIT_NOT_EVALUATED',
  SCHEMA_INVALID: 'AUDIT_SCHEMA_INVALID',
  UNSUPPORTED_SUITE: 'AUDIT_UNSUPPORTED_SUITE',
  UNSUPPORTED_ALGORITHM: 'AUDIT_UNSUPPORTED_ALGORITHM',
  UNTRUSTED_RECORDER: 'AUDIT_UNTRUSTED_RECORDER',
  KEY_BOUNDARY_UNRESOLVED: 'AUDIT_KEY_BOUNDARY_UNRESOLVED',
  KEY_NOT_CURRENT: 'AUDIT_KEY_NOT_CURRENT',
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
  MERKLE_PROOF_MISSING: 'AUDIT_MERKLE_PROOF_MISSING',
  OBSERVER_EVIDENCE_MISSING: 'AUDIT_OBSERVER_EVIDENCE_MISSING',
  OBSERVATION_DIGEST_MISMATCH: 'AUDIT_OBSERVATION_DIGEST_MISMATCH',
  OBSERVATION_SIGNATURE_INVALID: 'AUDIT_OBSERVATION_SIGNATURE_INVALID',
  OBSERVATION_SCOPE_MISMATCH: 'AUDIT_OBSERVATION_SCOPE_MISMATCH',
  UNTRUSTED_OBSERVER: 'AUDIT_UNTRUSTED_OBSERVER',
  OBSERVATION_STALE: 'AUDIT_OBSERVATION_STALE',
  OBSERVATION_FUTURE_DATED: 'AUDIT_OBSERVATION_FUTURE_DATED',
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
  REQUIRED_PROFILE_UNMET: 'AUDIT_REQUIRED_PROFILE_UNMET',
  EXPLICITLY_REDACTED: 'AUDIT_EXPLICITLY_REDACTED',
  EXPLICITLY_DISPOSED: 'AUDIT_EXPLICITLY_DISPOSED',
  EXPLICITLY_UNAVAILABLE: 'AUDIT_EXPLICITLY_UNAVAILABLE',
  EXPLICITLY_POLICY_EXCLUDED: 'AUDIT_EXPLICITLY_POLICY_EXCLUDED',
} as const);

/** Reasons that mean "not decidable from the supplied collateral", never "wrong". */
const INDETERMINATE_REASONS: ReadonlySet<string> = new Set([
  AUDIT_REASON_CODES.NOT_EVALUATED,
  AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED,
]);

/** Dimensions each audit assurance profile requires to be `valid`, in level order. */
const PROFILE_DIMENSIONS = [
  'cryptographicIntegrity',
  'chainIntegrity',
  'checkpointIntegrity',
  'anchorIntegrity',
] as const;

export function dimension(
  verdict: AuditVerificationDimension['verdict'],
  reasonCodes: Iterable<string> = [],
): AuditVerificationDimension {
  return { verdict, reasonCodes: [...new Set(reasonCodes)].sort() };
}

export function verdictOf(reasons: ReadonlySet<string>): AuditVerificationDimension['verdict'] {
  if (reasons.size === 0) return 'valid';
  return [...reasons].every((reason) => INDETERMINATE_REASONS.has(reason))
    ? 'indeterminate'
    : 'invalid';
}

export function invalidPolicyReport(policy: unknown): AuditVerificationReportV1 {
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

/**
 * Marks every dimension the policy's `requiredAuditProfile` depends on as
 * invalid unless it is `valid`: AAP-1 needs cryptographic integrity, AAP-2
 * adds chain integrity, AAP-3 adds checkpoint integrity, and AAP-4 adds
 * observation integrity backed by a supporting anchor receipt.
 */
export function applyRequiredAuditProfile(
  report: AuditVerificationReportV1,
  policy: AuditVerificationPolicyV1,
  evidence: { supportingAnchors: boolean } = { supportingAnchors: false },
): AuditVerificationReportV1 {
  if (policy.requiredAuditProfile === undefined) return report;
  const level = Number(policy.requiredAuditProfile.slice(-1));
  const result = { ...report };
  for (const name of PROFILE_DIMENSIONS.slice(0, level)) {
    const unmet = report[name].verdict !== 'valid' ||
      (name === 'anchorIntegrity' && !evidence.supportingAnchors);
    if (unmet) {
      result[name] = dimension('invalid', [
        ...report[name].reasonCodes,
        AUDIT_REASON_CODES.REQUIRED_PROFILE_UNMET,
      ]);
    }
  }
  return result;
}

export function mergeAuditDimensions(
  ...values: readonly AuditVerificationDimension[]
): AuditVerificationDimension {
  return mergeDimensionList(values);
}

/**
 * {@link mergeAuditDimensions} over a list. Use it for a list whose length a bundle decides, one
 * dimension per item the bundle carries: spread into a call, such a list can exceed the engine's
 * argument limit.
 */
export function mergeDimensionList(
  values: readonly AuditVerificationDimension[],
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
