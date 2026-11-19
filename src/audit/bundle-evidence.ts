/**
 * What a replay bundle's entries, observations and supporting anchors prove, and whether its
 * entries complete the ledger ranges it selects.
 */

import {
  compareDecimal,
  ledgerEpochKey,
} from './bundle-components.js';
import { validAt } from './key-trust.js';
import { auditAnchorReceiptSchema, signedAuditEntrySchema } from './schemas.js';
import type {
  AuditAnchorReceipt,
  AuditBundleComponentV1,
  AuditBundleDisposition,
  AuditBundleSelectionV1,
  AuditObservationReceiptV1,
  AuditVerificationDimension,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import { AUDIT_REASON_CODES, dimension, mergeDimensionList } from './verdicts.js';
import type { AuditArtifactVerifier } from './verifier.js';
import type { AuditVerificationContext } from './verifier-types.js';

/** Verifies a supporting anchor's receipt for a checkpoint, as `verifyAuditBundle` is given one. */
/** The members of a verification report that are dimensions. */
type AuditReportDimensionName = {
  [Name in keyof AuditVerificationReportV1]-?:
    AuditVerificationReportV1[Name] extends AuditVerificationDimension ? Name : never;
}[keyof AuditVerificationReportV1];

/** The reason each disposition of an omitted component gives: none is left unreported. */
const OMISSION_REASONS: Readonly<Record<Exclude<AuditBundleDisposition, 'included'>, string>> = {
  redacted: AUDIT_REASON_CODES.EXPLICITLY_REDACTED,
  disposed: AUDIT_REASON_CODES.EXPLICITLY_DISPOSED,
  unavailable: AUDIT_REASON_CODES.EXPLICITLY_UNAVAILABLE,
  policy_excluded: AUDIT_REASON_CODES.EXPLICITLY_POLICY_EXCLUDED,
};

export type SupportingAnchorVerifier = (
  checkpoint: SignedAuditCheckpointV1,
  receipt: AuditAnchorReceipt,
) => Promise<boolean>;

export async function verifyEntryGroups(
  entries: readonly unknown[],
  policy: AuditVerificationPolicyV1,
  artifacts: AuditArtifactVerifier,
  context: AuditVerificationContext,
): Promise<AuditVerificationReportV1> {
  const groups = new Map<string, SignedAuditEntryV1[]>();
  const malformed: unknown[] = [];
  for (const candidate of entries) {
    if (!signedAuditEntrySchema.safeParse(candidate).success) {
      malformed.push(candidate);
      continue;
    }
    const entry = candidate as SignedAuditEntryV1;
    const key = ledgerEpochKey(entry.core);
    const group = groups.get(key) ?? [];
    group.push(entry);
    groups.set(key, group);
  }
  const reports = await Promise.all([
    ...[...groups.values()].map((group) => artifacts.verifyEntries(group, policy, context)),
    ...(malformed.length === 0 ? [] : [artifacts.verifyEntries(malformed, policy, context)]),
  ]);
  if (reports.length === 0) return artifacts.verifyEntries([], policy, context);
  const merged = (name: AuditReportDimensionName): AuditVerificationDimension =>
    mergeDimensionList(reports.map((report) => report[name]));
  return {
    ...reports[0]!,
    cryptographicIntegrity: merged('cryptographicIntegrity'),
    chainIntegrity: merged('chainIntegrity'),
    checkpointIntegrity: merged('checkpointIntegrity'),
    anchorIntegrity: merged('anchorIntegrity'),
    scopeEvidenceCompleteness: merged('scopeEvidenceCompleteness'),
    authorizedAsObserved: merged('authorizedAsObserved'),
    currentAuthorization: merged('currentAuthorization'),
  };
}

export function verifyObservationHistory(
  observations: readonly AuditObservationReceiptV1[],
): AuditVerificationDimension {
  const reasons = new Set<string>();
  const groups = new Map<string, AuditObservationReceiptV1[]>();
  for (const receipt of observations) {
    const key = `${ledgerEpochKey(receipt.core)}\0${receipt.core.observerId}`;
    const group = groups.get(key) ?? [];
    group.push(receipt);
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    group.sort((left, right) =>
      left.core.observedAt - right.core.observedAt ||
      compareDecimal(left.core.treeSize, right.core.treeSize));
    for (let index = 1; index < group.length; index += 1) {
      if (group[index]!.core.previousObservationDigest !==
        group[index - 1]!.observationDigest) {
        reasons.add(AUDIT_REASON_CODES.OBSERVATION_CHAIN_MISMATCH);
      }
    }
  }
  return dimension(reasons.size === 0 ? 'valid' : 'invalid', reasons);
}

export async function verifySupportingAnchors(
  candidates: readonly unknown[],
  checkpoints: readonly SignedAuditCheckpointV1[],
  policy: AuditVerificationPolicyV1,
  verifyReceipt: SupportingAnchorVerifier | undefined,
): Promise<AuditVerificationDimension> {
  const reasons = new Set<string>();
  let notEvaluated = false;
  for (const candidate of candidates) {
    if (!auditAnchorReceiptSchema.safeParse(candidate).success) {
      reasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
      continue;
    }
    const receipt = candidate as AuditAnchorReceipt;
    const checkpoint = checkpoints.find((value) =>
      value.checkpointDigest === receipt.checkpointDigest);
    const trusted = policy.trustedSupportingAnchors?.some((value) =>
      value.kind === receipt.kind && value.providerId === receipt.providerId &&
      validAt(value, receipt.issuedAt)) ?? false;
    if (!trusted) reasons.add(AUDIT_REASON_CODES.UNTRUSTED_SUPPORTING_ANCHOR);
    if (checkpoint === undefined) {
      reasons.add(AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID);
    } else if (verifyReceipt === undefined) {
      reasons.add(AUDIT_REASON_CODES.NOT_EVALUATED);
      notEvaluated = true;
    } else if ((await verifyReceipt(checkpoint, receipt)) !== true) {
      reasons.add(AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID);
    }
  }
  const invalid = [...reasons].some((reason) => reason !== AUDIT_REASON_CODES.NOT_EVALUATED);
  return dimension(invalid ? 'invalid' : notEvaluated ? 'indeterminate' : 'valid', reasons);
}

export function selectionCompleteness(
  selections: readonly AuditBundleSelectionV1[],
  entries: readonly SignedAuditEntryV1[],
  components: readonly AuditBundleComponentV1[],
): AuditVerificationDimension {
  const reasons = new Set<string>();
  for (const selection of selections) {
    const selected = entries.filter((entry) =>
      entry.core.ledgerId === selection.ledgerId &&
      entry.core.ledgerEpochId === selection.ledgerEpochId);
    const uniqueBySequence = new Map<string, SignedAuditEntryV1>();
    let hasDuplicateSequence = false;
    for (const entry of selected) {
      if (uniqueBySequence.has(entry.core.sequence)) hasDuplicateSequence = true;
      else uniqueBySequence.set(entry.core.sequence, entry);
    }
    const ordered = [...uniqueBySequence.values()].sort((left, right) => {
      const leftSequence = BigInt(left.core.sequence);
      const rightSequence = BigInt(right.core.sequence);
      return leftSequence < rightSequence ? -1 : leftSequence > rightSequence ? 1 : 0;
    });
    let expectedCount: bigint;
    try {
      expectedCount = BigInt(selection.lastSequence) - BigInt(selection.firstSequence) + 1n;
    } catch {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE);
      continue;
    }
    let contiguous = true;
    for (let index = 1; index < ordered.length; index += 1) {
      if (BigInt(ordered[index]!.core.sequence) !==
        BigInt(ordered[index - 1]!.core.sequence) + 1n) {
        contiguous = false;
        break;
      }
    }
    if (hasDuplicateSequence || !contiguous || expectedCount < 1n ||
      expectedCount !== BigInt(ordered.length) ||
      ordered[0]?.core.sequence !== selection.firstSequence ||
      ordered[ordered.length - 1]?.core.sequence !== selection.lastSequence ||
      ordered[ordered.length - 1]?.entryDigest !== selection.expectedHeadDigest) {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE);
    }
  }
  for (const { disposition } of components) {
    if (disposition !== 'included') reasons.add(OMISSION_REASONS[disposition]);
  }
  if (reasons.has(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE)) return dimension('invalid', reasons);
  return reasons.size === 0 ? dimension('valid') : dimension('indeterminate', reasons);
}
