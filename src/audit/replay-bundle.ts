import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import {
  AUDIT_BUNDLE_MEDIA_TYPES,
  assertPath,
  componentMetadata,
  firstByKey,
  includedArrays,
} from './bundle-components.js';
import {
  checkpointBindings,
  coversEverySelection,
  verifyCheckpointHistory,
  verifyMerkleProofComponents,
} from './bundle-checkpoints.js';
import {
  selectionCompleteness,
  verifyEntryGroups,
  verifyObservationHistory,
  verifySupportingAnchors,
} from './bundle-evidence.js';
import type { AuditHasher, AuditSignatureVerifier } from './crypto.js';
import { BUNDLE_SCHEMA } from './bundle-exporter.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_DIGEST_DOMAINS } from './integrity.js';
import { sameSigner, validAt } from './key-trust.js';
import {
  auditAnchorReceiptSchema,
  auditBundleConsistencyProofSchema,
  auditBundleInclusionProofSchema,
  auditObservationReceiptSchema,
  auditReplayBundleSchema,
  auditVerificationPolicySchema,
  signedAuditCheckpointSchema,
  signedAuditEntrySchema,
} from './schemas.js';
import type {
  AuditBundleManifestCoreV1,
  AuditLedgerRef,
  AuditObservationReceiptV1,
  AuditAnchorReceipt,
  AuditReplayBundleV1,
  AuditVerificationDimension,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import { withCarriedEvidence } from './key-dating-evidence.js';
import { dimension, mergeDimensionList, verdictOf } from './verdicts.js';
import {
  AUDIT_REASON_CODES,
  AuditArtifactVerifier,
  applyRequiredAuditProfile,
  mergeAuditDimensions,
  type AuditVerificationContext,
} from './verifier.js';

export { AUDIT_BUNDLE_MEDIA_TYPES } from './bundle-components.js';
export {
  AuditReplayBundleExporter,
  type AuditBundleComponentInput,
  type AuditReplayBundleExporterOptions,
  type AuditReplayBundleExportInput,
} from './bundle-exporter.js';

function malformedBundleReport(policy: AuditVerificationPolicyV1): AuditVerificationReportV1 {
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0',
    policyId: policy.policyId,
    cryptographicIntegrity: dimension('invalid', [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID]),
    chainIntegrity: dimension('invalid', [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID]),
    checkpointIntegrity: dimension('indeterminate', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]),
    anchorIntegrity: dimension('indeterminate', [AUDIT_REASON_CODES.OBSERVER_EVIDENCE_MISSING]),
    scopeEvidenceCompleteness: dimension('invalid', [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID]),
    authorizedAsObserved: dimension('indeterminate', [
      AUDIT_REASON_CODES.AUTHORIZATION_COLLATERAL_NOT_VERIFIED,
    ]),
    currentAuthorization: dimension('indeterminate', [
      AUDIT_REASON_CODES.CURRENT_AUTHORIZATION_NOT_EVALUATED,
    ]),
  };
}

export interface VerifyAuditBundleDependencies {
  hasher: AuditHasher;
  signatures: AuditSignatureVerifier;
  artifacts?: AuditArtifactVerifier;
  /**
   * The verifier's clock, used when `artifacts` is not given. A key whose validity has ended by
   * then makes what it signed undecided unless evidence dates it before the end; with no clock,
   * any key with an end is taken to have ended.
   */
  verifiedAt?: () => number;
  verifySupportingAnchor?: (
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditAnchorReceipt,
  ) => Promise<boolean>;
}

/**
 * An export has no ledger position, so an exporter key bounded by
 * `validFromCheckpoint` or `validUntilCheckpoint` can neither be confirmed nor
 * refuted here: such a key leaves the exporter `unresolved`, never authorized.
 */
function exporterAuthorization(
  core: AuditBundleManifestCoreV1,
  policy: AuditVerificationPolicyV1,
): 'authorized' | 'unresolved' | 'unauthorized' {
  let result: 'unresolved' | 'unauthorized' = 'unauthorized';
  for (const authorization of policy.authorizedExporters) {
    if (!authorization.allowedPurposes.includes(core.purpose) ||
      !core.selections.every((selection) =>
        authorization.allowedLedgerIds.includes(selection.ledgerId))) continue;
    for (const key of authorization.signerKeys) {
      if (!sameSigner(key.signer, core.exporter) || !validAt(key, core.exportedAt)) continue;
      if (key.validFromCheckpoint === undefined && key.validUntilCheckpoint === undefined) {
        return 'authorized';
      }
      result = 'unresolved';
    }
  }
  return result;
}

/** Offline bundle verification. Trust is supplied only through the policy argument. */
export async function verifyAuditBundle(
  bundle: AuditReplayBundleV1 | unknown,
  policy: AuditVerificationPolicyV1,
  dependencies: VerifyAuditBundleDependencies,
): Promise<AuditVerificationReportV1> {
  if (!auditVerificationPolicySchema.safeParse(policy).success) {
    const policyId = typeof (policy as { policyId?: unknown })?.policyId === 'string'
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
  if (!auditReplayBundleSchema.safeParse(bundle).success) {
    return applyRequiredAuditProfile(malformedBundleReport(policy), policy);
  }
  const replayBundle = bundle as AuditReplayBundleV1;
  const reasons = new Set<string>();
  const core = replayBundle.manifest.core;
  if (core?.schema !== BUNDLE_SCHEMA || core.formatVersion !== '1.0.0') {
    reasons.add(AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID);
  }
  if (!policy.acceptedIntegritySuites.includes(core?.integritySuite ?? '')) {
    reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_SUITE);
  }
  if (core === undefined || !policy.acceptedAlgorithms.includes(core.exporter.alg)) {
    reasons.add(AUDIT_REASON_CODES.UNSUPPORTED_ALGORITHM);
  }
  const exporter = core === undefined ? 'unauthorized' : exporterAuthorization(core, policy);
  if (exporter === 'unauthorized') reasons.add(AUDIT_REASON_CODES.BUNDLE_EXPORTER_UNAUTHORIZED);
  if (exporter === 'unresolved') reasons.add(AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED);

  if (core !== undefined) {
    const [manifestDigest, policyDigest] = await Promise.all([
      hashAuditValue(dependencies.hasher, AUDIT_DIGEST_DOMAINS.bundleManifest, core),
      hashAuditValue(
        dependencies.hasher,
        'org.kya-os.audit.verification-policy.v1',
        policy,
      ),
    ]);
    if (manifestDigest !== replayBundle.manifest.manifestDigest) {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_MANIFEST_DIGEST_MISMATCH);
    }
    if (policyDigest !== core.verificationPolicyDigest) {
      reasons.add(AUDIT_REASON_CODES.VERIFICATION_POLICY_MISMATCH);
    }
    if ((await dependencies.signatures.verify(
      canonicalizeJsonBytes(core),
      replayBundle.manifest.jws,
      core.exporter,
    )) !== true) {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_SIGNATURE_INVALID);
    }

    const inventoryByPath = new Map(core.inventory.map((item) => [item.path, item]));
    const componentsByPath = new Map(replayBundle.components.map((item) => [item.path, item]));
    if (inventoryByPath.size !== core.inventory.length ||
      componentsByPath.size !== replayBundle.components.length ||
      inventoryByPath.size !== componentsByPath.size) {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_INVENTORY_MISMATCH);
    }
    for (const [path, item] of inventoryByPath) {
      const component = componentsByPath.get(path);
      if (component === undefined ||
        canonicalizeJson(item) !== canonicalizeJson(componentMetadata(component))) {
        reasons.add(AUDIT_REASON_CODES.BUNDLE_INVENTORY_MISMATCH);
        continue;
      }
      try {
        assertPath(path);
      } catch {
        reasons.add(AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID);
      }
      if (component.disposition === 'included') {
        if (component.content === undefined) {
          reasons.add(AUDIT_REASON_CODES.BUNDLE_INVENTORY_MISMATCH);
          continue;
        }
        const bytes = canonicalizeJsonBytes(component.content);
        if (component.size !== String(bytes.length) ||
          component.digest !== await dependencies.hasher.sha256(bytes)) {
          reasons.add(AUDIT_REASON_CODES.BUNDLE_COMPONENT_DIGEST_MISMATCH);
        }
      } else if (component.content !== undefined || component.reasonCode === undefined) {
        reasons.add(AUDIT_REASON_CODES.BUNDLE_INVENTORY_MISMATCH);
      }
    }
  }

  const entryCandidates = includedArrays<unknown>(
    replayBundle,
    AUDIT_BUNDLE_MEDIA_TYPES.entries,
  );
  const checkpointCandidates = includedArrays<unknown>(
    replayBundle,
    AUDIT_BUNDLE_MEDIA_TYPES.checkpoints,
  );
  const observationCandidates = includedArrays<unknown>(
    replayBundle,
    AUDIT_BUNDLE_MEDIA_TYPES.observations,
  );
  const anchorCandidates = includedArrays<unknown>(
    replayBundle,
    AUDIT_BUNDLE_MEDIA_TYPES.anchors,
  );
  const entries = entryCandidates.filter((candidate): candidate is SignedAuditEntryV1 =>
    signedAuditEntrySchema.safeParse(candidate).success);
  // Frozen, so the verifier indexes the key boundaries they state only once.
  const checkpoints = Object.freeze(checkpointCandidates.filter(
    (candidate): candidate is SignedAuditCheckpointV1 =>
      signedAuditCheckpointSchema.safeParse(candidate).success,
  ));
  const observations = observationCandidates.filter(
    (candidate): candidate is AuditObservationReceiptV1 =>
      auditObservationReceiptSchema.safeParse(candidate).success,
  );
  const proofScopes = [
    ...includedArrays<unknown>(replayBundle, AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs)
      .filter((candidate) => auditBundleInclusionProofSchema.safeParse(candidate).success),
    ...includedArrays<unknown>(replayBundle, AUDIT_BUNDLE_MEDIA_TYPES.consistencyProofs)
      .filter((candidate) => auditBundleConsistencyProofSchema.safeParse(candidate).success),
  ] as AuditLedgerRef[];
  const artifacts = dependencies.artifacts ?? new AuditArtifactVerifier(dependencies);
  const proofs = await verifyMerkleProofComponents(
    replayBundle,
    entries,
    checkpoints,
    dependencies.hasher,
  );
  // The bundle's own checkpoints are what checkpoint-bounded key policies name.
  const supporting: AuditVerificationContext = { checkpoints };
  const checkpointsByDigest = firstByKey(checkpoints, (checkpoint) => checkpoint.checkpointDigest);
  const observationResults: AuditVerificationDimension[] = [];
  const observed: AuditObservationReceiptV1[] = [];
  for (const candidate of observationCandidates) {
    if (!auditObservationReceiptSchema.safeParse(candidate).success) {
      observationResults.push(dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]));
      continue;
    }
    const receipt = candidate as AuditObservationReceiptV1;
    const checkpoint = checkpointsByDigest.get(receipt.core.checkpointDigest);
    const result = checkpoint === undefined
      ? dimension('invalid', [AUDIT_REASON_CODES.OBSERVATION_SCOPE_MISMATCH])
      : await artifacts.verifyObservation(checkpoint, receipt, policy, supporting);
    if (result.verdict === 'valid') observed.push(receipt);
    observationResults.push(result);
  }
  const anchors = await verifySupportingAnchors(
    anchorCandidates,
    checkpoints,
    policy,
    dependencies.verifySupportingAnchor,
  );
  // With the proofs, observations and anchors that verified, and any successor genesis the
  // bundle carries, they date records whose key has ended.
  const context = withCarriedEvidence({
    checkpoints,
    // Each is verified before it dates anything.
    successorGeneses: includedArrays<SignedAuditEntryV1>(
      replayBundle,
      AUDIT_BUNDLE_MEDIA_TYPES.successorGeneses,
    ),
  }, {
    entries,
    inclusions: proofs.inclusions,
    extensions: proofs.extensions,
    observations: observed,
    anchors: anchors.verified,
  });
  const artifactReport = await verifyEntryGroups(entryCandidates, policy, artifacts, context);
  let checkpointDimension = artifactReport.checkpointIntegrity;
  if (checkpointCandidates.length > 0) {
    const binding = await checkpointBindings(
      checkpoints,
      entries,
      proofs.inclusionCounts,
      dependencies.hasher,
    );
    const checkpointResults: AuditVerificationDimension[] = [];
    for (const candidate of checkpointCandidates) {
      if (!signedAuditCheckpointSchema.safeParse(candidate).success) {
        checkpointResults.push(dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]));
        continue;
      }
      const checkpoint = candidate as SignedAuditCheckpointV1;
      checkpointResults.push(mergeAuditDimensions(
        await artifacts.verifySignedCheckpoint(checkpoint, policy, context),
        binding(checkpoint),
      ));
    }
    checkpointResults.push(
      verifyCheckpointHistory(checkpoints, entries, core.selections, proofs.consistencies),
      proofs.dimension,
    );
    checkpointDimension = mergeDimensionList(checkpointResults);
  } else if (core.selections.some((selection) => selection.checkpointTreeSizes.length > 0)) {
    checkpointDimension = dimension('invalid', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]);
  }
  // Checkpoint and observation verdicts speak for the selected entries only
  // through a checkpoint that holds them all.
  const named = (digests: readonly string[]): SignedAuditCheckpointV1[] => {
    const set = new Set(digests);
    return checkpoints.filter((checkpoint) => set.has(checkpoint.checkpointDigest));
  };
  if (!coversEverySelection(core.selections, checkpoints)) {
    checkpointDimension = mergeAuditDimensions(
      checkpointDimension,
      dimension('indeterminate', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]),
    );
  }
  let anchorDimension = artifactReport.anchorIntegrity;
  if (observationCandidates.length > 0) {
    observationResults.push(verifyObservationHistory(observations));
    anchorDimension = mergeDimensionList(observationResults);
  }
  if (!coversEverySelection(
    core.selections,
    named(observations.map((receipt) => receipt.core.checkpointDigest)),
  )) {
    anchorDimension = mergeAuditDimensions(
      anchorDimension,
      dimension('indeterminate', [AUDIT_REASON_CODES.OBSERVER_EVIDENCE_MISSING]),
    );
  }
  if (anchorCandidates.length > 0) {
    anchorDimension = mergeAuditDimensions(anchorDimension, anchors.dimension);
  }

  // Nothing dates an export: once the exporter's key has ended, its manifest is its word alone.
  if (core !== undefined && exporter === 'authorized' && artifacts.keyHasEnded(
    policy.authorizedExporters.flatMap((authorization) => authorization.signerKeys),
    core.exporter,
  )) {
    reasons.add(AUDIT_REASON_CODES.KEY_ENDED_UNDATED);
  }
  // An exporter key bound that cannot be placed, or an exporter key that has ended, leaves the
  // manifest undecided, never valid; any other manifest reason is a failure.
  const manifestDimension = dimension(verdictOf(reasons), reasons);
  // Entry recorder keys were already evaluated per ledger epoch group.
  const currentKeys = artifacts.verifyCurrentKeys(policy, {
    checkpoints,
    observations,
    exporter: core.exporter,
  });
  return applyRequiredAuditProfile({
    ...artifactReport,
    cryptographicIntegrity: mergeAuditDimensions(
      manifestDimension,
      artifactReport.cryptographicIntegrity,
    ),
    checkpointIntegrity: checkpointDimension,
    anchorIntegrity: anchorDimension,
    scopeEvidenceCompleteness: selectionCompleteness(
      core.selections,
      entries,
      [
        ...checkpoints.map((checkpoint) => checkpoint.core),
        ...observations.map((receipt) => receipt.core),
        ...proofScopes,
      ],
      replayBundle.components,
    ),
    currentAuthorization: currentKeys === undefined
      ? artifactReport.currentAuthorization
      : mergeAuditDimensions(artifactReport.currentAuthorization, currentKeys),
  }, policy, {
    supportingAnchors: coversEverySelection(core.selections, named(anchorCandidates
      .filter((candidate): candidate is AuditAnchorReceipt =>
        auditAnchorReceiptSchema.safeParse(candidate).success)
      .map((receipt) => receipt.checkpointDigest))),
  });
}
