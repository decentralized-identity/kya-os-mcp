import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import {
  AUDIT_BUNDLE_MEDIA_TYPES,
  assertPath,
  componentMetadata,
  includedArrays,
  sameLedgerEpoch,
} from './bundle-components.js';
import {
  isCompletePrefix,
  verifyCheckpointHistory,
  verifyInclusionBinding,
  verifyMerkleProofComponents,
} from './bundle-checkpoints.js';
import {
  selectionCompleteness,
  verifyEntryGroups,
  verifyObservationHistory,
  verifySupportingAnchors,
} from './bundle-evidence.js';
import type { AuditHasher, AuditSignatureVerifier, AuditSigner } from './crypto.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_DIGEST_DOMAINS } from './integrity.js';
import { sameSigner, validAt } from './key-trust.js';
import {
  auditObservationReceiptSchema,
  auditReplayBundleSchema,
  auditVerificationPolicySchema,
  parseAuditBundleManifestCore,
  signedAuditCheckpointSchema,
  signedAuditEntrySchema,
} from './schemas.js';
import type {
  AuditBundleComponentV1,
  AuditBundleDisposition,
  AuditBundleManifestCoreV1,
  AuditObservationReceiptV1,
  AuditBundleSelectionV1,
  AuditAnchorReceipt,
  AuditReplayBundleV1,
  AuditVerificationDimension,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import { dimension } from './verdicts.js';
import {
  AUDIT_REASON_CODES,
  AuditArtifactVerifier,
  applyRequiredAuditProfile,
  mergeAuditDimensions,
  type AuditVerificationContext,
} from './verifier.js';

export { AUDIT_BUNDLE_MEDIA_TYPES } from './bundle-components.js';

const BUNDLE_SCHEMA =
  'https://schema.kya-os.org/v1/protocol/audit/bundle-manifest/v1.0.0' as const;
const BUNDLE_SUITE = 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026' as const;

export type AuditBundleComponentInput =
  | {
      path: string;
      mediaType: string;
      disposition: 'included';
      content: unknown;
    }
  | {
      path: string;
      mediaType: string;
      disposition: Exclude<AuditBundleDisposition, 'included'>;
      reasonCode: string;
    };

export interface AuditReplayBundleExportInput {
  bundleId: string;
  purpose: string;
  verificationPolicyDigest: `sha256:${string}`;
  selections: readonly AuditBundleSelectionV1[];
  components: readonly AuditBundleComponentInput[];
}

export interface AuditReplayBundleExporterOptions {
  hasher: AuditHasher;
  signer: AuditSigner;
  clock: { now(): number };
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneCanonical<T>(value: T): T {
  return JSON.parse(canonicalizeJson(value)) as T;
}

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

/** Produces deterministic, signed-inventory evidence bundles. */
export class AuditReplayBundleExporter {
  constructor(private readonly options: AuditReplayBundleExporterOptions) {}

  async export(input: AuditReplayBundleExportInput): Promise<AuditReplayBundleV1> {
    if (!input.bundleId || !input.purpose) {
      throw new TypeError('Bundle ID and export purpose are required');
    }
    const paths = new Set<string>();
    const sortedInputs = [...input.components].sort((left, right) =>
      left.path.localeCompare(right.path));
    const components: AuditBundleComponentV1[] = [];
    for (const item of sortedInputs) {
      assertPath(item.path);
      if (paths.has(item.path)) throw new TypeError(`Duplicate bundle component path: ${item.path}`);
      paths.add(item.path);
      if (item.disposition === 'included') {
        const content = cloneCanonical(item.content);
        const bytes = canonicalizeJsonBytes(content);
        components.push({
          path: item.path,
          mediaType: item.mediaType,
          disposition: 'included',
          digest: await this.options.hasher.sha256(bytes),
          size: String(bytes.length),
          content,
        });
      } else {
        if (!item.reasonCode) throw new TypeError('Excluded bundle items require a reason code');
        components.push({
          path: item.path,
          mediaType: item.mediaType,
          disposition: item.disposition,
          reasonCode: item.reasonCode,
        });
      }
    }

    const inventory = components.map((component) => componentMetadata(component));
    const core = parseAuditBundleManifestCore({
      schema: BUNDLE_SCHEMA,
      bundleId: input.bundleId,
      formatVersion: '1.0.0',
      selections: cloneCanonical([...input.selections]),
      exporter: this.options.signer.ref,
      purpose: input.purpose,
      exportedAt: this.options.clock.now(),
      verificationPolicyDigest: input.verificationPolicyDigest,
      inventory,
      integritySuite: BUNDLE_SUITE,
    });
    const manifestDigest = await hashAuditValue(
      this.options.hasher,
      AUDIT_DIGEST_DOMAINS.bundleManifest,
      core,
    );
    return deepFreeze({
      manifest: {
        core,
        manifestDigest,
        jws: await this.options.signer.sign(canonicalizeJsonBytes(core)),
      },
      components,
    });
  }
}

export interface VerifyAuditBundleDependencies {
  hasher: AuditHasher;
  signatures: AuditSignatureVerifier;
  artifacts?: AuditArtifactVerifier;
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
  const checkpoints = checkpointCandidates.filter(
    (candidate): candidate is SignedAuditCheckpointV1 =>
      signedAuditCheckpointSchema.safeParse(candidate).success,
  );
  const observations = observationCandidates.filter(
    (candidate): candidate is AuditObservationReceiptV1 =>
      auditObservationReceiptSchema.safeParse(candidate).success,
  );
  // The bundle's own checkpoints are what checkpoint-bounded key policies name.
  const context: AuditVerificationContext = { checkpoints };
  const artifacts = dependencies.artifacts ?? new AuditArtifactVerifier(dependencies);
  const artifactReport = await verifyEntryGroups(entryCandidates, policy, artifacts, context);
  let checkpointDimension = artifactReport.checkpointIntegrity;
  if (checkpointCandidates.length > 0) {
    const proofs = await verifyMerkleProofComponents(
      replayBundle,
      entries,
      checkpoints,
      dependencies.hasher,
    );
    const checkpointResults: AuditVerificationDimension[] = [];
    for (const candidate of checkpointCandidates) {
      if (!signedAuditCheckpointSchema.safeParse(candidate).success) {
        checkpointResults.push(dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]));
        continue;
      }
      const checkpoint = candidate as SignedAuditCheckpointV1;
      const covered = entries.filter((entry) =>
        sameLedgerEpoch(entry.core, checkpoint.core) &&
        BigInt(entry.core.sequence) < BigInt(checkpoint.core.treeSize));
      // A subset export (a sequence range, or no entries at all) cannot
      // recompute the root, so its entries are bound by inclusion proofs.
      checkpointResults.push(isCompletePrefix(covered, checkpoint.core.treeSize)
        ? await artifacts.verifyCheckpoint(checkpoint, covered, policy, context)
        : mergeAuditDimensions(
            await artifacts.verifySignedCheckpoint(checkpoint, policy, context),
            verifyInclusionBinding(checkpoint, covered, proofs.inclusions),
          ));
    }
    checkpointDimension = mergeAuditDimensions(
      ...checkpointResults,
      verifyCheckpointHistory(checkpoints, entries, core.selections, proofs.consistencies),
      proofs.dimension,
    );
  } else if (core.selections.some((selection) => selection.checkpointTreeSizes.length > 0)) {
    checkpointDimension = dimension('invalid', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]);
  }
  let anchorDimension = artifactReport.anchorIntegrity;
  if (observationCandidates.length > 0) {
    const observationResults: AuditVerificationDimension[] = [];
    for (const candidate of observationCandidates) {
      if (!auditObservationReceiptSchema.safeParse(candidate).success) {
        observationResults.push(dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]));
        continue;
      }
      const receipt = candidate as AuditObservationReceiptV1;
      const checkpoint = checkpoints.find((candidate) =>
        candidate.checkpointDigest === receipt.core.checkpointDigest);
      observationResults.push(checkpoint === undefined
        ? dimension('invalid', [AUDIT_REASON_CODES.OBSERVATION_SCOPE_MISMATCH])
        : await artifacts.verifyObservation(checkpoint, receipt, policy, context));
    }
    anchorDimension = mergeAuditDimensions(
      ...observationResults,
      verifyObservationHistory(observations),
    );
  }
  if (anchorCandidates.length > 0) {
    anchorDimension = mergeAuditDimensions(
      anchorDimension,
      await verifySupportingAnchors(
        anchorCandidates,
        checkpoints,
        policy,
        dependencies.verifySupportingAnchor,
      ),
    );
  }

  // An exporter key bound that cannot be placed leaves the manifest
  // undecided, never valid; any other manifest reason is a failure.
  const manifestDimension = dimension(
    reasons.size === 0
      ? 'valid'
      : [...reasons].every((reason) => reason === AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED)
        ? 'indeterminate'
        : 'invalid',
    reasons,
  );
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
      core?.selections ?? [],
      entries,
      replayBundle.components.filter((component) => component.disposition !== 'included'),
    ),
    currentAuthorization: currentKeys === undefined
      ? artifactReport.currentAuthorization
      : mergeAuditDimensions(artifactReport.currentAuthorization, currentKeys),
  }, policy, { supportingAnchors: anchorCandidates.length > 0 });
}
