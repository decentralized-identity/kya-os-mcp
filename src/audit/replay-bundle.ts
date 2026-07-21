import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import type { AuditHasher, AuditSignatureVerifier, AuditSigner } from './crypto.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_DIGEST_DOMAINS } from './integrity.js';
import { Rfc9162MerkleTree } from './merkle.js';
import {
  auditObservationReceiptSchema,
  auditAnchorReceiptSchema,
  auditBundleConsistencyProofSchema,
  auditBundleInclusionProofSchema,
  auditReplayBundleSchema,
  auditVerificationPolicySchema,
  parseAuditBundleManifestCore,
  signedAuditCheckpointSchema,
  signedAuditEntrySchema,
} from './schemas.js';
import type {
  AuditBundleComponentV1,
  AuditBundleConsistencyProofV1,
  AuditBundleDisposition,
  AuditBundleInclusionProofV1,
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
  SignerRef,
} from './types.js';
import {
  AUDIT_REASON_CODES,
  AuditArtifactVerifier,
  mergeAuditDimensions,
} from './verifier.js';

const BUNDLE_SCHEMA =
  'https://schema.kya-os.org/v1/protocol/audit/bundle-manifest/v1.0.0' as const;
const BUNDLE_SUITE = 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026' as const;

export const AUDIT_BUNDLE_MEDIA_TYPES = Object.freeze({
  entries: 'application/vnd.kya-os.audit.entries.v1+json',
  checkpoints: 'application/vnd.kya-os.audit.checkpoints.v1+json',
  inclusionProofs: 'application/vnd.kya-os.audit.inclusion-proofs.v1+json',
  consistencyProofs: 'application/vnd.kya-os.audit.consistency-proofs.v1+json',
  observations: 'application/vnd.kya-os.audit.observations.v1+json',
  anchors: 'application/vnd.kya-os.audit.anchors.v1+json',
  verificationReport: 'application/vnd.kya-os.audit.verification-report.v1+json',
});

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

function assertPath(path: string): void {
  if (path.length === 0 || path.startsWith('/') || path.includes('\\') ||
    path.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new TypeError('Bundle component path must be a safe canonical relative path');
  }
}

function sameSigner(left: SignerRef, right: SignerRef): boolean {
  return left.did === right.did && left.kid === right.kid && left.alg === right.alg;
}

function atTime(input: { validFrom?: number; validUntil?: number }, time: number): boolean {
  return (input.validFrom === undefined || time >= input.validFrom) &&
    (input.validUntil === undefined || time <= input.validUntil);
}

function dim(
  verdict: AuditVerificationDimension['verdict'],
  reasons: Iterable<string> = [],
): AuditVerificationDimension {
  return { verdict, reasonCodes: [...new Set(reasons)].sort() };
}

function malformedBundleReport(policy: AuditVerificationPolicyV1): AuditVerificationReportV1 {
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0',
    policyId: policy.policyId,
    cryptographicIntegrity: dim('invalid', [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID]),
    chainIntegrity: dim('invalid', [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID]),
    checkpointIntegrity: dim('indeterminate', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]),
    anchorIntegrity: dim('indeterminate', [AUDIT_REASON_CODES.OBSERVER_EVIDENCE_MISSING]),
    scopeEvidenceCompleteness: dim('invalid', [AUDIT_REASON_CODES.BUNDLE_SCHEMA_INVALID]),
    authorizedAsObserved: dim('indeterminate', [
      AUDIT_REASON_CODES.AUTHORIZATION_COLLATERAL_NOT_VERIFIED,
    ]),
    currentAuthorization: dim('indeterminate', [
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

function exporterAuthorized(
  core: AuditBundleManifestCoreV1,
  policy: AuditVerificationPolicyV1,
): boolean {
  return policy.authorizedExporters.some((authorization) =>
    authorization.allowedPurposes.includes(core.purpose) &&
    core.selections.every((selection) =>
      authorization.allowedLedgerIds.includes(selection.ledgerId)) &&
    authorization.signerKeys.some((key) =>
      sameSigner(key.signer, core.exporter) && atTime(key, core.exportedAt)));
}

function componentMetadata(component: AuditBundleComponentV1): Omit<AuditBundleComponentV1, 'content'> {
  return {
    path: component.path,
    mediaType: component.mediaType,
    disposition: component.disposition,
    ...(component.digest === undefined ? {} : { digest: component.digest }),
    ...(component.size === undefined ? {} : { size: component.size }),
    ...(component.reasonCode === undefined ? {} : { reasonCode: component.reasonCode }),
  };
}

function includedArrays<T>(
  bundle: AuditReplayBundleV1,
  mediaType: string,
): T[] {
  const result: T[] = [];
  for (const component of bundle.components) {
    if (component.disposition !== 'included' || component.mediaType !== mediaType ||
      !Array.isArray(component.content)) continue;
    result.push(...component.content as T[]);
  }
  return result;
}

function ledgerEpochKey(value: { ledgerId: string; ledgerEpochId: string }): string {
  return `${value.ledgerId}\0${value.ledgerEpochId}`;
}

function compareDecimal(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

async function verifyEntryGroups(
  entries: readonly unknown[],
  policy: AuditVerificationPolicyV1,
  artifacts: AuditArtifactVerifier,
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
    ...[...groups.values()].map((group) => artifacts.verifyEntries(group, policy)),
    ...(malformed.length === 0 ? [] : [artifacts.verifyEntries(malformed, policy)]),
  ]);
  if (reports.length === 0) return artifacts.verifyEntries([], policy);
  const first = reports[0]!;
  return {
    ...first,
    cryptographicIntegrity: mergeAuditDimensions(
      ...reports.map((report) => report.cryptographicIntegrity),
    ),
    chainIntegrity: mergeAuditDimensions(...reports.map((report) => report.chainIntegrity)),
    checkpointIntegrity: mergeAuditDimensions(
      ...reports.map((report) => report.checkpointIntegrity),
    ),
    anchorIntegrity: mergeAuditDimensions(...reports.map((report) => report.anchorIntegrity)),
    scopeEvidenceCompleteness: mergeAuditDimensions(
      ...reports.map((report) => report.scopeEvidenceCompleteness),
    ),
    authorizedAsObserved: mergeAuditDimensions(
      ...reports.map((report) => report.authorizedAsObserved),
    ),
    currentAuthorization: mergeAuditDimensions(
      ...reports.map((report) => report.currentAuthorization),
    ),
  };
}

function verifyCheckpointHistory(
  checkpoints: readonly SignedAuditCheckpointV1[],
  entries: readonly SignedAuditEntryV1[],
  selections: readonly AuditBundleSelectionV1[],
): AuditVerificationDimension {
  const reasons = new Set<string>();
  const groups = new Map<string, SignedAuditCheckpointV1[]>();
  for (const checkpoint of checkpoints) {
    const key = ledgerEpochKey(checkpoint.core);
    const group = groups.get(key) ?? [];
    group.push(checkpoint);
    groups.set(key, group);
  }

  for (const group of groups.values()) {
    group.sort((left, right) => {
      const a = BigInt(left.core.treeSize);
      const b = BigInt(right.core.treeSize);
      return a < b ? -1 : a > b ? 1 : 0;
    });
    for (let index = 1; index < group.length; index += 1) {
      const previous = group[index - 1]!;
      const current = group[index]!;
      if (current.core.treeSize === previous.core.treeSize) {
        reasons.add(AUDIT_REASON_CODES.CHECKPOINT_FORK_DETECTED);
      } else if (current.core.previousCheckpointDigest !== previous.checkpointDigest) {
        reasons.add(AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH);
      }
    }
  }

  for (const selection of selections) {
    const actual = (groups.get(ledgerEpochKey(selection)) ?? [])
      .map((checkpoint) => checkpoint.core.treeSize)
      .sort(compareDecimal);
    const expected = [...selection.checkpointTreeSizes]
      .sort(compareDecimal);
    if (canonicalizeJson(actual) !== canonicalizeJson(expected)) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_MISSING);
    }
  }

  for (const entry of entries) {
    if (entry.core.sequence !== '0' || entry.core.event.eventType !== 'ledger.epoch.started' ||
      entry.core.event.details.family !== 'ledger') continue;
    const details = entry.core.event.details;
    if (details.previousEpochId === undefined ||
      details.previousTerminalCheckpointDigest === undefined) continue;
    const predecessorSelected = selections.some((selection) =>
      selection.ledgerId === entry.core.ledgerId &&
      selection.ledgerEpochId === details.previousEpochId);
    if (predecessorSelected && !checkpoints.some((checkpoint) =>
      checkpoint.core.ledgerId === entry.core.ledgerId &&
      checkpoint.core.ledgerEpochId === details.previousEpochId &&
      checkpoint.checkpointDigest === details.previousTerminalCheckpointDigest)) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH);
    }
  }

  return dim(reasons.size === 0 ? 'valid' : 'invalid', reasons);
}

async function verifyMerkleProofComponents(
  bundle: AuditReplayBundleV1,
  entries: readonly SignedAuditEntryV1[],
  checkpoints: readonly SignedAuditCheckpointV1[],
  hasher: AuditHasher,
): Promise<AuditVerificationDimension> {
  const reasons = new Set<string>();
  const tree = new Rfc9162MerkleTree(hasher);
  const inclusionCandidates = includedArrays<unknown>(
    bundle,
    AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs,
  );
  for (const candidate of inclusionCandidates) {
    if (!auditBundleInclusionProofSchema.safeParse(candidate).success) {
      reasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
      continue;
    }
    const item = candidate as AuditBundleInclusionProofV1;
    const checkpoint = checkpoints.find((value) =>
      value.checkpointDigest === item.checkpointDigest &&
      value.core.ledgerId === item.ledgerId &&
      value.core.ledgerEpochId === item.ledgerEpochId);
    const entry = entries.find((value) =>
      value.entryDigest === item.entryDigest &&
      value.core.sequence === item.sequence &&
      value.core.ledgerId === item.ledgerId &&
      value.core.ledgerEpochId === item.ledgerEpochId);
    const leafIndex = Number(item.proof.leafIndex);
    const treeSize = Number(item.proof.treeSize);
    if (checkpoint === undefined || entry === undefined ||
      item.proof.treeSize !== checkpoint.core.treeSize ||
      item.proof.leafIndex !== item.sequence ||
      !(await tree.verifyInclusion({
        leaf: item.entryDigest,
        leafIndex,
        treeSize,
        root: checkpoint.core.rootDigest,
        auditPath: item.proof.auditPath,
      }))) {
      reasons.add(AUDIT_REASON_CODES.MERKLE_PROOF_INVALID);
    }
  }

  const consistencyCandidates = includedArrays<unknown>(
    bundle,
    AUDIT_BUNDLE_MEDIA_TYPES.consistencyProofs,
  );
  for (const candidate of consistencyCandidates) {
    if (!auditBundleConsistencyProofSchema.safeParse(candidate).success) {
      reasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
      continue;
    }
    const item = candidate as AuditBundleConsistencyProofV1;
    const oldCheckpoint = checkpoints.find((value) =>
      value.checkpointDigest === item.oldCheckpointDigest &&
      value.core.ledgerId === item.ledgerId &&
      value.core.ledgerEpochId === item.ledgerEpochId);
    const newCheckpoint = checkpoints.find((value) =>
      value.checkpointDigest === item.newCheckpointDigest &&
      value.core.ledgerId === item.ledgerId &&
      value.core.ledgerEpochId === item.ledgerEpochId);
    if (oldCheckpoint === undefined || newCheckpoint === undefined ||
      item.proof.oldTreeSize !== oldCheckpoint.core.treeSize ||
      item.proof.newTreeSize !== newCheckpoint.core.treeSize ||
      !(await tree.verifyConsistency({
        oldSize: Number(item.proof.oldTreeSize),
        newSize: Number(item.proof.newTreeSize),
        oldRoot: oldCheckpoint.core.rootDigest,
        newRoot: newCheckpoint.core.rootDigest,
        auditPath: item.proof.auditPath,
      }))) {
      reasons.add(AUDIT_REASON_CODES.MERKLE_PROOF_INVALID);
    }
  }
  return dim(reasons.size === 0 ? 'valid' : 'invalid', reasons);
}

function verifyObservationHistory(
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
  return dim(reasons.size === 0 ? 'valid' : 'invalid', reasons);
}

async function verifySupportingAnchors(
  candidates: readonly unknown[],
  checkpoints: readonly SignedAuditCheckpointV1[],
  policy: AuditVerificationPolicyV1,
  verifyReceipt: VerifyAuditBundleDependencies['verifySupportingAnchor'],
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
      atTime(value, receipt.issuedAt)) ?? false;
    if (!trusted) reasons.add(AUDIT_REASON_CODES.UNTRUSTED_SUPPORTING_ANCHOR);
    if (checkpoint === undefined) {
      reasons.add(AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID);
    } else if (verifyReceipt === undefined) {
      reasons.add(AUDIT_REASON_CODES.NOT_EVALUATED);
      notEvaluated = true;
    } else if (!(await verifyReceipt(checkpoint, receipt))) {
      reasons.add(AUDIT_REASON_CODES.SUPPORTING_ANCHOR_INVALID);
    }
  }
  const invalid = [...reasons].some((reason) => reason !== AUDIT_REASON_CODES.NOT_EVALUATED);
  return dim(invalid ? 'invalid' : notEvaluated ? 'indeterminate' : 'valid', reasons);
}

function selectionCompleteness(
  selections: readonly AuditBundleSelectionV1[],
  entries: readonly SignedAuditEntryV1[],
  explicitOmissions: readonly AuditBundleComponentV1[],
): AuditVerificationDimension {
  const reasons = new Set<string>();
  for (const selection of selections) {
    const selected = entries.filter((entry) =>
      entry.core.ledgerId === selection.ledgerId &&
      entry.core.ledgerEpochId === selection.ledgerEpochId);
    let expectedCount: bigint;
    try {
      expectedCount = BigInt(selection.lastSequence) - BigInt(selection.firstSequence) + 1n;
    } catch {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE);
      continue;
    }
    if (expectedCount < 1n || expectedCount !== BigInt(selected.length) ||
      selected[0]?.core.sequence !== selection.firstSequence ||
      selected[selected.length - 1]?.core.sequence !== selection.lastSequence ||
      selected[selected.length - 1]?.entryDigest !== selection.expectedHeadDigest) {
      reasons.add(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE);
    }
  }
  for (const component of explicitOmissions) {
    if (component.disposition === 'redacted') reasons.add(AUDIT_REASON_CODES.EXPLICITLY_REDACTED);
    if (component.disposition === 'disposed') reasons.add(AUDIT_REASON_CODES.EXPLICITLY_DISPOSED);
    if (component.disposition === 'unavailable') reasons.add(AUDIT_REASON_CODES.EXPLICITLY_UNAVAILABLE);
  }
  if (reasons.has(AUDIT_REASON_CODES.BUNDLE_SELECTION_INCOMPLETE)) return dim('invalid', reasons);
  return reasons.size === 0 ? dim('valid') : dim('indeterminate', reasons);
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
    const invalid = dim('invalid', [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID]);
    return {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0',
      policyId,
      cryptographicIntegrity: invalid,
      chainIntegrity: invalid,
      checkpointIntegrity: invalid,
      anchorIntegrity: invalid,
      scopeEvidenceCompleteness: invalid,
      authorizedAsObserved: dim('indeterminate', [AUDIT_REASON_CODES.NOT_EVALUATED]),
      currentAuthorization: dim('indeterminate', [AUDIT_REASON_CODES.NOT_EVALUATED]),
    };
  }
  if (!auditReplayBundleSchema.safeParse(bundle).success) {
    return malformedBundleReport(policy);
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
  if (core === undefined || !exporterAuthorized(core, policy)) {
    reasons.add(AUDIT_REASON_CODES.BUNDLE_EXPORTER_UNAUTHORIZED);
  }

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
    if (!(await dependencies.signatures.verify(
      canonicalizeJsonBytes(core),
      replayBundle.manifest.jws,
      core.exporter,
    ))) {
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
  const artifacts = dependencies.artifacts ?? new AuditArtifactVerifier(dependencies);
  const artifactReport = await verifyEntryGroups(entryCandidates, policy, artifacts);
  const entries = entryCandidates.filter((candidate): candidate is SignedAuditEntryV1 =>
    signedAuditEntrySchema.safeParse(candidate).success);
  const checkpoints = checkpointCandidates.filter(
    (candidate): candidate is SignedAuditCheckpointV1 =>
      signedAuditCheckpointSchema.safeParse(candidate).success,
  );
  let checkpointDimension = artifactReport.checkpointIntegrity;
  if (checkpointCandidates.length > 0) {
    const checkpointResults: AuditVerificationDimension[] = [];
    for (const candidate of checkpointCandidates) {
      if (!signedAuditCheckpointSchema.safeParse(candidate).success) {
        checkpointResults.push(dim('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]));
        continue;
      }
      const checkpoint = candidate as SignedAuditCheckpointV1;
      const checkpointEntries = entries.filter((entry) =>
        entry.core.ledgerId === checkpoint.core.ledgerId &&
        entry.core.ledgerEpochId === checkpoint.core.ledgerEpochId &&
        BigInt(entry.core.sequence) < BigInt(checkpoint.core.treeSize));
      checkpointResults.push(await artifacts.verifyCheckpoint(checkpoint, checkpointEntries, policy));
    }
    checkpointDimension = mergeAuditDimensions(
      ...checkpointResults,
      verifyCheckpointHistory(checkpoints, entries, core.selections),
      await verifyMerkleProofComponents(replayBundle, entries, checkpoints, dependencies.hasher),
    );
  } else if (core.selections.some((selection) => selection.checkpointTreeSizes.length > 0)) {
    checkpointDimension = dim('invalid', [AUDIT_REASON_CODES.CHECKPOINT_MISSING]);
  }
  let anchorDimension = artifactReport.anchorIntegrity;
  if (observationCandidates.length > 0) {
    const observationResults: AuditVerificationDimension[] = [];
    for (const candidate of observationCandidates) {
      if (!auditObservationReceiptSchema.safeParse(candidate).success) {
        observationResults.push(dim('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]));
        continue;
      }
      const receipt = candidate as AuditObservationReceiptV1;
      const checkpoint = checkpoints.find((candidate) =>
        candidate.checkpointDigest === receipt.core.checkpointDigest);
      observationResults.push(checkpoint === undefined
        ? dim('invalid', [AUDIT_REASON_CODES.OBSERVATION_SCOPE_MISMATCH])
        : await artifacts.verifyObservation(checkpoint, receipt, policy));
    }
    const validObservations = observationCandidates.filter(
      (candidate): candidate is AuditObservationReceiptV1 =>
        auditObservationReceiptSchema.safeParse(candidate).success,
    );
    anchorDimension = mergeAuditDimensions(
      ...observationResults,
      verifyObservationHistory(validObservations),
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

  const manifestDimension = dim(reasons.size === 0 ? 'valid' : 'invalid', reasons);
  return {
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
  };
}
