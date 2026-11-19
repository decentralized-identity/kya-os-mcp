import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { hashAuditValue } from './crypto.js';
import {
  AUDIT_DIGEST_DOMAINS,
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  digestAuditEvent,
} from './integrity.js';
import {
  keyIsCurrent,
  keyTrust,
  withBoundary,
  type CheckpointBoundaries,
  type CheckpointBoundary,
} from './key-trust.js';
import { Rfc9162MerkleTree } from './merkle.js';
import {
  auditObservationReceiptSchema,
  auditVerificationPolicySchema,
  signedAuditCheckpointSchema,
  signedAuditEntrySchema,
} from './schemas.js';
import type {
  AuditCheckpointCoreV1,
  AuditLedgerRef,
  AuditVerificationDimension,
  AuditObservationReceiptV1,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  HistoricalAuditKeyPolicy,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import {
  AUDIT_REASON_CODES,
  applyRequiredAuditProfile,
  dimension,
  invalidPolicyReport,
  mergeAuditDimensions,
  verdictOf,
} from './verdicts.js';
import type {
  AuditArtifactVerifierOptions,
  AuditSignedArtifacts,
  AuditVerificationContext,
} from './verifier-types.js';

export { AUDIT_REASON_CODES, applyRequiredAuditProfile, mergeAuditDimensions } from './verdicts.js';
export type {
  AuditArtifactVerifierOptions,
  AuditAuthorizationVerifier,
  AuditSignedArtifacts,
  AuditVerificationContext,
} from './verifier-types.js';

/** Matches the proof verifier's default timestamp tolerance. */
const DEFAULT_MAX_CLOCK_SKEW_MS = 120_000;

function exactJson(left: unknown, right: unknown): boolean {
  try {
    return canonicalizeJson(left) === canonicalizeJson(right);
  } catch {
    return false;
  }
}

type CheckpointCheck =
  | { kind: 'rejected'; result: AuditVerificationDimension }
  | { kind: 'checked'; core: AuditCheckpointCoreV1; reasons: Set<string> };

/** Pure historical verifier. It never reads live nonce state or applies current freshness. */
export class AuditArtifactVerifier {
  /** Boundary indexes of the frozen checkpoint lists this verifier was given, built once each. */
  private readonly indexed = new WeakMap<readonly unknown[], Promise<CheckpointBoundaries>>();

  constructor(private readonly options: AuditArtifactVerifierOptions) {}

  async verifyEntries(
    entries: readonly unknown[],
    policy: AuditVerificationPolicyV1 | unknown,
    context: AuditVerificationContext = {},
  ): Promise<AuditVerificationReportV1> {
    if (!auditVerificationPolicySchema.safeParse(policy).success) {
      return invalidPolicyReport(policy);
    }
    const verificationPolicy = policy as AuditVerificationPolicyV1;
    const boundaries = await this.boundaries(context.checkpoints ?? []);
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
      await this.verifyEntry(entry, verificationPolicy, boundaries, cryptoReasons);
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
    const currentKeys = this.verifyCurrentKeys(verificationPolicy, { entries: validatedEntries });
    return applyRequiredAuditProfile({
      schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0',
      policyId: verificationPolicy.policyId,
      ...(this.options.verifiedAt === undefined ? {} : { verifiedAt: this.options.verifiedAt() }),
      cryptographicIntegrity: dimension(
        entries.length > 0 ? verdictOf(cryptoReasons) : 'invalid',
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
      currentAuthorization: currentKeys === undefined
        ? currentAuthorization
        : mergeAuditDimensions(currentAuthorization, currentKeys),
    }, verificationPolicy);
  }

  /**
   * Evaluates the `current` and `both` key revocation modes: whether every key
   * these artifacts were signed with is still valid at `verifiedAt`. The
   * as-observed check, at signing time and ledger position, stays in the
   * integrity dimensions under every mode, because revocation does not rewrite
   * what was observed; this result belongs in `currentAuthorization`, which the
   * report keeps separate from it. Returns `undefined` under `as_observed`, and
   * `indeterminate` when the verifier has no `verifiedAt` clock.
   */
  verifyCurrentKeys(
    policy: AuditVerificationPolicyV1,
    artifacts: AuditSignedArtifacts,
  ): AuditVerificationDimension | undefined {
    if (policy.keyRevocationMode === 'as_observed') return undefined;
    const now = this.options.verifiedAt?.();
    if (now === undefined) return dimension('indeterminate', [AUDIT_REASON_CODES.NOT_EVALUATED]);
    const recorderKeys = (ledger: AuditLedgerRef): readonly HistoricalAuditKeyPolicy[] =>
      policy.trustedLedgerEpochs.find((candidate) =>
        candidate.ledgerId === ledger.ledgerId &&
        candidate.ledgerEpochId === ledger.ledgerEpochId)?.recorderKeys ?? [];
    const current = [
      ...(artifacts.entries ?? []).map((entry) =>
        keyIsCurrent(recorderKeys(entry.core), entry.core.recorder, now)),
      ...(artifacts.checkpoints ?? []).map((checkpoint) =>
        keyIsCurrent(recorderKeys(checkpoint.core), checkpoint.core.issuer, now)),
      ...(artifacts.observations ?? []).map((receipt) =>
        keyIsCurrent(policy.trustedObservers, receipt.core.observer, now)),
      ...(artifacts.exporter === undefined
        ? []
        : [keyIsCurrent(
            policy.authorizedExporters.flatMap((exporter) => exporter.signerKeys),
            artifacts.exporter,
            now,
          )]),
    ];
    return current.every(Boolean)
      ? dimension('valid')
      : dimension('invalid', [AUDIT_REASON_CODES.KEY_NOT_CURRENT]);
  }

  /** Verifies a checkpoint and recomputes its root from the complete journal prefix. */
  async verifyCheckpoint(
    checkpoint: SignedAuditCheckpointV1,
    entries: readonly SignedAuditEntryV1[],
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext = {},
  ): Promise<AuditVerificationDimension> {
    const checked = await this.checkSignedCheckpoint(checkpoint, policy, context);
    if (checked.kind === 'rejected') return checked.result;
    const { core, reasons } = checked;

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
    return dimension(verdictOf(reasons), reasons);
  }

  /**
   * Verifies a checkpoint's schema, suite, issuer trust, digest, signature, and
   * declared range without its leaves. It proves only what the recorder
   * signed; entries are bound to it separately by inclusion proofs.
   */
  async verifySignedCheckpoint(
    checkpoint: SignedAuditCheckpointV1,
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext = {},
  ): Promise<AuditVerificationDimension> {
    const checked = await this.checkSignedCheckpoint(checkpoint, policy, context);
    if (checked.kind === 'rejected') return checked.result;
    const { core, reasons } = checked;
    if (core.firstSequence !== '0' ||
      BigInt(core.lastSequence) + 1n !== BigInt(core.treeSize)) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH);
    }
    return dimension(verdictOf(reasons), reasons);
  }

  async verifyObservation(
    checkpoint: SignedAuditCheckpointV1,
    receipt: AuditObservationReceiptV1,
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext = {},
  ): Promise<AuditVerificationDimension> {
    const reasons = new Set<string>();
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
    const boundaries = withBoundary(
      await this.boundaries(context.checkpoints ?? []),
      await hashAuditValue(
        this.options.hasher,
        AUDIT_DIGEST_DOMAINS.checkpoint,
        validatedCheckpoint.core,
      ),
      validatedCheckpoint.core,
    );
    const trust = keyTrust(
      policy.trustedObservers,
      core.observer,
      core.observedAt,
      core,
      BigInt(core.treeSize),
      boundaries,
    );
    if (trust === 'outside') reasons.add(AUDIT_REASON_CODES.UNTRUSTED_OBSERVER);
    if (trust === 'unresolved') reasons.add(AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED);
    if (policy.requiredCheckpointFreshnessMs !== undefined) {
      const now = this.options.verifiedAt?.();
      if (now === undefined) {
        reasons.add(AUDIT_REASON_CODES.NOT_EVALUATED);
      } else if (core.observedAt > now + (this.options.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS)) {
        // A future-dated observation would otherwise count as perfectly fresh.
        reasons.add(AUDIT_REASON_CODES.OBSERVATION_FUTURE_DATED);
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
    if ((await this.options.signatures.verify(
      canonicalizeJsonBytes(core),
      validatedReceipt.jws,
      core.observer,
    )) !== true) {
      reasons.add(AUDIT_REASON_CODES.OBSERVATION_SIGNATURE_INVALID);
    }
    return dimension(verdictOf(reasons), reasons);
  }

  private async checkSignedCheckpoint(
    checkpoint: SignedAuditCheckpointV1,
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext,
  ): Promise<CheckpointCheck> {
    if (!auditVerificationPolicySchema.safeParse(policy).success) {
      return {
        kind: 'rejected',
        result: dimension('invalid', [AUDIT_REASON_CODES.VERIFICATION_POLICY_INVALID]),
      };
    }
    const parsedCheckpoint = signedAuditCheckpointSchema.safeParse(checkpoint);
    if (!parsedCheckpoint.success) {
      return {
        kind: 'rejected',
        result: dimension('invalid', [AUDIT_REASON_CODES.SCHEMA_INVALID]),
      };
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
    const expectedDigest = await hashAuditValue(
      this.options.hasher,
      AUDIT_DIGEST_DOMAINS.checkpoint,
      core,
    );
    const epochPolicy = policy.trustedLedgerEpochs.find((candidate) =>
      candidate.ledgerId === core.ledgerId &&
      candidate.ledgerEpochId === core.ledgerEpochId);
    const trust = keyTrust(
      epochPolicy?.recorderKeys ?? [],
      core.issuer,
      core.createdAt,
      core,
      BigInt(core.treeSize),
      withBoundary(await this.boundaries(context.checkpoints ?? []), expectedDigest, core),
      epochPolicy,
    );
    if (trust === 'outside') reasons.add(AUDIT_REASON_CODES.UNTRUSTED_RECORDER);
    if (trust === 'unresolved') reasons.add(AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED);

    if (expectedDigest !== validated.checkpointDigest) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_DIGEST_MISMATCH);
    }
    if ((await this.options.signatures.verify(
      canonicalizeJsonBytes(core),
      validated.jws,
      core.issuer,
    )) !== true) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_SIGNATURE_INVALID);
    }
    return { kind: 'checked', core, reasons };
  }

  /**
   * Indexes candidate checkpoints by their recomputed digest. A policy names a
   * boundary by digest, which commits to the checkpoint core, so a matching
   * core authenticates the boundary's ledger epoch and tree size by itself.
   * A frozen list cannot change, so its index is built once however many
   * artifacts are checked against it; a replay bundle freezes its own.
   */
  private boundaries(checkpoints: readonly unknown[]): Promise<CheckpointBoundaries> {
    if (!Object.isFrozen(checkpoints)) return this.indexBoundaries(checkpoints);
    let index = this.indexed.get(checkpoints);
    if (index === undefined) {
      index = this.indexBoundaries(checkpoints);
      this.indexed.set(checkpoints, index);
    }
    return index;
  }

  private async indexBoundaries(
    checkpoints: readonly unknown[],
  ): Promise<Map<string, CheckpointBoundary>> {
    const result = new Map<string, CheckpointBoundary>();
    for (const candidate of checkpoints) {
      if (!signedAuditCheckpointSchema.safeParse(candidate).success) continue;
      const core = (candidate as SignedAuditCheckpointV1).core;
      result.set(
        await hashAuditValue(this.options.hasher, AUDIT_DIGEST_DOMAINS.checkpoint, core),
        {
          ledgerId: core.ledgerId,
          ledgerEpochId: core.ledgerEpochId,
          treeSize: BigInt(core.treeSize),
        },
      );
    }
    return result;
  }

  private async verifyEntry(
    entry: SignedAuditEntryV1,
    policy: AuditVerificationPolicyV1,
    boundaries: CheckpointBoundaries,
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
    const trust = keyTrust(
      epochPolicy?.recorderKeys ?? [],
      entry.core.recorder,
      entry.core.recordedAt,
      entry.core,
      BigInt(entry.core.sequence) + 1n,
      boundaries,
      epochPolicy,
    );
    if (trust === 'outside') reasons.add(AUDIT_REASON_CODES.UNTRUSTED_RECORDER);
    if (trust === 'unresolved') reasons.add(AUDIT_REASON_CODES.KEY_BOUNDARY_UNRESOLVED);

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
    if ((await this.options.signatures.verify(
      canonicalizeJsonBytes(entry.recorderReceipt.core),
      entry.recorderReceipt.jws,
      entry.core.recorder,
    )) !== true) {
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
