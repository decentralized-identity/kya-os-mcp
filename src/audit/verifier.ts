import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import {
  checkChainPosition,
  checkCheckpoint,
  checkEntry,
  type CheckpointCheck,
} from './artifact-checks.js';
import { hashAuditValue } from './crypto.js';
import { AUDIT_DIGEST_DOMAINS } from './integrity.js';
import { carriedEvidence, gatherDating, type Dating } from './key-dating-evidence.js';
import {
  keyIsCurrent,
  keyIsLive,
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
  AuditLedgerRef,
  AuditVerificationDimension,
  AuditObservationReceiptV1,
  AuditVerificationPolicyV1,
  AuditVerificationReportV1,
  HistoricalAuditKeyPolicy,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
  SignerRef,
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

/** Whether evidence dates an artifact at `at` no later than its key's end. */
function dated(at: number | undefined, until: number): boolean {
  return at !== undefined && at <= until;
}

/** Pure historical verifier. It never reads live nonce state or applies current freshness. */
export class AuditArtifactVerifier {
  /** Boundary indexes of the frozen checkpoint lists this verifier was given, built once each. */
  private readonly indexed = new WeakMap<readonly unknown[], Promise<CheckpointBoundaries>>();
  /** The dating of each replay bundle's evidence, built once per bundle and policy. */
  private readonly dated = new WeakMap<
    AuditVerificationContext,
    { policy: AuditVerificationPolicyV1; dating: Promise<Dating> }
  >();

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

    const ended: { entry: SignedAuditEntryV1; until: number }[] = [];
    for (const candidate of entries) {
      const parsed = signedAuditEntrySchema.safeParse(candidate);
      if (!parsed.success) {
        cryptoReasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
        chainReasons.add(AUDIT_REASON_CODES.SCHEMA_INVALID);
        continue;
      }
      const entry = parsed.data as SignedAuditEntryV1;
      const index = validatedEntries.length;
      const until = await checkEntry(
        this.options, entry, verificationPolicy, boundaries, cryptoReasons,
      );
      if (until !== undefined) ended.push({ entry, until });
      checkChainPosition(entry, validatedEntries[index - 1], index, chainReasons);
      validatedEntries.push(entry);
    }
    // A record whose key has ended is the signer's word alone until evidence dates it.
    if (ended.length > 0 || (context.successorGeneses?.length ?? 0) > 0) {
      const dating = await this.dating(verificationPolicy, context, validatedEntries);
      for (const reason of dating.reasons) cryptoReasons.add(reason);
      for (const { entry, until } of ended) {
        if (!dated(dating.entryAt(entry.entryDigest), until)) {
          cryptoReasons.add(AUDIT_REASON_CODES.KEY_ENDED_UNDATED);
        }
      }
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

  /**
   * Whether a key has ended by this verifier's clock, or, with no clock, has an end at all: what
   * such a key signed is its holder's word alone on when it was signed.
   */
  keyHasEnded(keys: readonly HistoricalAuditKeyPolicy[], signer: SignerRef): boolean {
    return !keyIsLive(keys, signer, this.options.verifiedAt?.());
  }

  /** Verifies a checkpoint and recomputes its root from the complete journal prefix. */
  async verifyCheckpoint(
    checkpoint: SignedAuditCheckpointV1,
    entries: readonly SignedAuditEntryV1[],
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext = {},
  ): Promise<AuditVerificationDimension> {
    const checked = await this.checkSignedCheckpoint(checkpoint, policy, context, entries);
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
    const checked = await this.checkSignedCheckpoint(checkpoint, policy, context, []);
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

  /**
   * Checks a checkpoint on its own ({@link checkCheckpoint}), and, when its issuer key has ended,
   * whether evidence dates it before that end.
   */
  private async checkSignedCheckpoint(
    checkpoint: SignedAuditCheckpointV1,
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext,
    entries: readonly SignedAuditEntryV1[],
  ): Promise<CheckpointCheck> {
    const checked = await checkCheckpoint(
      this.options, checkpoint, policy, await this.boundaries(context.checkpoints ?? []),
    );
    if (checked.kind === 'checked' && checked.until !== undefined) {
      const dating = await this.dating(policy, context, entries, checkpoint);
      if (!dated(dating.checkpointAt(checked.digest), checked.until)) {
        checked.reasons.add(AUDIT_REASON_CODES.KEY_ENDED_UNDATED);
      }
    }
    return checked;
  }

  /**
   * What dates artifacts whose key has ended, from what this verification was given: the
   * context's checkpoints and successor geneses, and `entries`; for a replay bundle, everything it
   * carries instead, gathered once however many groups and checkpoints it verifies. `checkpoint`,
   * when given, is the one being checked, whose own chain and tree are evidence too.
   */
  private dating(
    policy: AuditVerificationPolicyV1,
    context: AuditVerificationContext,
    entries: readonly SignedAuditEntryV1[],
    checkpoint?: SignedAuditCheckpointV1,
  ): Promise<Dating> {
    const carried = carriedEvidence(context);
    const gather = async (): Promise<Dating> => gatherDating(this.options, {
      policy,
      boundaries: await this.boundaries(context.checkpoints ?? []),
      checkpoints: carried !== undefined || checkpoint === undefined
        ? context.checkpoints ?? []
        : [...(context.checkpoints ?? []), checkpoint],
      offered: context.successorGeneses ?? [],
      entries,
      carried,
    });
    if (carried === undefined) return gather();
    let cached = this.dated.get(context);
    if (cached?.policy !== policy) {
      cached = { policy, dating: gather() };
      this.dated.set(context, cached);
    }
    return cached.dating;
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
}
