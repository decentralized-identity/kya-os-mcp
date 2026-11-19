/**
 * Gathers what dates audit artifacts whose key has ended (`./key-dating.ts`) from what a
 * verification is given: its supporting checkpoints, the successor epoch geneses it is offered,
 * the entries it carries, and, for a replay bundle, the proofs, observations and supporting
 * anchors the bundle verified. Each piece is verified before it dates anything. An offered
 * successor genesis that dates nothing is reported, as `AUDIT_SUCCESSOR_GENESIS_MISMATCH`.
 */

import { checkCheckpoint, checkEntry, type ArtifactCheckOptions } from './artifact-checks.js';
import { prefixBoundCheckpoints } from './bundle-checkpoints.js';
import { compareDecimal } from './bundle-components.js';
import {
  dateEvidence,
  type AuditDating,
  type DatingCheckpoint,
  type DatingGenesis,
} from './key-dating.js';
import { keyIsLive, type CheckpointBoundaries, type CheckpointBounds } from './key-trust.js';
import { signedAuditCheckpointSchema, signedAuditEntrySchema } from './schemas.js';
import type {
  AuditAnchorReceipt,
  AuditBundleInclusionProofV1,
  AuditObservationReceiptV1,
  AuditVerificationPolicyV1,
  Digest,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import { AUDIT_REASON_CODES } from './verdicts.js';
import type { AuditVerificationContext } from './verifier-types.js';

/** What a replay bundle verified beyond its checkpoints, for dating. */
export interface CarriedDatingEvidence {
  /** Every entry the bundle carries, of every epoch. */
  entries: readonly SignedAuditEntryV1[];
  /** Inclusion proofs that verified. */
  inclusions: readonly AuditBundleInclusionProofV1[];
  /** Consistency proofs that verified, as their new and old checkpoint digests. */
  extensions: readonly (readonly [Digest, Digest])[];
  /** Observation receipts that verified. */
  observations: readonly AuditObservationReceiptV1[];
  /** Supporting anchor receipts that verified for a checkpoint the bundle carries. */
  anchors: readonly AuditAnchorReceipt[];
}

const carriedByContext = new WeakMap<AuditVerificationContext, CarriedDatingEvidence>();

/** `context`, frozen, carrying what a replay bundle verified to the verifier it hands it to. */
export function withCarriedEvidence(
  context: AuditVerificationContext,
  evidence: CarriedDatingEvidence,
): AuditVerificationContext {
  const frozen = Object.freeze({ ...context });
  carriedByContext.set(frozen, evidence);
  return frozen;
}

export function carriedEvidence(
  context: AuditVerificationContext,
): CarriedDatingEvidence | undefined {
  return carriedByContext.get(context);
}

export interface Dating extends AuditDating {
  /** Why an offered successor genesis dates nothing; empty when every one dates. */
  reasons: ReadonlySet<string>;
}

export interface DatingInput {
  policy: AuditVerificationPolicyV1;
  /** The boundaries of the supporting checkpoints, which key bounds resolve against. */
  boundaries: CheckpointBoundaries;
  /** Supporting checkpoints, unverified. */
  checkpoints: readonly unknown[];
  /** Successor epoch geneses offered as dating evidence, unverified. */
  offered: readonly unknown[];
  /** The entries being verified, schema-valid. A bundle's `carried` entries replace them. */
  entries: readonly SignedAuditEntryV1[];
  carried?: CarriedDatingEvidence | undefined;
}

/**
 * The checkpoints a policy ends a recorder key or a ledger epoch at, by `validUntilCheckpoint`:
 * whoever wrote the policy vouches for the tree each one ends at.
 */
function pinnedCheckpoints(policy: AuditVerificationPolicyV1): Set<Digest> {
  const pinned = new Set<Digest>();
  const pin = (bounds: CheckpointBounds): void => {
    if (bounds.validUntilCheckpoint !== undefined) pinned.add(bounds.validUntilCheckpoint);
  };
  for (const epoch of policy.trustedLedgerEpochs) {
    pin(epoch);
    epoch.recorderKeys.forEach(pin);
  }
  return pinned;
}

/** Whether an entry is shaped as the genesis of an epoch that succeeds another. */
function isSuccessorGenesis(entry: SignedAuditEntryV1): boolean {
  const { core } = entry;
  const details = core.event.details;
  return core.sequence === '0' && core.previousEntryDigest === null &&
    core.event.eventType === 'ledger.epoch.started' &&
    details.family === 'ledger' && details.phase === 'epoch_started' &&
    typeof details.previousEpochId === 'string' &&
    details.previousEpochId !== core.ledgerEpochId &&
    typeof details.previousTerminalCheckpointDigest === 'string';
}

/**
 * A successor genesis as dating evidence: one that verifies as the first entry of an epoch the
 * policy trusts, with its key placed at the time it states, and commits to a verified checkpoint
 * of the epoch it names as its predecessor.
 */
async function successorGenesis(
  options: ArtifactCheckOptions,
  input: DatingInput,
  candidate: unknown,
  verified: ReadonlyMap<Digest, SignedAuditCheckpointV1>,
): Promise<DatingGenesis | undefined> {
  if (!signedAuditEntrySchema.safeParse(candidate).success) return undefined;
  const genesis = candidate as SignedAuditEntryV1;
  if (!isSuccessorGenesis(genesis)) return undefined;
  const details = genesis.core.event.details as { previousEpochId: string; previousTerminalCheckpointDigest: Digest };
  const terminal = verified.get(details.previousTerminalCheckpointDigest);
  if (terminal?.core.ledgerId !== genesis.core.ledgerId ||
    terminal.core.ledgerEpochId !== details.previousEpochId) return undefined;
  const reasons = new Set<string>();
  const until = await checkEntry(options, genesis, input.policy, input.boundaries, reasons);
  if (reasons.size > 0) return undefined;
  return {
    entryDigest: genesis.entryDigest,
    recordedAt: genesis.core.recordedAt,
    until,
    commits: details.previousTerminalCheckpointDigest,
  };
}

export async function gatherDating(
  options: ArtifactCheckOptions,
  input: DatingInput,
): Promise<Dating> {
  const verified = new Map<Digest, SignedAuditCheckpointV1>();
  const checkpoints: DatingCheckpoint[] = [];
  for (const candidate of input.checkpoints) {
    if (!signedAuditCheckpointSchema.safeParse(candidate).success) continue;
    const checkpoint = candidate as SignedAuditCheckpointV1;
    const checked = await checkCheckpoint(options, checkpoint, input.policy, input.boundaries);
    if (checked.kind !== 'checked' || checked.reasons.size > 0 || verified.has(checked.digest)) {
      continue;
    }
    verified.set(checked.digest, checkpoint);
    checkpoints.push({ digest: checked.digest, createdAt: checked.core.createdAt, until: checked.until });
  }

  const contains: (readonly [Digest, Digest])[] = [...(input.carried?.extensions ?? [])];
  for (const [digest, checkpoint] of verified) {
    const previous = checkpoint.core.previousCheckpointDigest;
    if (previous !== null && verified.has(previous)) contains.push([digest, previous]);
  }
  const holders = new Map<Digest, Digest[]>();
  const hold = (entryDigest: Digest, checkpointDigest: Digest): void => {
    const known = holders.get(entryDigest);
    if (known === undefined) holders.set(entryDigest, [checkpointDigest]);
    else known.push(checkpointDigest);
  };
  for (const item of input.carried?.inclusions ?? []) hold(item.entryDigest, item.checkpointDigest);
  // Over one carried prefix, each checkpoint holds the one below it, and holds itself only the
  // entries past it: an entry is dated through the smallest tree that holds it.
  const entries = input.carried?.entries ?? input.entries;
  const byPrefix = new Map<readonly SignedAuditEntryV1[], SignedAuditCheckpointV1[]>();
  for (const { checkpoint, prefix } of await prefixBoundCheckpoints(
    [...verified.values()], entries, options.hasher,
  )) {
    byPrefix.set(prefix, [...(byPrefix.get(prefix) ?? []), checkpoint]);
  }
  for (const [prefix, group] of byPrefix) {
    group.sort((left, right) => compareDecimal(left.core.treeSize, right.core.treeSize));
    let below: SignedAuditCheckpointV1 | undefined;
    for (const checkpoint of group) {
      if (below !== undefined) contains.push([checkpoint.checkpointDigest, below.checkpointDigest]);
      const from = Number(below?.core.treeSize ?? 0);
      for (let index = from; index < Number(checkpoint.core.treeSize); index += 1) {
        hold(prefix[index]!.entryDigest, checkpoint.checkpointDigest);
      }
      below = checkpoint;
    }
  }

  const reasons = new Set<string>();
  const geneses: DatingGenesis[] = [];
  const candidates = [
    ...input.offered.map((candidate) => ({ candidate, offered: true })),
    ...entries.filter(isSuccessorGenesis).map((candidate) => ({ candidate, offered: false })),
  ];
  for (const { candidate, offered } of candidates) {
    const genesis = await successorGenesis(options, input, candidate, verified);
    if (genesis !== undefined) geneses.push(genesis);
    else if (offered) reasons.add(AUDIT_REASON_CODES.SUCCESSOR_GENESIS_MISMATCH);
  }

  const now = options.verifiedAt?.();
  const attestations = [
    ...(input.carried?.observations ?? [])
      .filter((receipt) => keyIsLive(input.policy.trustedObservers, receipt.core.observer, now))
      .map((receipt) => ({ digest: receipt.core.checkpointDigest, at: receipt.core.observedAt })),
    ...(input.carried?.anchors ?? [])
      .map((receipt) => ({ digest: receipt.checkpointDigest, at: receipt.issuedAt })),
  ];
  return {
    ...dateEvidence({
      checkpoints,
      geneses,
      pinned: pinnedCheckpoints(input.policy),
      attestations,
      contains,
      holders,
    }),
    reasons,
  };
}
