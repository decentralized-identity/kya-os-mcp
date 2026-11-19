/**
 * What a replay bundle's checkpoints and Merkle proofs prove: the checkpoint history of each ledger
 * epoch, the bundle-bound inclusion and consistency proofs, and the binding of a subset export's
 * entries to the checkpoint that covers them.
 */

import { canonicalizeJson } from '../utils/canonical-json.js';
import type { AuditHasher } from './crypto.js';
import {
  AUDIT_BUNDLE_MEDIA_TYPES,
  compareDecimal,
  includedArrays,
  ledgerEpochKey,
  sameLedgerEpoch,
} from './bundle-components.js';
import { Rfc9162MerkleTree } from './merkle.js';
import {
  auditBundleConsistencyProofSchema,
  auditBundleInclusionProofSchema,
} from './schemas.js';
import type {
  AuditBundleConsistencyProofV1,
  AuditBundleInclusionProofV1,
  AuditBundleSelectionV1,
  AuditReplayBundleV1,
  AuditVerificationDimension,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from './types.js';
import { AUDIT_REASON_CODES, dimension } from './verdicts.js';

function inclusionKey(checkpointDigest: string, entryDigest: string, sequence: string): string {
  return `${checkpointDigest}\0${entryDigest}\0${sequence}`;
}

function consistencyKey(oldCheckpointDigest: string, newCheckpointDigest: string): string {
  return `${oldCheckpointDigest}\0${newCheckpointDigest}`;
}

export /** True when the entries are exactly the leaves 0..treeSize-1, in order. */
function isCompletePrefix(entries: readonly SignedAuditEntryV1[], treeSize: string): boolean {
  return BigInt(entries.length) === BigInt(treeSize) &&
    entries.every((entry, index) => entry.core.sequence === String(index));
}

export function verifyCheckpointHistory(
  checkpoints: readonly SignedAuditCheckpointV1[],
  entries: readonly SignedAuditEntryV1[],
  selections: readonly AuditBundleSelectionV1[],
  verifiedConsistency: ReadonlySet<string>,
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
    group.sort((left, right) => compareDecimal(left.core.treeSize, right.core.treeSize));
    const included = new Set(group.map((checkpoint) => checkpoint.checkpointDigest));
    for (let index = 1; index < group.length; index += 1) {
      const previous = group[index - 1]!;
      const current = group[index]!;
      if (current.core.treeSize === previous.core.treeSize) {
        reasons.add(AUDIT_REASON_CODES.CHECKPOINT_FORK_DETECTED);
        continue;
      }
      const claimed = current.core.previousCheckpointDigest;
      if (claimed === previous.checkpointDigest) continue;
      // A subset export may omit intermediate checkpoints. An unlinked pair is
      // accepted only when an omitted checkpoint could sit between the two and
      // a verified consistency proof binds them: the proof, not the chain link,
      // is the split-view guarantee. Naming another included checkpoint, or
      // none, is a forked checkpoint chain.
      const omittable = claimed !== null && !included.has(claimed) &&
        BigInt(current.core.treeSize) - BigInt(previous.core.treeSize) > 1n;
      if (!omittable || !verifiedConsistency.has(
        consistencyKey(previous.checkpointDigest, current.checkpointDigest),
      )) {
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
    const predecessor = {
      ledgerId: entry.core.ledgerId,
      ledgerEpochId: details.previousEpochId,
    };
    if (!selections.some((selection) => sameLedgerEpoch(selection, predecessor))) continue;
    const terminal = checkpoints.find((checkpoint) =>
      sameLedgerEpoch(checkpoint.core, predecessor) &&
      checkpoint.checkpointDigest === details.previousTerminalCheckpointDigest);
    if (terminal === undefined) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH);
      continue;
    }
    // The successor genesis commits where the predecessor epoch ends, so a
    // predecessor checkpoint signed over a larger tree is a second authority
    // still checkpointing after rollover. Entries past the terminal are not:
    // the terminal checkpoint's own lifecycle event lands there legitimately.
    const terminalSize = BigInt(terminal.core.treeSize);
    if (checkpoints.some((checkpoint) =>
      sameLedgerEpoch(checkpoint.core, predecessor) &&
      BigInt(checkpoint.core.treeSize) > terminalSize)) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_FORK_DETECTED);
    }
  }

  return dimension(reasons.size === 0 ? 'valid' : 'invalid', reasons);
}

export interface MerkleProofVerification {
  dimension: AuditVerificationDimension;
  /** Inclusion proofs that verified, keyed by checkpoint, entry digest, and sequence. */
  inclusions: Set<string>;
  /** Consistency proofs that verified, keyed by old and new checkpoint digest. */
  consistencies: Set<string>;
}

export async function verifyMerkleProofComponents(
  bundle: AuditReplayBundleV1,
  entries: readonly SignedAuditEntryV1[],
  checkpoints: readonly SignedAuditCheckpointV1[],
  hasher: AuditHasher,
): Promise<MerkleProofVerification> {
  const reasons = new Set<string>();
  const inclusions = new Set<string>();
  const consistencies = new Set<string>();
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
    } else {
      inclusions.add(inclusionKey(item.checkpointDigest, item.entryDigest, item.sequence));
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
    } else {
      consistencies.add(consistencyKey(item.oldCheckpointDigest, item.newCheckpointDigest));
    }
  }
  return {
    dimension: dimension(reasons.size === 0 ? 'valid' : 'invalid', reasons),
    inclusions,
    consistencies,
  };
}

/**
 * Without the complete leaf prefix a checkpoint's root cannot be recomputed,
 * so every entry it covers must instead carry a verified inclusion proof
 * against it, and a covered head entry must be the one the checkpoint signed.
 */
export function verifyInclusionBinding(
  checkpoint: SignedAuditCheckpointV1,
  covered: readonly SignedAuditEntryV1[],
  verifiedInclusions: ReadonlySet<string>,
): AuditVerificationDimension {
  const reasons = new Set<string>();
  const headSequence = String(BigInt(checkpoint.core.treeSize) - 1n);
  for (const entry of covered) {
    if (!verifiedInclusions.has(
      inclusionKey(checkpoint.checkpointDigest, entry.entryDigest, entry.core.sequence),
    )) {
      reasons.add(AUDIT_REASON_CODES.MERKLE_PROOF_MISSING);
    }
    if (entry.core.sequence === headSequence &&
      entry.entryDigest !== checkpoint.core.headEntryDigest) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH);
    }
  }
  return dimension(reasons.size === 0 ? 'valid' : 'invalid', reasons);
}
