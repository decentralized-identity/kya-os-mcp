/**
 * What a replay bundle's checkpoints and Merkle proofs prove: the checkpoint history of each ledger
 * epoch, the bundle-bound inclusion and consistency proofs, the binding of each checkpoint to the
 * entries it covers, and whether the checkpoints cover what the bundle selects. Anyone may hand a
 * verifier a bundle, so the work here grows with the bundle, never with its square.
 */

import { canonicalizeJson } from '../utils/canonical-json.js';
import type { AuditHasher } from './crypto.js';
import {
  AUDIT_BUNDLE_MEDIA_TYPES,
  compareDecimal,
  firstByKey,
  includedArrays,
  ledgerEpochKey,
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
  AuditLedgerRef,
  AuditReplayBundleV1,
  AuditVerificationDimension,
  Digest,
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

function checkpointKey(ledger: AuditLedgerRef, checkpointDigest: string): string {
  return `${ledgerEpochKey(ledger)}\0${checkpointDigest}`;
}

function entryKey(ledger: AuditLedgerRef, entryDigest: string, sequence: string): string {
  return `${ledgerEpochKey(ledger)}\0${entryDigest}\0${sequence}`;
}

/**
 * The longest prefix of one epoch's leaves that the bundle carries whole: entries 0..n-1, each
 * once, in bundle order. A checkpoint over a tree no larger is bound by recomputing its root.
 */
function wholePrefix(epochEntries: readonly SignedAuditEntryV1[]): SignedAuditEntryV1[] {
  const bySequence = new Map<string, { entry: SignedAuditEntryV1; position: number; count: number }>();
  epochEntries.forEach((entry, position) => {
    const seen = bySequence.get(entry.core.sequence);
    if (seen === undefined) bySequence.set(entry.core.sequence, { entry, position, count: 1 });
    else seen.count += 1;
  });
  const prefix: SignedAuditEntryV1[] = [];
  let previousPosition = -1;
  while (prefix.length < epochEntries.length) {
    const next = bySequence.get(String(prefix.length));
    if (next === undefined || next.count !== 1 || next.position < previousPosition) break;
    prefix.push(next.entry);
    previousPosition = next.position;
  }
  return prefix;
}

/**
 * The RFC 9162 roots of the prefixes of `leaves` of the given sizes, in one pass: each leaf is
 * hashed once into the perfect subtrees of the prefix so far, and a prefix's root folds those
 * subtrees from the right. Hashing every prefix from its leaves would cost the square of the
 * ledger for a bundle with a checkpoint at every size.
 */
export async function prefixRoots(
  hasher: AuditHasher,
  leaves: readonly Digest[],
  sizes: Iterable<number>,
): Promise<Map<number, Digest>> {
  const tree = new Rfc9162MerkleTree(hasher);
  const wanted = [...new Set(sizes)]
    .filter((size) => size >= 1 && size <= leaves.length)
    .sort((left, right) => left - right);
  const roots = new Map<number, Digest>();
  // The perfect subtrees of the leaves consumed so far, largest first.
  const subtrees: { size: number; root: Digest }[] = [];
  let consumed = 0;
  for (const size of wanted) {
    for (; consumed < size; consumed += 1) {
      let joined = { size: 1, root: await tree.leafHash(leaves[consumed]!) };
      while (subtrees.at(-1)?.size === joined.size) {
        const left = subtrees.pop()!;
        joined = { size: left.size * 2, root: await tree.nodeHash(left.root, joined.root) };
      }
      subtrees.push(joined);
    }
    let root = subtrees.at(-1)!.root;
    for (let index = subtrees.length - 2; index >= 0; index -= 1) {
      root = await tree.nodeHash(subtrees[index]!.root, root);
    }
    roots.set(size, root);
  }
  return roots;
}

/**
 * Binds a checkpoint to the whole prefix the bundle carries for it, given the prefix's last entry
 * and recomputed root: the prefix must be the range it signed, end at the head it signed, and hash
 * to the root it signed.
 */
function prefixBinding(
  checkpoint: SignedAuditCheckpointV1,
  head: SignedAuditEntryV1 | undefined,
  root: Digest | undefined,
): AuditVerificationDimension {
  const { core } = checkpoint;
  if (core.firstSequence !== '0' || head === undefined ||
    head.core.sequence !== core.lastSequence || head.entryDigest !== core.headEntryDigest) {
    return dimension('invalid', [AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH]);
  }
  return root === core.rootDigest
    ? dimension('valid')
    : dimension('invalid', [AUDIT_REASON_CODES.CHECKPOINT_ROOT_MISMATCH]);
}

/**
 * How the bundle binds each of its checkpoints to the entries it carries. A checkpoint over a tree
 * no larger than the prefix its epoch carries whole is bound by its recomputed root, all of an
 * epoch's roots computed in one pass; any other, by inclusion proofs for the entries it covers.
 */
export async function checkpointBindings(
  checkpoints: readonly SignedAuditCheckpointV1[],
  entries: readonly SignedAuditEntryV1[],
  verifiedInclusions: ReadonlySet<string>,
  hasher: AuditHasher,
): Promise<(checkpoint: SignedAuditCheckpointV1) => AuditVerificationDimension> {
  const epochs = new Map<string, SignedAuditEntryV1[]>();
  for (const entry of entries) {
    const key = ledgerEpochKey(entry.core);
    const group = epochs.get(key) ?? [];
    group.push(entry);
    epochs.set(key, group);
  }
  const prefixes = new Map([...epochs].map(([key, group]) => [key, wholePrefix(group)]));
  const sizes = new Map<string, number[]>();
  for (const checkpoint of checkpoints) {
    const key = ledgerEpochKey(checkpoint.core);
    const treeSize = BigInt(checkpoint.core.treeSize);
    if (treeSize < 1n || treeSize > BigInt(prefixes.get(key)?.length ?? 0)) continue;
    const group = sizes.get(key) ?? [];
    group.push(Number(checkpoint.core.treeSize));
    sizes.set(key, group);
  }
  const roots = new Map<string, Map<number, Digest>>();
  for (const [key, wanted] of sizes) {
    const leaves = prefixes.get(key)!.map((entry) => entry.entryDigest);
    roots.set(key, await prefixRoots(hasher, leaves, wanted));
  }
  return (checkpoint) => {
    const key = ledgerEpochKey(checkpoint.core);
    const prefix = prefixes.get(key) ?? [];
    const treeSize = BigInt(checkpoint.core.treeSize);
    if (treeSize <= BigInt(prefix.length)) {
      const size = Number(treeSize);
      return prefixBinding(checkpoint, prefix[size - 1], roots.get(key)?.get(size));
    }
    const covered = (epochs.get(key) ?? []).filter((entry) => BigInt(entry.core.sequence) < treeSize);
    return verifyInclusionBinding(checkpoint, covered, verifiedInclusions);
  };
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

  // Each group is sorted by tree size above.
  const treeSizes = new Map([...groups].map(([key, group]) =>
    [key, canonicalizeJson(group.map((checkpoint) => checkpoint.core.treeSize))]));
  const selected = new Set(selections.map(ledgerEpochKey));
  const byDigest = firstByKey(checkpoints, (checkpoint) =>
    checkpointKey(checkpoint.core, checkpoint.checkpointDigest));
  for (const selection of selections) {
    const expected = [...selection.checkpointTreeSizes]
      .sort(compareDecimal);
    if ((treeSizes.get(ledgerEpochKey(selection)) ?? '[]') !== canonicalizeJson(expected)) {
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
    if (!selected.has(ledgerEpochKey(predecessor))) continue;
    const terminal = byDigest.get(
      checkpointKey(predecessor, details.previousTerminalCheckpointDigest),
    );
    if (terminal === undefined) {
      reasons.add(AUDIT_REASON_CODES.CHECKPOINT_CHAIN_MISMATCH);
      continue;
    }
    // The successor genesis commits where the predecessor epoch ends, so a
    // predecessor checkpoint signed over a larger tree is a second authority
    // still checkpointing after rollover. Entries past the terminal are not:
    // the terminal checkpoint's own lifecycle event lands there legitimately.
    const largest = groups.get(ledgerEpochKey(predecessor))!.at(-1)!;
    if (BigInt(largest.core.treeSize) > BigInt(terminal.core.treeSize)) {
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
  const checkpointsByKey = firstByKey(checkpoints, (value) =>
    checkpointKey(value.core, value.checkpointDigest));
  const entriesByKey = firstByKey(entries, (value) =>
    entryKey(value.core, value.entryDigest, value.core.sequence));
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
    const checkpoint = checkpointsByKey.get(checkpointKey(item, item.checkpointDigest));
    const entry = entriesByKey.get(entryKey(item, item.entryDigest, item.sequence));
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
    const oldCheckpoint = checkpointsByKey.get(checkpointKey(item, item.oldCheckpointDigest));
    const newCheckpoint = checkpointsByKey.get(checkpointKey(item, item.newCheckpointDigest));
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
function verifyInclusionBinding(
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

/**
 * Whether, for every selection, one of `checkpoints` covers it: of the selection's ledger epoch,
 * over a tree that holds every entry it selects. A checkpoint, an observation or a supporting
 * anchor is evidence about the entries a bundle selects only through such a checkpoint.
 */
export function coversEverySelection(
  selections: readonly AuditBundleSelectionV1[],
  checkpoints: readonly SignedAuditCheckpointV1[],
): boolean {
  const largest = new Map<string, bigint>();
  for (const checkpoint of checkpoints) {
    const key = ledgerEpochKey(checkpoint.core);
    const treeSize = BigInt(checkpoint.core.treeSize);
    if (treeSize > (largest.get(key) ?? -1n)) largest.set(key, treeSize);
  }
  return selections.every((selection) =>
    (largest.get(ledgerEpochKey(selection)) ?? -1n) > BigInt(selection.lastSequence));
}
