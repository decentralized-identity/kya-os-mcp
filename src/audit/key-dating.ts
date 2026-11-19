/**
 * Dating audit artifacts whose signing key has ended. Until a key ends, the time an artifact states
 * is its holder's word and the policy takes it. Once it has ended, whoever still holds the key can
 * sign any time, so the stated time proves nothing: the artifact must be dated at or before the
 * key's end by evidence its signer does not control.
 *
 * Evidence dates checkpoints, and a checkpoint dates every entry its tree holds:
 * - a checkpoint the verification policy names by digest, whose tree the policy's operator vouches
 *   for, is dated before any end;
 * - an observer or supporting anchor places a checkpoint at the time it attests;
 * - a checkpoint, or a successor epoch's genesis, places itself at the time it states while its
 *   own key is live, or once something else dates it before its key's end; a genesis so placed
 *   dates the terminal checkpoint of the epoch before it, whose digest it commits to;
 * - a checkpoint whose tree holds an earlier one's, by its chain link, a consistency proof or a
 *   prefix recomputed from the same leaves, dates that earlier one too.
 */

import type { Digest } from './types.js';

/** A checkpoint that verified apart from its date. */
export interface DatingCheckpoint {
  digest: Digest;
  createdAt: number;
  /** When its issuer key ended, if it has (`keyEnd` in `./key-trust.ts`). */
  until: number | undefined;
}

/** A successor epoch's genesis that verified apart from its date. */
export interface DatingGenesis {
  entryDigest: Digest;
  recordedAt: number;
  /** When its recorder key ended, if it has. */
  until: number | undefined;
  /** The digest of the terminal checkpoint of the epoch before it. */
  commits: Digest;
}

export interface DatingEvidence {
  checkpoints: readonly DatingCheckpoint[];
  geneses: readonly DatingGenesis[];
  /** Checkpoints the verification policy names by digest. */
  pinned: ReadonlySet<Digest>;
  /** Times observers and supporting anchors place checkpoints at. */
  attestations: readonly { digest: Digest; at: number }[];
  /** Pairs of a checkpoint and an earlier checkpoint whose tree it holds. */
  contains: readonly (readonly [newer: Digest, older: Digest])[];
  /** The checkpoints known to hold each entry, by entry digest. */
  holders: ReadonlyMap<Digest, readonly Digest[]>;
}

export interface AuditDating {
  /** The earliest time the evidence places a checkpoint at; `undefined` when nothing dates it. */
  checkpointAt(digest: Digest): number | undefined;
  /** The earliest time the evidence places an entry at, through a checkpoint that holds it. */
  entryAt(entryDigest: Digest): number | undefined;
}

function earlier(left: number | undefined, right: number | undefined): number | undefined {
  if (left === undefined) return right;
  return right === undefined || left <= right ? left : right;
}

/** Whether an artifact's own time is its key's word: the key is live, or it is dated before the end. */
function credible(until: number | undefined, datedAt: number | undefined): boolean {
  return until === undefined || (datedAt !== undefined && datedAt <= until);
}

/** Every time the evidence can place each checkpoint at, settled to its earliest. */
export function dateEvidence(evidence: DatingEvidence): AuditDating {
  const times = new Map<Digest, number>();
  let changed: boolean;
  const lower = (digest: Digest, at: number | undefined): void => {
    if (at === undefined) return;
    const known = times.get(digest);
    if (known === undefined || at < known) {
      times.set(digest, at);
      changed = true;
    }
  };
  const entryAt = (entryDigest: Digest): number | undefined => {
    let at: number | undefined;
    for (const holder of evidence.holders.get(entryDigest) ?? []) at = earlier(at, times.get(holder));
    return at;
  };

  for (const digest of evidence.pinned) lower(digest, -Infinity);
  for (const { digest, at } of evidence.attestations) lower(digest, at);
  // Times only fall, and each is one the evidence states, so this settles.
  do {
    changed = false;
    for (const checkpoint of evidence.checkpoints) {
      if (credible(checkpoint.until, times.get(checkpoint.digest))) {
        lower(checkpoint.digest, checkpoint.createdAt);
      }
    }
    for (const genesis of evidence.geneses) {
      const datedAt = entryAt(genesis.entryDigest);
      if (credible(genesis.until, datedAt)) {
        lower(genesis.commits, earlier(datedAt, genesis.recordedAt));
      }
    }
    for (const [newer, older] of evidence.contains) lower(older, times.get(newer));
  } while (changed);

  return { checkpointAt: (digest) => times.get(digest), entryAt };
}
