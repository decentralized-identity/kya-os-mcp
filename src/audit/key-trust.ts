/**
 * Whether a verification policy trusts a signing key for an artifact: by the key's time interval,
 * and by the checkpoints that bound it or its ledger epoch, resolved against supporting checkpoints.
 */

import type {
  AuditLedgerRef,
  Digest,
  HistoricalAuditKeyPolicy,
  SignerRef,
} from './types.js';

export function sameSigner(left: SignerRef, right: SignerRef): boolean {
  return left.did === right.did && left.kid === right.kid && left.alg === right.alg;
}

export function keyIsValidAt(policy: HistoricalAuditKeyPolicy, at: number): boolean {
  return (policy.validFrom === undefined || at >= policy.validFrom) &&
    (policy.validUntil === undefined || at <= policy.validUntil);
}

export interface CheckpointBounds {
  validFromCheckpoint?: Digest;
  validUntilCheckpoint?: Digest;
}

export interface CheckpointBoundary extends AuditLedgerRef {
  treeSize: bigint;
}

export type CheckpointBoundaries = ReadonlyMap<string, CheckpointBoundary>;

export type BoundStatus = 'within' | 'unresolved' | 'outside';

/**
 * Checkpoint bounds place an artifact by the tree size it first appears in:
 * `sequence + 1` for an entry, `treeSize` for a checkpoint or an observation.
 * A key valid until checkpoint C covers positions up to C's tree size; a key
 * valid from C covers positions after it. A boundary that is missing, or
 * belongs to another ledger epoch, cannot place the artifact.
 */
function positionWithin(
  bounds: CheckpointBounds,
  ledger: AuditLedgerRef,
  position: bigint,
  boundaries: CheckpointBoundaries,
): BoundStatus {
  const resolve = (digest: Digest | undefined): bigint | null | undefined => {
    if (digest === undefined) return undefined;
    const boundary = boundaries.get(digest);
    return boundary?.ledgerId === ledger.ledgerId &&
      boundary.ledgerEpochId === ledger.ledgerEpochId
      ? boundary.treeSize
      : null;
  };
  const from = resolve(bounds.validFromCheckpoint);
  const until = resolve(bounds.validUntilCheckpoint);
  if ((typeof from === 'bigint' && position <= from) ||
    (typeof until === 'bigint' && position > until)) return 'outside';
  return from === null || until === null ? 'unresolved' : 'within';
}

function strictest(...values: BoundStatus[]): BoundStatus {
  if (values.includes('outside')) return 'outside';
  return values.includes('unresolved') ? 'unresolved' : 'within';
}

export function keyTrust(
  keys: readonly HistoricalAuditKeyPolicy[],
  signer: SignerRef,
  at: number,
  ledger: AuditLedgerRef,
  position: bigint,
  boundaries: CheckpointBoundaries,
  epochBounds: CheckpointBounds = {},
): BoundStatus {
  const epoch = positionWithin(epochBounds, ledger, position, boundaries);
  let best: BoundStatus = 'outside';
  for (const key of keys) {
    if (!sameSigner(key.signer, signer) || !keyIsValidAt(key, at)) continue;
    const status = strictest(epoch, positionWithin(key, ledger, position, boundaries));
    if (status === 'within') return status;
    if (status === 'unresolved') best = status;
  }
  return best;
}

/**
 * Whether the policy still lists the signer as valid at `now`. A checkpoint
 * bound names a checkpoint that already exists, so a key valid only until one
 * has been retired, while one valid from one has already started.
 */
export function keyIsCurrent(
  keys: readonly HistoricalAuditKeyPolicy[],
  signer: SignerRef,
  now: number,
): boolean {
  return keys.some((key) => sameSigner(key.signer, signer) && keyIsValidAt(key, now) &&
    key.validUntilCheckpoint === undefined);
}
