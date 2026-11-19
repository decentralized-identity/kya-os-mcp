/**
 * Anyone may hand a verifier a replay bundle, so the work of reading one grows with the bundle and
 * never with its square. Each case counts the reads of a member every pass over the bundle's
 * entries or checkpoints makes, at two sizes: work that grows with the bundle doubles when the
 * bundle does, and work that grows with its square quadruples. Counting, not timing, keeps the
 * cases deterministic.
 */

import { describe, expect, it } from 'vitest';
import { checkpointBindings } from '../bundle-checkpoints.js';
import { selectionCompleteness, verifySupportingAnchors } from '../bundle-evidence.js';
import type {
  AuditAnchorReceipt,
  AuditBundleSelectionV1,
  AuditVerificationPolicyV1,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from '../types.js';
import { hasher, ledger } from './observer-fixtures.js';

/** A bundle twice as large may cost a little more than twice the work, never four times. */
const MOST_GROWTH = 2.5;

const digest = (n: number, tag: string): string =>
  `sha256:${(tag + n.toString(16)).padStart(64, '0').slice(-64)}`;

/** `value` with `member` read through a getter that counts each read in `reads`. */
function counted<T extends object>(value: T, member: keyof T & string, reads: { count: number }): T {
  const inner = value[member];
  return Object.defineProperty({ ...value }, member, {
    enumerable: true,
    get: () => {
      reads.count += 1;
      return inner;
    },
  });
}

/** Entries 0 to `size` - 1 of one ledger epoch, each counting the reads of its `core`. */
function entries(size: number, reads: { count: number }): SignedAuditEntryV1[] {
  return Array.from({ length: size }, (_, n) => counted({
    core: { ...ledger, sequence: String(n), recorder: { did: 'did:key:z', kid: 'did:key:z#k', alg: 'EdDSA' } },
    entryDigest: digest(n, 'e'),
    eventDigest: digest(n, 'v'),
  } as unknown as SignedAuditEntryV1, 'core', reads));
}

/** `count` checkpoints of one ledger epoch, each over a tree of `treeSize`, counting reads of their digest. */
function checkpoints(count: number, treeSize: number, reads: { count: number }): SignedAuditCheckpointV1[] {
  return Array.from({ length: count }, (_, n) => counted({
    core: {
      ...ledger, treeSize: String(treeSize), firstSequence: '0', lastSequence: String(treeSize - 1),
      headEntryDigest: digest(treeSize - 1, 'e'), rootDigest: digest(n, 'r'), previousCheckpointDigest: null,
    },
    checkpointDigest: digest(n, 'c'),
  } as unknown as SignedAuditCheckpointV1, 'checkpointDigest', reads));
}

/** The reads `work` makes on a bundle of `size`, and on one of twice that size. */
async function readsAt(size: number, work: (size: number, reads: { count: number }) => Promise<void> | void) {
  const small = { count: 0 };
  await work(size, small);
  const large = { count: 0 };
  await work(size * 2, large);
  return { small: small.count, large: large.count };
}

describe('the work of reading a replay bundle', () => {
  it('grows with the bundle when every checkpoint runs past the entries it carries', async () => {
    const { small, large } = await readsAt(400, async (size, reads) => {
      const carried = entries(size, reads);
      const signed = checkpoints(size, size + 10, { count: 0 });
      const bind = await checkpointBindings(signed, carried, new Map(), hasher);
      for (const checkpoint of signed) bind(checkpoint);
    });

    expect(large).toBeLessThanOrEqual(small * MOST_GROWTH);
  });

  it('grows with the bundle when it selects many ranges of one ledger epoch', async () => {
    const { small, large } = await readsAt(400, (size, reads) => {
      const carried = entries(size, reads);
      const selections = Array.from({ length: size }, (_, n): AuditBundleSelectionV1 => ({
        ...ledger, firstSequence: String(n), lastSequence: String(n),
        expectedHeadDigest: digest(n, 'e'), checkpointTreeSizes: [],
      } as unknown as AuditBundleSelectionV1));
      selectionCompleteness(selections, carried, [], []);
    });

    expect(large).toBeLessThanOrEqual(small * MOST_GROWTH);
  });

  it('grows with the bundle when it carries a supporting anchor for each of many checkpoints', async () => {
    const { small, large } = await readsAt(400, async (size, reads) => {
      const signed = checkpoints(size, 1, reads);
      const anchors = signed.map((_, n): AuditAnchorReceipt => ({
        schema: 'https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0',
        kind: 'worm', providerId: 'worm-1', checkpointDigest: digest(n, 'c'), issuedAt: 1,
      }));
      const policy = { trustedSupportingAnchors: [] } as unknown as AuditVerificationPolicyV1;
      await verifySupportingAnchors(anchors, signed, policy, async () => true);
    });

    expect(large).toBeLessThanOrEqual(small * MOST_GROWTH);
  });
});
