/**
 * How a replay bundle binds a checkpoint to the entries it carries: by the root recomputed over
 * the whole leaf prefix it holds, every root of an epoch in one pass over its leaves, or else by
 * an inclusion proof for each entry the checkpoint covers.
 */

import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { checkpointBindings, prefixRoots, verifyMerkleProofComponents } from '../bundle-checkpoints.js';
import { AuditCheckpointBuilder, MemoryAuditCheckpointStore } from '../checkpoint.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { Rfc9162MerkleTree } from '../merkle.js';
import type { AuditReplayBundleV1, Digest, SignedAuditCheckpointV1, SignedAuditEntryV1 } from '../types.js';
import { AUDIT_BUNDLE_MEDIA_TYPES } from '../bundle-components.js';
import { AUDIT_REASON_CODES } from '../verifier.js';
import { recordedHistory, TestSigner } from './audit-fixtures.js';

const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
const leaves: Digest[] = Array.from({ length: 33 }, (_, index): Digest =>
  `sha256:${index.toString(16).padStart(64, '0')}`);

describe('prefix roots', () => {
  it('match the root of every prefix, asked for in any order', async () => {
    const sizes = Array.from({ length: leaves.length }, (_, index) => leaves.length - index);
    const roots = await prefixRoots(hasher, leaves, sizes);
    const tree = new Rfc9162MerkleTree(hasher);

    for (const size of sizes) {
      expect(roots.get(size)).toBe(await tree.root(leaves.slice(0, size)));
    }
  });

  it('answer nothing for a prefix the leaves do not hold', async () => {
    const roots = await prefixRoots(hasher, leaves.slice(0, 4), [0, 5, 4]);

    expect([...roots.keys()]).toEqual([4]);
  });
});

describe('checkpoint bindings', () => {
  const recorded = async () => {
    const { journal, ledger, entries } = await recordedHistory();
    const checkpoint = await new AuditCheckpointBuilder({
      journal, store: new MemoryAuditCheckpointStore(), signer: new TestSigner(), hasher,
      clock: { now: () => 1_750_000_002_000 },
    }).createCheckpoint(ledger);
    return { entries, checkpoint };
  };
  const tampered = (checkpoint: SignedAuditCheckpointV1, core: Partial<SignedAuditCheckpointV1['core']>) =>
    ({ ...checkpoint, core: { ...checkpoint.core, ...core } });

  it('binds a checkpoint over the whole prefix by its root, and refuses one whose root or head differ', async () => {
    const { entries, checkpoint } = await recorded();
    const wrongRoot = tampered(checkpoint, { rootDigest: `sha256:${'f'.repeat(64)}` });
    const wrongHead = tampered(checkpoint, { headEntryDigest: entries[0]!.entryDigest });
    const bind = await checkpointBindings([checkpoint, wrongRoot, wrongHead], entries, new Map(), hasher);

    expect(bind(checkpoint)).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(bind(wrongRoot)).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_ROOT_MISMATCH],
    });
    expect(bind(wrongHead)).toEqual({
      verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.CHECKPOINT_RANGE_MISMATCH],
    });
  });

  it('asks for inclusion proofs where the bundle carries a leaf twice or out of order', async () => {
    const { entries, checkpoint } = await recorded();
    const missing = { verdict: 'invalid', reasonCodes: [AUDIT_REASON_CODES.MERKLE_PROOF_MISSING] };

    const twice = await checkpointBindings([checkpoint], [...entries, entries[1]!], new Map(), hasher);
    const reordered = await checkpointBindings([checkpoint], [entries[1]!, entries[0]!, ...entries.slice(2)], new Map(), hasher);

    expect(twice(checkpoint)).toEqual(missing);
    expect(reordered(checkpoint)).toEqual(missing);
  });
});

describe('inclusion counts', () => {
  /** Ledger epoch `ledgerEpochId`'s one-leaf tree, with the same entry and checkpoint digests in every epoch. */
  const epoch = async (ledgerEpochId: string) => {
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId };
    const entryDigest = leaves[0]!;
    const checkpointDigest = leaves[1]!;
    const rootDigest = await new Rfc9162MerkleTree(hasher).root([entryDigest]);
    return {
      entry: { core: { ...ledger, sequence: '0' }, entryDigest } as unknown as SignedAuditEntryV1,
      checkpoint: { core: { ...ledger, treeSize: '1', rootDigest }, checkpointDigest } as unknown as SignedAuditCheckpointV1,
      proof: { ...ledger, sequence: '0', entryDigest, checkpointDigest, proof: { leafIndex: '0', treeSize: '1', auditPath: [] } },
    };
  };
  const carrying = (proofs: unknown[]) => ({
    components: [{ path: 'inclusion-proofs.json', mediaType: AUDIT_BUNDLE_MEDIA_TYPES.inclusionProofs, disposition: 'included', content: proofs }],
  }) as unknown as AuditReplayBundleV1;

  it('count each entry once for each checkpoint, in the ledger epoch the proof names, though another has its digests', async () => {
    const [first, second] = [await epoch('epoch_1'), await epoch('epoch_2')];
    const { dimension, inclusionCounts } = await verifyMerkleProofComponents(
      carrying([first.proof, second.proof, first.proof]),
      [first.entry, second.entry],
      [first.checkpoint, second.checkpoint],
      hasher,
    );

    expect(dimension.verdict).toBe('valid');
    expect([...inclusionCounts.values()]).toEqual([1, 1]);
  });
});
