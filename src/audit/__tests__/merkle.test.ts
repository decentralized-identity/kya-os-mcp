import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { Rfc9162MerkleTree } from '../merkle.js';
import type { Digest } from '../types.js';

const digest = (index: number) =>
  `sha256:${createHash('sha256').update(`entry-${index}`).digest('hex')}` as Digest;

const nodeHash = (prefix: number, ...parts: Uint8Array[]) => {
  const hash = createHash('sha256');
  hash.update(Uint8Array.of(prefix));
  for (const part of parts) hash.update(part);
  return `sha256:${hash.digest('hex')}`;
};

const bytes = (value: Digest) => Buffer.from(value.slice('sha256:'.length), 'hex');

describe('RFC 9162 Merkle tree', () => {
  const tree = new Rfc9162MerkleTree(
    new CryptoProviderAuditHasher(new NodeCryptoProvider()),
  );

  it('uses the RFC leaf and node domain-separation bytes', async () => {
    const left = digest(0);
    const right = digest(1);
    const leftLeaf = nodeHash(0x00, bytes(left));
    const rightLeaf = nodeHash(0x00, bytes(right));
    const expectedRoot = nodeHash(0x01, bytes(leftLeaf as Digest), bytes(rightLeaf as Digest));

    expect(await tree.leafHash(left)).toBe(leftLeaf);
    expect(await tree.root([left, right])).toBe(expectedRoot);
  });

  it('produces valid inclusion proofs for every leaf in an uneven tree', async () => {
    const leaves = Array.from({ length: 7 }, (_, index) => digest(index));
    const root = await tree.root(leaves);

    for (let index = 0; index < leaves.length; index += 1) {
      const proof = await tree.inclusionProof(leaves, index);
      await expect(tree.verifyInclusion({
        leaf: leaves[index]!,
        leafIndex: index,
        treeSize: leaves.length,
        root,
        auditPath: proof,
      })).resolves.toBe(true);
    }
  });

  it('rejects a mutated inclusion path', async () => {
    const leaves = Array.from({ length: 7 }, (_, index) => digest(index));
    const proof = await tree.inclusionProof(leaves, 3);
    proof[0] = digest(99);

    expect(await tree.verifyInclusion({
      leaf: leaves[3]!,
      leafIndex: 3,
      treeSize: leaves.length,
      root: await tree.root(leaves),
      auditPath: proof,
    })).toBe(false);
  });

  it('proves consistency for every prefix of growing uneven trees', async () => {
    const leaves = Array.from({ length: 20 }, (_, index) => digest(index));
    const newRoot = await tree.root(leaves);

    for (let oldSize = 1; oldSize <= leaves.length; oldSize += 1) {
      const oldRoot = await tree.root(leaves.slice(0, oldSize));
      const proof = await tree.consistencyProof(leaves, oldSize);
      await expect(tree.verifyConsistency({
        oldSize,
        newSize: leaves.length,
        oldRoot,
        newRoot,
        auditPath: proof,
      })).resolves.toBe(true);
    }
  });

  it('rejects inconsistent roots and impossible proof ranges', async () => {
    const leaves = Array.from({ length: 8 }, (_, index) => digest(index));
    const proof = await tree.consistencyProof(leaves, 4);
    expect(await tree.verifyConsistency({
      oldSize: 4,
      newSize: 8,
      oldRoot: digest(100),
      newRoot: await tree.root(leaves),
      auditPath: proof,
    })).toBe(false);
    await expect(tree.consistencyProof(leaves, 9)).rejects.toThrow(/old tree size/i);
  });
});
