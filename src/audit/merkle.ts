import type { AuditHasher } from './crypto.js';
import type { Digest } from './types.js';

const DIGEST_PATTERN = /^sha256:([a-f0-9]{64})$/;

export interface AuditInclusionVerification {
  leaf: Digest;
  leafIndex: number;
  treeSize: number;
  root: Digest;
  auditPath: readonly Digest[];
}

export interface AuditConsistencyVerification {
  oldSize: number;
  newSize: number;
  oldRoot: Digest;
  newRoot: Digest;
  auditPath: readonly Digest[];
}

function digestBytes(digest: Digest): Uint8Array {
  const match = DIGEST_PATTERN.exec(digest);
  if (match === null) throw new TypeError('Expected sha256:<lowercase-hex> digest');
  const hex = match[1]!;
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function concat(...values: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function largestPowerOfTwoLessThan(value: number): number {
  let power = 1;
  while (power * 2 < value) power *= 2;
  return power;
}

function validateSize(size: number, label: string): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer`);
  }
}

/** RFC 9162 section 2 Merkle tree over immutable audit-entry digests. */
export class Rfc9162MerkleTree {
  constructor(private readonly hasher: AuditHasher) {}

  async leafHash(entryDigest: Digest): Promise<Digest> {
    return this.hasher.sha256(concat(Uint8Array.of(0x00), digestBytes(entryDigest)));
  }

  async nodeHash(left: Digest, right: Digest): Promise<Digest> {
    return this.hasher.sha256(concat(
      Uint8Array.of(0x01),
      digestBytes(left),
      digestBytes(right),
    ));
  }

  async root(leaves: readonly Digest[]): Promise<Digest> {
    if (leaves.length === 0) return this.hasher.sha256(new Uint8Array());
    if (leaves.length === 1) return this.leafHash(leaves[0]!);
    const split = largestPowerOfTwoLessThan(leaves.length);
    const [left, right] = await Promise.all([
      this.root(leaves.slice(0, split)),
      this.root(leaves.slice(split)),
    ]);
    return this.nodeHash(left, right);
  }

  async inclusionProof(leaves: readonly Digest[], leafIndex: number): Promise<Digest[]> {
    validateSize(leafIndex, 'Leaf index');
    if (leaves.length === 0 || leafIndex >= leaves.length) {
      throw new RangeError('Leaf index must identify a leaf in the tree');
    }
    return this.buildInclusionProof(leaves, leafIndex);
  }

  private async buildInclusionProof(
    leaves: readonly Digest[],
    leafIndex: number,
  ): Promise<Digest[]> {
    if (leaves.length === 1) return [];
    const split = largestPowerOfTwoLessThan(leaves.length);
    if (leafIndex < split) {
      const [path, sibling] = await Promise.all([
        this.buildInclusionProof(leaves.slice(0, split), leafIndex),
        this.root(leaves.slice(split)),
      ]);
      return [...path, sibling];
    }
    const [path, sibling] = await Promise.all([
      this.buildInclusionProof(leaves.slice(split), leafIndex - split),
      this.root(leaves.slice(0, split)),
    ]);
    return [...path, sibling];
  }

  async verifyInclusion(input: AuditInclusionVerification): Promise<boolean> {
    try {
      validateSize(input.leafIndex, 'Leaf index');
      validateSize(input.treeSize, 'Tree size');
      if (input.treeSize === 0 || input.leafIndex >= input.treeSize) return false;

      let leafPosition = input.leafIndex;
      let lastNodePosition = input.treeSize - 1;
      let calculated = await this.leafHash(input.leaf);

      for (const sibling of input.auditPath) {
        if (lastNodePosition === 0) return false;
        if ((leafPosition & 1) === 1 || leafPosition === lastNodePosition) {
          calculated = await this.nodeHash(sibling, calculated);
          while ((leafPosition & 1) === 0 && leafPosition !== 0) {
            leafPosition = Math.floor(leafPosition / 2);
            lastNodePosition = Math.floor(lastNodePosition / 2);
          }
        } else {
          calculated = await this.nodeHash(calculated, sibling);
        }
        leafPosition = Math.floor(leafPosition / 2);
        lastNodePosition = Math.floor(lastNodePosition / 2);
      }
      return lastNodePosition === 0 && calculated === input.root;
    } catch {
      return false;
    }
  }

  async consistencyProof(leaves: readonly Digest[], oldSize: number): Promise<Digest[]> {
    validateSize(oldSize, 'Old tree size');
    if (oldSize === 0 || oldSize > leaves.length) {
      throw new RangeError('Old tree size must be between 1 and the new tree size');
    }
    if (oldSize === leaves.length) return [];
    return this.buildConsistencyProof(oldSize, leaves, true);
  }

  private async buildConsistencyProof(
    oldSize: number,
    leaves: readonly Digest[],
    completeSubtree: boolean,
  ): Promise<Digest[]> {
    if (oldSize === leaves.length) {
      return completeSubtree ? [] : [await this.root(leaves)];
    }
    const split = largestPowerOfTwoLessThan(leaves.length);
    if (oldSize <= split) {
      const [path, rightRoot] = await Promise.all([
        this.buildConsistencyProof(oldSize, leaves.slice(0, split), completeSubtree),
        this.root(leaves.slice(split)),
      ]);
      return [...path, rightRoot];
    }
    const [path, leftRoot] = await Promise.all([
      this.buildConsistencyProof(oldSize - split, leaves.slice(split), false),
      this.root(leaves.slice(0, split)),
    ]);
    return [...path, leftRoot];
  }

  async verifyConsistency(input: AuditConsistencyVerification): Promise<boolean> {
    try {
      validateSize(input.oldSize, 'Old tree size');
      validateSize(input.newSize, 'New tree size');
      if (input.oldSize === 0 || input.oldSize > input.newSize) return false;
      if (input.oldSize === input.newSize) {
        return input.auditPath.length === 0 && input.oldRoot === input.newRoot;
      }

      let oldNode = input.oldSize - 1;
      let newNode = input.newSize - 1;
      while ((oldNode & 1) === 1) {
        oldNode = Math.floor(oldNode / 2);
        newNode = Math.floor(newNode / 2);
      }

      let pathIndex = 0;
      let oldCalculated: Digest;
      let newCalculated: Digest;
      if (oldNode === 0) {
        oldCalculated = input.oldRoot;
        newCalculated = input.oldRoot;
      } else {
        const first = input.auditPath[pathIndex++];
        if (first === undefined) return false;
        oldCalculated = first;
        newCalculated = first;
      }

      for (; pathIndex < input.auditPath.length; pathIndex += 1) {
        if (newNode === 0) return false;
        const sibling = input.auditPath[pathIndex]!;
        if ((oldNode & 1) === 1 || oldNode === newNode) {
          oldCalculated = await this.nodeHash(sibling, oldCalculated);
          newCalculated = await this.nodeHash(sibling, newCalculated);
          while ((oldNode & 1) === 0 && oldNode !== 0) {
            oldNode = Math.floor(oldNode / 2);
            newNode = Math.floor(newNode / 2);
          }
        } else {
          newCalculated = await this.nodeHash(newCalculated, sibling);
        }
        oldNode = Math.floor(oldNode / 2);
        newNode = Math.floor(newNode / 2);
      }

      return newNode === 0 &&
        oldCalculated === input.oldRoot &&
        newCalculated === input.newRoot;
    } catch {
      return false;
    }
  }
}
