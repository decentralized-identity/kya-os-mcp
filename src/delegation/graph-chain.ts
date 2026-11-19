/**
 * Graph Chain
 *
 * Whether the chain a delegation graph's storage provider returns for a delegation reads from a
 * root down to it without a gap. Only such a chain says whether the delegation is revoked: one
 * that stops at a node the store does not hold, as a replica that has not received it yet or a
 * store that lost it returns, says nothing of an ancestor above the gap.
 */

import type { DelegationNode } from './delegation-graph-storage.js';

/**
 * Whether `node` is a root. A `parentId` that is `null`, absent or empty names no parent, as
 * `registerDelegation` and `MemoryDelegationGraphStorage.getChain` read it.
 */
function isRoot(node: DelegationNode): boolean {
  return !node.parentId;
}

/**
 * Why `chain`, as a storage provider's `getChain(delegationId)` returned it, root first, is not a
 * chain from a root to `delegationId`, or `undefined` when it is: its last node is another
 * delegation, its first names a parent, as a chain that stops at a node the store does not hold
 * does, or a node's `parentId` is not the id of the node before it. Words that follow
 * `Invalid chain: `. An empty chain is one the graph does not hold, which this does not judge.
 */
export function graphChainBreak(chain: readonly DelegationNode[], delegationId: string): string | undefined {
  const first = chain[0];
  const last = chain[chain.length - 1];
  if (first === undefined || last === undefined) return undefined;
  if (last.id !== delegationId) {
    return `the chain the graph holds for ${delegationId} ends at ${last.id}`;
  }
  if (!isRoot(first)) {
    return `${first.id} names parent ${first.parentId}, which the graph does not hold`;
  }
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1]!;
    const child = chain[i]!;
    if (child.parentId !== parent.id) {
      return `${child.id} parentId=${child.parentId} but actual parent is ${parent.id}`;
    }
  }
  return undefined;
}
