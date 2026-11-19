/**
 * Delegation Removal
 *
 * How a `DelegationGraphManager` removes a delegation from its graph: in the delegation's turn,
 * then its parent's, it retires the status list entry allocated to it, unlinks it from its parent
 * and deletes its node, or refuses, removing nothing. A delegation the graph alone records as
 * revoked leaves a revoked record of its id in place of its node, since a delegation the graph
 * does not hold reads as not revoked.
 */

import { describeValue } from '../utils/describe-value.js';
import type { DelegationGraphStorageProvider, DelegationNode } from './delegation-graph-storage.js';
import { readableStatusEntry } from './delegation-status-entry.js';
import { graphChainBreak } from './graph-chain.js';
import type { NodeTurns } from './graph-node-turns.js';
import type { StatusEntryOwners } from './status-entry-owner.js';

/** What a removal reads and writes: the graph's store, the turns at its nodes, and the entries' owners. */
export interface RemovalContext {
  readonly storage: DelegationGraphStorageProvider;
  readonly turns: NodeTurns;
  readonly owners: StatusEntryOwners | undefined;
}

/** Remove `delegationId`, as `DelegationGraphManager.removeDelegation` says. */
export async function removeDelegationNode(context: RemovalContext, delegationId: string): Promise<void> {
  const { storage, turns } = context;
  await turns.take(delegationId, 'removed', async () => {
    const node = await storage.getNode(delegationId);
    if (!node || node.removed === true) return;
    const refused = await removalRefusal(storage, node);
    if (refused !== undefined) {
      throw new Error(`Delegation ${delegationId} is not removed: ${refused}`);
    }
    const drop = (await revokedInGraphAlone(storage, node))
      ? () => storage.setNode(revokedRecordOf(node))
      : () => storage.deleteNode(delegationId);
    const parentId = node.parentId;
    if (!parentId) {
      await retireOwnedEntry(context.owners, node);
      await drop();
      return;
    }
    // In the parent's turn too, so the removal changes nothing unless it can unlink the node. The
    // node goes before its link: a parent that still names a child the store does not hold has
    // none, and a node whose deletion failed is still under its parent.
    await turns.take(parentId, `unlinked from ${describeValue(delegationId)}, which is so not removed`, async () => {
      await retireOwnedEntry(context.owners, node);
      await drop();
      const parent = await storage.getNode(parentId);
      if (parent) {
        parent.children = parent.children.filter((id) => id !== delegationId);
        await storage.setNode(parent);
      }
    });
  });
}

/**
 * Remove `delegationId` and every delegation under it, as `removeDelegation` with
 * `{ subtree: true }` says: children first, each as {@link removeDelegationNode} removes one.
 * Throws a {@link SubtreeRemovalError} once every other delegation of the subtree is removed when
 * any could not be.
 */
export async function removeDelegationSubtree(context: RemovalContext, delegationId: string): Promise<void> {
  const top = await context.storage.getNode(delegationId);
  if (!top) return;
  // Breadth first lists each delegation before those under it, so read backwards it lists them after.
  const nodes = [...(await context.storage.getDescendants(delegationId))].reverse();
  nodes.push(top);
  const outcome: SubtreeRemoval = { removed: [], notRemoved: [], kept: [] };
  const left = new Set<string>();
  for (const node of nodes) {
    if (node.children.some((child) => left.has(child))) {
      outcome.kept.push(node.id);
      left.add(node.id);
      continue;
    }
    try {
      await removeDelegationNode(context, node.id);
      outcome.removed.push(node.id);
    } catch (cause) {
      outcome.notRemoved.push({ delegationId: node.id, cause });
      left.add(node.id);
    }
  }
  if (outcome.notRemoved.length > 0) throw new SubtreeRemovalError(delegationId, outcome);
}

/** What a removal of a subtree did: what it removed, what it could not, and what it kept above those. */
interface SubtreeRemoval {
  readonly removed: string[];
  readonly notRemoved: { readonly delegationId: string; readonly cause: unknown }[];
  readonly kept: string[];
}

/**
 * Thrown by `removeDelegation` with `{ subtree: true }` when it could not remove every delegation
 * of the subtree. Each other delegation was removed, but none above one that was not, so every
 * delegation left still reads to a root: remove the subtree again.
 */
export class SubtreeRemovalError extends Error {
  /** The delegations removed, children first. */
  readonly removed: readonly string[];
  /** Each delegation whose removal threw, with what it threw. */
  readonly notRemoved: readonly { readonly delegationId: string; readonly cause: unknown }[];
  /** The delegations kept, not tried, since one under them was not removed. */
  readonly kept: readonly string[];

  constructor(delegationId: string, outcome: SubtreeRemoval) {
    const [first, ...more] = outcome.notRemoved;
    const others = more.length === 0 ? '' : more.length === 1 ? ', and one more was not' : `, and ${more.length} more were not`;
    super(
      `Delegation ${describeValue(delegationId)} and the delegations under it were not all removed: delegation ` +
        `${describeValue(first!.delegationId)} was not${others}, for the ${more.length === 0 ? 'reason' : 'reasons'} ` +
        'in notRemoved. Every delegation above one not removed is kept, so each one left reads to a root ' +
        `(${outcome.kept.length} kept, ${outcome.removed.length} removed). Remove delegation ` +
        `${describeValue(delegationId)} with { subtree: true } again`,
    );
    this.name = 'SubtreeRemovalError';
    this.removed = outcome.removed;
    this.notRemoved = outcome.notRemoved;
    this.kept = outcome.kept;
  }
}

/** Why `node` may not be removed, or `undefined` when it may. */
async function removalRefusal(storage: DelegationGraphStorageProvider, node: DelegationNode): Promise<string | undefined> {
  const children = await storage.getChildren(node.id);
  if (children.length > 0) {
    return (
      `delegations are registered under it (${children.map((child) => child.id).join(', ')}). Remove it with ` +
      '{ subtree: true }, which removes them first, or remove them first, since a delegation whose parent the ' +
      'graph does not hold cannot be read to a root'
    );
  }
  return undefined;
}

/**
 * Whether the graph holds the only record that `node` is revoked: it has no status list entry,
 * and it, or an ancestor, is marked revoked, or its chain does not read to a root, so it cannot be
 * told not to be.
 */
async function revokedInGraphAlone(storage: DelegationGraphStorageProvider, node: DelegationNode): Promise<boolean> {
  if (readableStatusEntry(node) !== undefined) return false;
  const chain = await storage.getChain(node.id);
  return graphChainBreak(chain, node.id) !== undefined || chain.some((link) => link.revoked === true);
}

/** The record a removed `node` leaves when the graph alone records its revocation: a revoked root. */
function revokedRecordOf(node: DelegationNode): DelegationNode {
  return {
    id: node.id,
    parentId: null,
    children: [],
    issuerDid: node.issuerDid,
    subjectDid: node.subjectDid,
    revoked: true,
    removed: true,
  };
}

/** Retire `node`'s entry when the graph reads owners and the entry was allocated to `node`. */
async function retireOwnedEntry(owners: StatusEntryOwners | undefined, node: DelegationNode): Promise<void> {
  const entry = owners === undefined ? undefined : readableStatusEntry(node);
  if (owners === undefined || entry === undefined) return;
  if ((await owners.getStatusEntryOwner(entry))?.delegationId === node.id) {
    await owners.retireStatusEntry(entry);
  }
}
