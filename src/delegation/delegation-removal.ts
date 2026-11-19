/**
 * Delegation Removal
 *
 * How a `DelegationGraphManager` removes a delegation from its graph: in the delegation's turn,
 * then its parent's, it retires the status list entry allocated to it, unlinks it from its parent
 * and deletes its node, or refuses, removing nothing.
 */

import { describeValue } from '../utils/describe-value.js';
import type { DelegationGraphStorageProvider, DelegationNode } from './delegation-graph-storage.js';
import { readableStatusEntry } from './delegation-status-entry.js';
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
    if (!node) return;
    const refused = await removalRefusal(storage, node);
    if (refused !== undefined) {
      throw new Error(`Delegation ${delegationId} is not removed: ${refused}`);
    }
    const parentId = node.parentId;
    if (!parentId) {
      await retireOwnedEntry(context.owners, node);
      await storage.deleteNode(delegationId);
      return;
    }
    // In the parent's turn too, so the removal changes nothing unless it can unlink the node.
    await turns.take(parentId, `unlinked from ${describeValue(delegationId)}, which is so not removed`, async () => {
      await retireOwnedEntry(context.owners, node);
      const parent = await storage.getNode(parentId);
      if (parent) {
        parent.children = parent.children.filter((id) => id !== delegationId);
        await storage.setNode(parent);
      }
      await storage.deleteNode(delegationId);
    });
  });
}

/** Why `node` may not be removed, or `undefined` when it may. */
async function removalRefusal(storage: DelegationGraphStorageProvider, node: DelegationNode): Promise<string | undefined> {
  const children = await storage.getChildren(node.id);
  if (children.length > 0) {
    return (
      `delegations are registered under it (${children.map((child) => child.id).join(', ')}). Remove them first, ` +
      'since a delegation whose parent the graph does not hold cannot be read to a root'
    );
  }
  if (node.revoked === true && readableStatusEntry(node) === undefined) {
    return (
      'it is revoked, and has no status list entry, so the graph holds the only record of its revocation, ' +
      'and a delegation the graph does not hold reads as not revoked. Restore it first to remove it'
    );
  }
  return undefined;
}

/** Retire `node`'s entry when the graph reads owners and the entry was allocated to `node`. */
async function retireOwnedEntry(owners: StatusEntryOwners | undefined, node: DelegationNode): Promise<void> {
  const entry = owners === undefined ? undefined : readableStatusEntry(node);
  if (owners === undefined || entry === undefined) return;
  if ((await owners.getStatusEntryOwner(entry))?.delegationId === node.id) {
    await owners.retireStatusEntry(entry);
  }
}
