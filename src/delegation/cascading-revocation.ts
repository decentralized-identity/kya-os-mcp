/**
 * Cascading Revocation Manager
 *
 * Implements cascading revocation per Python POC design.
 * When a parent delegation is revoked, all children are automatically revoked.
 *
 * Related Spec: KYA-OS §4.4, Delegation Chains
 */

import { DelegationGraphManager, type DelegationNode } from './delegation-graph.js';
import { nodeStatusEntry } from './delegation-status-entry.js';
import {
  assertRestorable,
  entriesLeftUnset,
  entryLeftUnset,
  unsetEntryClause,
  type StatusEntryRecords,
  type UnsetEntry,
} from './status-entry-claim.js';
import { readsStatusEntryOwners } from './status-entry-owner.js';
import { StatusList2021Manager } from './statuslist-manager.js';
import { readRevoked, unreadableStatusReason } from '../utils/revocation-answer.js';

export interface RevocationEvent {
  delegationId: string;
  isRoot: boolean;
  parentId?: string;
  timestamp: number;
  reason?: string;
}

export type RevocationHook = (event: RevocationEvent) => Promise<void> | void;

export interface CascadingRevocationOptions {
  reason?: string;
  onRevoke?: RevocationHook;
  maxDepth?: number;
  dryRun?: boolean;
}

/**
 * Revokes a delegation and its subtree, in the graph and on the status list, and restores one.
 *
 * Each status bit belongs to the delegations whose entry it is: the one the status list manager
 * allocated it to, or, when it recorded none, those the graph has registered with it. A revocation
 * sets a bit only when each of them lies in the subtree it revokes, and a restore clears one only
 * when it belongs to no other delegation, so neither ever changes the status of a delegation it was
 * not asked to change (`./status-entry-claim.ts`).
 */
export class CascadingRevocationManager {
  private readonly entryRecords: StatusEntryRecords;

  constructor(
    private graph: DelegationGraphManager,
    private statusList: StatusList2021Manager
  ) {
    // A status list a host wraps or stubs may record no owners; the graph's registrations then say.
    this.entryRecords = { owners: readsStatusEntryOwners(statusList) ? statusList : undefined, graph };
  }

  /**
   * Revoke `delegationId` and every delegation below it: each is marked revoked in the graph, and
   * the status bit of each is set. A bit that also belongs to a delegation outside the subtree is
   * left unchanged, since setting it would revoke that delegation too: once the whole subtree is
   * revoked, this throws a `RefusalError` of code `delegation_malformed` that names each such
   * delegation and its entry. Each is still revoked in the graph, which `isRevoked` reads, but not
   * on the published list.
   */
  async revokeDelegation(
    delegationId: string,
    options: CascadingRevocationOptions = {}
  ): Promise<RevocationEvent[]> {
    const maxDepth = options.maxDepth || 100;
    const events: RevocationEvent[] = [];

    const targetNode = await this.graph.getNode(delegationId);
    if (!targetNode) {
      throw new Error(`Delegation not found: ${delegationId}`);
    }

    const depth = await this.graph.getDepth(delegationId);
    if (depth > maxDepth) {
      throw new Error(`Delegation depth ${depth} exceeds maximum ${maxDepth}`);
    }

    const unset: UnsetEntry[] = [];
    const rootEvent = await this.revokeNode(
      targetNode,
      true,
      unset,
      options.reason,
      options.dryRun
    );
    events.push(rootEvent);

    if (options.onRevoke) {
      await options.onRevoke(rootEvent);
    }

    const descendants = await this.graph.getDescendants(delegationId);

    for (const descendant of descendants) {
      const event = await this.revokeNode(
        descendant,
        false,
        unset,
        `Cascaded from ${delegationId}`,
        options.dryRun,
        delegationId
      );
      events.push(event);

      if (options.onRevoke) {
        await options.onRevoke(event);
      }
    }

    const leftUnset = entriesLeftUnset(unset);
    if (leftUnset) {
      throw leftUnset;
    }
    return events;
  }

  /**
   * Revoke one node of the subtree, adding to `unset` its entry when that is left unchanged.
   * `parentId` is the delegation the revocation was asked for, for every node below it.
   */
  private async revokeNode(
    node: DelegationNode,
    isRoot: boolean,
    unset: UnsetEntry[],
    reason?: string,
    dryRun?: boolean,
    parentId?: string
  ): Promise<RevocationEvent> {
    const event: RevocationEvent = {
      delegationId: node.id,
      isRoot,
      parentId,
      timestamp: Date.now(),
      reason,
    };

    if (dryRun) {
      return event;
    }

    // Mark the graph first (SPEC.md §6.5 step 1): it holds even when the node
    // has no status list entry to flip (no status id, or one such as
    // urn:uuid:… that names no list and index), or when publishing the bit
    // below fails.
    const marked = await this.graph.setRevoked(node.id, true);

    const credentialStatus = nodeStatusEntry(node);
    const leftUnset = credentialStatus
      ? await entryLeftUnset(node.id, parentId ?? node.id, credentialStatus, this.entryRecords)
      : undefined;
    // With no bit to flip, the mark is the only record. If the storage
    // provider dropped it, reporting success would leave the delegation live.
    if (!marked && (!credentialStatus || leftUnset)) {
      const entry = leftUnset ? unsetEntryClause(leftUnset) : 'it has no status list entry';
      throw new Error(
        `Revocation of delegation ${node.id} was not recorded: ${entry}, and the ` +
          `graph storage provider did not persist DelegationNode.revoked. A DelegationGraphStorageProvider ` +
          `must store the revoked field to revoke delegations without a status list entry.`
      );
    }
    if (leftUnset) {
      unset.push(leftUnset);
    } else if (credentialStatus) {
      await this.statusList.updateStatus(credentialStatus, true);
    }

    return event;
  }

  /**
   * Restore `delegationId` alone: its status bit is cleared, then its graph mark. Its subtree stays
   * revoked. A bit that belongs to another delegation too is never cleared, since that would restore
   * the other delegation: this throws a `RefusalError` of code `delegation_malformed` before
   * anything changes, and the delegation stays revoked.
   */
  async restoreDelegation(delegationId: string): Promise<RevocationEvent> {
    const node = await this.graph.getNode(delegationId);
    if (!node) {
      throw new Error(`Delegation not found: ${delegationId}`);
    }

    const event: RevocationEvent = {
      delegationId: node.id,
      isRoot: true,
      timestamp: Date.now(),
      reason: 'Restored',
    };

    // Clear the graph mark last: if clearing the status bit fails, the
    // delegation still reads as revoked.
    const credentialStatus = nodeStatusEntry(node);
    if (credentialStatus) {
      await assertRestorable(node.id, credentialStatus, this.entryRecords);
      await this.statusList.updateStatus(credentialStatus, false);
    }
    await this.graph.setRevoked(node.id, false);

    return event;
  }

  async isRevoked(delegationId: string): Promise<{
    revoked: boolean;
    reason?: string;
    revokedAncestor?: string;
  }> {
    // Walk root → target so ancestor revocation is detected before the
    // target's own (cascade-set) bit. getChain() already returns root-first order.
    // A node counts as revoked when the graph marks it or its status bit is
    // set; a node with no status list entry is read from the mark alone.
    // The status list's answer is read by the shared reader: only a literal
    // false is a clear bit. Any answer that is neither true nor false reads as
    // revoked, with a reason that says the status could not be read, and does
    // not throw, since reading it by its truthiness did not.
    const chain = await this.graph.getChain(delegationId);

    for (const node of chain) {
      const answer: unknown = node.revoked ? true : await this.statusAnswer(node);
      const bit = readRevoked(answer);
      if (bit !== false) {
        const revoked = node.id === delegationId ? 'Directly revoked' : 'Ancestor revoked';
        return {
          revoked: true,
          reason: bit === undefined ? unreadableStatusReason(answer) : revoked,
          revokedAncestor: node.id === delegationId ? undefined : node.id,
        };
      }
    }

    return { revoked: false };
  }

  /** What the status list answers for the node's entry, unread, or `false` for a node that has none. */
  private async statusAnswer(node: DelegationNode): Promise<unknown> {
    const credentialStatus = nodeStatusEntry(node);
    return credentialStatus ? this.statusList.checkStatus(credentialStatus) : false;
  }

  async getRevokedInSubtree(rootId: string): Promise<string[]> {
    const descendants = await this.graph.getDescendants(rootId);
    const revoked: string[] = [];

    const rootRevoked = await this.isRevoked(rootId);
    if (rootRevoked.revoked) {
      revoked.push(rootId);
    }

    for (const node of descendants) {
      const isRevoked = await this.isRevoked(node.id);
      if (isRevoked.revoked) {
        revoked.push(node.id);
      }
    }

    return revoked;
  }

  async validateDelegation(delegationId: string): Promise<{ valid: boolean; reason?: string }> {
    const revokedCheck = await this.isRevoked(delegationId);
    if (revokedCheck.revoked) {
      return {
        valid: false,
        reason: revokedCheck.revokedAncestor
          ? `Ancestor ${revokedCheck.revokedAncestor} is revoked`
          : 'Delegation is revoked',
      };
    }

    const chainValidation = await this.graph.validateChain(delegationId);
    if (!chainValidation.valid) {
      return chainValidation;
    }

    return { valid: true };
  }
}

export function createCascadingRevocationManager(
  graph: DelegationGraphManager,
  statusList: StatusList2021Manager
): CascadingRevocationManager {
  return new CascadingRevocationManager(graph, statusList);
}
