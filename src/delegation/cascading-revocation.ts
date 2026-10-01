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
import { StatusList2021Manager } from './statuslist-manager.js';

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

export class CascadingRevocationManager {
  constructor(
    private graph: DelegationGraphManager,
    private statusList: StatusList2021Manager
  ) {}

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

    const rootEvent = await this.revokeNode(
      targetNode,
      true,
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
        `Cascaded from ${delegationId}`,
        options.dryRun,
        delegationId
      );
      events.push(event);

      if (options.onRevoke) {
        await options.onRevoke(event);
      }
    }

    return events;
  }

  private async revokeNode(
    node: DelegationNode,
    isRoot: boolean,
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
    await this.graph.setRevoked(node.id, true);

    const credentialStatus = nodeStatusEntry(node);
    if (credentialStatus) {
      await this.statusList.updateStatus(credentialStatus, true);
    }

    return event;
  }

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
    const chain = await this.graph.getChain(delegationId);

    for (const node of chain) {
      if (node.revoked || (await this.isStatusBitSet(node))) {
        return {
          revoked: true,
          reason: node.id === delegationId ? 'Directly revoked' : 'Ancestor revoked',
          revokedAncestor: node.id === delegationId ? undefined : node.id,
        };
      }
    }

    return { revoked: false };
  }

  private async isStatusBitSet(node: DelegationNode): Promise<boolean> {
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
