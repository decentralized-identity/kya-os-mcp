/**
 * Cascading Revocation Manager
 *
 * Implements cascading revocation per Python POC design.
 * When a parent delegation is revoked, all children are automatically revoked.
 *
 * Related Spec: KYA-OS §4.4, Delegation Chains
 */

import type { CredentialStatus } from '../types/protocol.js';
import { DelegationGraphManager, type DelegationNode } from './delegation-graph.js';
import { nodeStatusEntry } from './delegation-status-entry.js';
import { restoreRefusal, revocationDecision } from './status-entry-claim.js';
import {
  restoreLeftUnchanged,
  revocationLeftUnchanged,
  unchangedEntryClause,
  type UnchangedStatusEntry,
} from './status-entry-unchanged-error.js';
import { StatusList2021Manager } from './statuslist-manager.js';
import { RefusalError } from '../utils/refusal.js';
import { readRevoked, unreadableStatusReason } from '../utils/revocation-answer.js';

export {
  StatusEntryUnchangedError,
  type StatusEntryUnchangedReason,
  type UnchangedStatusEntry,
} from './status-entry-unchanged-error.js';

export interface RevocationEvent {
  delegationId: string;
  isRoot: boolean;
  parentId?: string;
  timestamp: number;
  reason?: string;
  /**
   * The delegations outside the revoked subtree that are registered with the
   * status list entry this revocation set, so it revoked them too on the
   * status list, though not in the graph. Present only when there are any,
   * which a graph that reads owners never allows for an entry whose owner was
   * recorded.
   */
  statusEntrySharedWith?: readonly string[];
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
 * Whose a status list entry is, it reads from the graph (`DelegationGraphManager.getStatusEntryClaim`),
 * so registration and revocation apply one record. With a graph built with `statusEntryOwners`, an
 * entry whose owner was recorded is set only by a revocation whose subtree holds that owner, and
 * cleared only by restoring that owner: revoking or restoring a delegation never changes the status
 * of a delegation outside what it revokes or restores. Any other entry, every entry with a graph
 * built without owners, is set by any revocation of a delegation that carries it, revoking too, the
 * safe way, any delegation outside the subtree registered with it (`statusEntrySharedWith`), and is
 * cleared only when no other delegation is registered with it. Such a graph cannot refuse an entry
 * allocated and not yet registered, nor a removed delegation's, so a delegation that carries one
 * can still revoke or restore that entry (`registerDelegation`).
 *
 * An entry left unchanged, and one the status list manager refuses, such as an entry of a list it
 * does not issue, is reported to the operator in a `StatusEntryUnchangedError`, never in a
 * `RefusalError`.
 */
export class CascadingRevocationManager {
  constructor(
    private graph: DelegationGraphManager,
    private statusList: StatusList2021Manager
  ) {}

  /**
   * Revoke `delegationId` and every delegation below it: each is marked revoked in the graph, and
   * its status list entry is set, unless it must be left unchanged (see the class). Once the whole
   * subtree is revoked, an entry left unchanged throws a `StatusEntryUnchangedError` that carries
   * the events of every delegation revoked and each entry left unchanged: those delegations are
   * revoked in the graph, which `isRevoked` reads, but not on the published list. A dry run changes
   * nothing, and returns or throws what the real run would, short of the status list manager's own
   * refusals.
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

    const unchanged: UnchangedStatusEntry[] = [];
    const rootEvent = await this.revokeNode(
      targetNode,
      delegationId,
      unchanged,
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
        delegationId,
        unchanged,
        `Cascaded from ${delegationId}`,
        options.dryRun
      );
      events.push(event);

      if (options.onRevoke) {
        await options.onRevoke(event);
      }
    }

    if (unchanged.length > 0) {
      throw revocationLeftUnchanged(delegationId, events, unchanged);
    }
    return events;
  }

  /**
   * Revoke one node of the subtree of `root`, the delegation the revocation was asked for, adding
   * to `unchanged` its entry when that is left unchanged. A dry run marks and sets nothing.
   */
  private async revokeNode(
    node: DelegationNode,
    root: string,
    unchanged: UnchangedStatusEntry[],
    reason?: string,
    dryRun?: boolean
  ): Promise<RevocationEvent> {
    const isRoot = node.id === root;
    const event: RevocationEvent = {
      delegationId: node.id,
      isRoot,
      parentId: isRoot ? undefined : root,
      timestamp: Date.now(),
      reason,
    };

    // Mark the graph first (SPEC.md §6.5 step 1): it holds even when the node
    // has no status list entry to flip (no status id, or one such as
    // urn:uuid:… that names no list and index), or when publishing the bit
    // below fails. A dry run marks nothing, and so needs no mark.
    const marked = dryRun ? true : await this.graph.setRevoked(node.id, true);

    const credentialStatus = nodeStatusEntry(node);
    // With no bit to flip, the mark is the only record. If the storage
    // provider dropped it, reporting success would leave the delegation live.
    if (credentialStatus === undefined) {
      if (!marked) throw notRecorded(node.id, 'it has no status list entry');
      return event;
    }

    const decision = await revocationDecision(node.id, root, credentialStatus, this.graph);
    if (decision.sharedWith !== undefined) {
      event.statusEntrySharedWith = decision.sharedWith;
    }
    const left: UnchangedStatusEntry | undefined =
      decision.unchanged !== undefined
        ? { delegationId: node.id, credentialStatus, reason: decision.unchanged }
        : dryRun
          ? undefined
          : await this.changeEntry(node.id, credentialStatus, true);
    if (left !== undefined) {
      if (!marked) throw notRecorded(node.id, unchangedEntryClause(left));
      unchanged.push(left);
    }

    return event;
  }

  /**
   * Set or clear `credentialStatus`, or say it was left unchanged: the status list manager refused
   * it, as it does an entry of a list it does not issue. Any other failure is thrown.
   */
  private async changeEntry(
    delegationId: string,
    credentialStatus: CredentialStatus,
    revoked: boolean
  ): Promise<UnchangedStatusEntry | undefined> {
    try {
      await this.statusList.updateStatus(credentialStatus, revoked);
      return undefined;
    } catch (error) {
      if (!(error instanceof RefusalError)) throw error;
      return { delegationId, credentialStatus, reason: 'refused-by-status-list', cause: error };
    }
  }

  /**
   * Restore `delegationId` alone: its status list entry is cleared, then its graph mark. Its
   * subtree stays revoked. An entry another delegation holds, by allocation or by registration, is
   * never cleared, since that would restore the other delegation: this throws a
   * `StatusEntryUnchangedError` before anything changes, and the delegation stays revoked, as it
   * does when the status list manager refuses the entry.
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
      const refused = await restoreRefusal(node.id, credentialStatus, this.graph);
      const left: UnchangedStatusEntry | undefined =
        refused !== undefined
          ? { delegationId: node.id, credentialStatus, reason: refused }
          : await this.changeEntry(node.id, credentialStatus, false);
      if (left !== undefined) {
        throw restoreLeftUnchanged(left);
      }
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

/** The error of a revocation the graph storage provider did not record, for a node `entry` says of. */
function notRecorded(delegationId: string, entry: string): Error {
  return new Error(
    `Revocation of delegation ${delegationId} was not recorded: ${entry}, and the ` +
      `graph storage provider did not persist DelegationNode.revoked. A DelegationGraphStorageProvider ` +
      `must store the revoked field to revoke delegations without a status list entry.`
  );
}

export function createCascadingRevocationManager(
  graph: DelegationGraphManager,
  statusList: StatusList2021Manager
): CascadingRevocationManager {
  return new CascadingRevocationManager(graph, statusList);
}
