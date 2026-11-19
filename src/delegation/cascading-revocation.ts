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
import { cascadeClaims, restoreRefusal, revocationDecision, type ClaimReader } from './status-entry-claim.js';
import {
  restoreLeftUnchanged,
  revocationLeftUnchanged,
  revocationNotRecorded,
  type UnchangedStatusEntry,
  type UnrecordedRevocation,
} from './status-entry-unchanged-error.js';
import { StatusList2021Manager } from './statuslist-manager.js';
import { readRevoked, unreadableStatusReason } from '../utils/revocation-answer.js';
import { describeValue } from '../utils/describe-value.js';
import { RefusalError } from '../utils/refusal.js';
import { graphChainBreak } from './graph-chain.js';

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

/** What a revocation's walk of a subtree gathers: what it did, and what it could not. */
interface RevocationWalk {
  /** The delegation the revocation was asked for. */
  readonly root: string;
  readonly events: RevocationEvent[];
  readonly unchanged: UnchangedStatusEntry[];
  readonly unrecorded: UnrecordedRevocation[];
  readonly dryRun: boolean;
}

/** What revoking a node did with its entry: whether it set one, and the entry it left unchanged. */
interface EntryOutcome {
  readonly set: boolean;
  readonly unchanged?: UnchangedStatusEntry;
}

/**
 * Revokes a delegation and its subtree, in the graph and on the status list, and restores one.
 *
 * Whose a status list entry is, it reads from the owner the status list manager recorded, whether
 * or not the graph was built with `statusEntryOwners`, and otherwise from the graph's
 * registrations (`DelegationGraphManager.getStatusEntryClaim`). An entry whose owner was recorded
 * is set only by a revocation whose subtree holds a delegation registered under the owner's id, and
 * cleared only by restoring one. With a graph built with `statusEntryOwners`, whose
 * `removeDelegation` retires the entry, revoking or restoring a delegation so never changes the
 * status of a delegation outside what it revokes or restores. A graph built without it retires
 * nothing, so a delegation registered again under a removed one's id reads as the owner of the
 * removed one's entry, and restoring it clears that entry. An entry with no owner recorded is set by any revocation of a delegation
 * that carries it, revoking too, the safe way, any delegation outside the subtree registered with
 * it (`statusEntrySharedWith`), and is cleared only when no other delegation is registered with it.
 * A graph built without owners cannot refuse such an entry when it was allocated and not yet
 * registered, or belonged to a removed delegation (`registerDelegation`).
 *
 * A revocation never stops part way for an entry: every delegation of the subtree is marked in the
 * graph, and an entry it may not change, that cannot be read, or that the status list manager
 * could not change, is reported to the operator at the end in a `StatusEntryUnchangedError`, never
 * in a `RefusalError`.
 */
export class CascadingRevocationManager {
  private readonly claims: ClaimReader;

  /**
   * Throws a `TypeError` when `graph` was built with `statusEntryOwners` other than `statusList`,
   * since the graph would then register entries by one manager's records and the cascade change
   * them on another's lists.
   */
  constructor(
    private graph: DelegationGraphManager,
    private statusList: StatusList2021Manager
  ) {
    const graphOwners: unknown = graph.statusEntryOwners;
    if (graphOwners !== undefined && graphOwners !== statusList) {
      throw new TypeError(
        'CascadingRevocationManager was given a status list manager other than the one its delegation graph ' +
          'reads owners from (statusEntryOwners): pass the same StatusList2021Manager to both'
      );
    }
    this.claims = cascadeClaims(graph, statusList);
  }

  /**
   * Revoke `delegationId` and every delegation below it: each is marked revoked in the graph, and
   * its status list entry is set, unless it must be left unchanged (see the class). Once the whole
   * subtree is walked, an entry left unchanged throws a `StatusEntryUnchangedError` that carries
   * the events of every delegation revoked and each entry left unchanged: those delegations are
   * revoked in the graph, which `isRevoked` reads, but not on the published list. A delegation
   * whose mark the graph storage provider dropped, and whose entry was not set, is recorded
   * nowhere: that throws an `Error` naming it instead, also once the walk is done. A dry run
   * changes nothing, and returns or throws what the real run would, short of what only changing
   * the list shows.
   */
  async revokeDelegation(
    delegationId: string,
    options: CascadingRevocationOptions = {}
  ): Promise<RevocationEvent[]> {
    const maxDepth = options.maxDepth || 100;

    const targetNode = await this.graph.getNode(delegationId);
    if (!targetNode) {
      throw new Error(`Delegation not found: ${delegationId}`);
    }

    const depth = await this.graph.getDepth(delegationId);
    if (depth > maxDepth) {
      throw new Error(`Delegation depth ${depth} exceeds maximum ${maxDepth}`);
    }

    const walk: RevocationWalk = {
      root: delegationId,
      events: [],
      unchanged: [],
      unrecorded: [],
      dryRun: options.dryRun === true,
    };
    await this.revokeNode(targetNode, walk, options.reason, options.onRevoke);

    const descendants = await this.graph.getDescendants(delegationId);
    for (const descendant of descendants) {
      await this.revokeNode(descendant, walk, `Cascaded from ${delegationId}`, options.onRevoke);
    }

    const [firstUnrecorded, ...moreUnrecorded] = walk.unrecorded;
    if (firstUnrecorded !== undefined) {
      throw revocationNotRecorded(firstUnrecorded, moreUnrecorded.length);
    }
    if (walk.unchanged.length > 0) {
      throw revocationLeftUnchanged(delegationId, walk.events, walk.unchanged);
    }
    return walk.events;
  }

  /** Revoke one node of the walk's subtree, then tell `onRevoke`. A dry run marks and sets nothing. */
  private async revokeNode(
    node: DelegationNode,
    walk: RevocationWalk,
    reason: string | undefined,
    onRevoke: RevocationHook | undefined
  ): Promise<void> {
    const isRoot = node.id === walk.root;
    const event: RevocationEvent = {
      delegationId: node.id,
      isRoot,
      parentId: isRoot ? undefined : walk.root,
      timestamp: Date.now(),
      reason,
    };

    // Mark the graph first (SPEC.md §6.5 step 1): it holds even when the node
    // has no status list entry to flip (no status id, or one such as
    // urn:uuid:… that names no list and index), or when publishing the bit
    // below fails. A dry run marks nothing, and so needs no mark.
    const marked = walk.dryRun ? true : await this.graph.setRevoked(node.id, true);
    const outcome = await this.revokeEntry(node, walk, event);
    if (outcome.unchanged !== undefined) {
      walk.unchanged.push(outcome.unchanged);
    }
    // With no bit set, the mark is the only record. If the storage provider
    // dropped it, reporting success would leave the delegation live.
    if (!marked && !outcome.set) {
      walk.unrecorded.push({ delegationId: node.id, unchanged: outcome.unchanged });
    }

    walk.events.push(event);
    if (onRevoke) {
      await onRevoke(event);
    }
  }

  /**
   * Set `node`'s entry, as a revocation of the walk's root may, and say what was done. Nothing
   * about the entry stops the walk: an entry that cannot be read, may not be set, or that the
   * status list manager could not set, comes back as left unchanged.
   */
  private async revokeEntry(node: DelegationNode, walk: RevocationWalk, event: RevocationEvent): Promise<EntryOutcome> {
    let credentialStatus: CredentialStatus | undefined;
    try {
      credentialStatus = nodeStatusEntry(node);
    } catch (error) {
      return { set: false, unchanged: { delegationId: node.id, reason: 'unreadable-entry', cause: error } };
    }
    if (credentialStatus === undefined) {
      return { set: false };
    }

    const decision = await revocationDecision(node.id, walk.root, credentialStatus, this.claims);
    if (decision.sharedWith !== undefined) {
      event.statusEntrySharedWith = decision.sharedWith;
    }
    if (decision.unchanged !== undefined) {
      return { set: false, unchanged: { delegationId: node.id, credentialStatus, reason: decision.unchanged } };
    }
    if (walk.dryRun) {
      return { set: true };
    }
    const failed = await this.changeEntry(node.id, credentialStatus, true);
    return failed === undefined ? { set: true } : { set: false, unchanged: failed };
  }

  /**
   * Set or clear `credentialStatus`, or say it was left unchanged, with the status list manager's
   * error as its cause: the manager refused it, as it does an entry that names its list by another
   * spelling, or could not set it, as for an index past the end of its list or a list it never
   * created.
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
      return { delegationId, credentialStatus, reason: 'status-list-error', cause: error };
    }
  }

  /**
   * Restore `delegationId` alone: its status list entry is cleared, then its graph mark. Its
   * subtree stays revoked. An entry another delegation holds, by allocation or by registration, is
   * never cleared, since that would restore the other delegation: this throws a
   * `StatusEntryUnchangedError` before anything changes, and the delegation stays revoked, as it
   * does for an entry that cannot be read or that the status list manager could not clear.
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
    let credentialStatus: CredentialStatus | undefined;
    try {
      credentialStatus = nodeStatusEntry(node);
    } catch (error) {
      throw restoreLeftUnchanged({ delegationId: node.id, reason: 'unreadable-entry', cause: error });
    }
    if (credentialStatus) {
      const refused = await restoreRefusal(node.id, credentialStatus, this.claims);
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

  /**
   * Whether `delegationId`, or an ancestor of it, is revoked, read root first over the chain the
   * graph holds for it. A delegation the graph does not hold reads as not revoked: the chain walk
   * asks about every credential of a chain, a leaf never registered among them.
   *
   * @throws {RefusalError} of code `status_unavailable` when the chain the graph holds does not read
   *   from a root to `delegationId`, as one that stops at a node a replica has not received, or a
   *   store lost, does: it says nothing of an ancestor above the gap. `validateChain` says where.
   */
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
    if (graphChainBreak(chain, delegationId) !== undefined) {
      throw new RefusalError(
        'status_unavailable',
        `The delegation graph holds no chain from delegation ${describeValue(delegationId)} to a root, ` +
          'so whether it is revoked cannot be read'
      );
    }

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

  /**
   * Whether `delegationId` stands: the graph holds a valid chain to it (`validateChain`), read
   * first, and neither it nor an ancestor is revoked (`isRevoked`).
   */
  async validateDelegation(delegationId: string): Promise<{ valid: boolean; reason?: string }> {
    const chainValidation = await this.graph.validateChain(delegationId);
    if (!chainValidation.valid) {
      return chainValidation;
    }

    const revokedCheck = await this.isRevoked(delegationId);
    if (revokedCheck.revoked) {
      return {
        valid: false,
        reason: revokedCheck.revokedAncestor
          ? `Ancestor ${revokedCheck.revokedAncestor} is revoked`
          : 'Delegation is revoked',
      };
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
