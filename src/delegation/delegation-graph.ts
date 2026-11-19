/**
 * Delegation Graph Manager
 *
 * Tracks parent-child relationships between delegation credentials.
 * Critical for cascading revocation per Delegation-Revocation.md.
 *
 * Related Spec: KYA-OS §4.4, Delegation Chains
 */

import type { CredentialStatus } from '../types/protocol.js';
import { registrationConflict } from './delegation-registration.js';
import { canonicalStatusEntry, entryKey, nodeStatusEntry } from './delegation-status-entry.js';
import {
  assertRegistrable,
  readClaim,
  type StatusEntryClaim,
  type StatusEntrySources,
} from './status-entry-claim.js';
import { readsStatusEntryOwners, type StatusEntryOwners } from './status-entry-owner.js';
import { describeValue } from '../utils/describe-value.js';
import { KeyedLock } from '../utils/keyed-lock.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import { graphChainBreak } from './graph-chain.js';
import { removeDelegationNode } from './delegation-removal.js';
import { nodeTurnsOf, type NodeTurns } from './graph-node-turns.js';
import {
  supportsAtomicRegistration,
  supportsStatusEntryLookup,
  type DelegationGraphStorageProvider,
  type DelegationNode,
} from './delegation-graph-storage.js';

export { statusEntryKey } from './delegation-status-entry.js';
export type { StatusEntryClaim } from './status-entry-claim.js';
export type {
  AtomicDelegationGraphStorageProvider,
  DelegationGraphStorageProvider,
  DelegationNode,
  StatusEntryIndexedGraphStorageProvider,
} from './delegation-graph-storage.js';

/** Where every copy of this package records that the warning about linking without `registerNodeAtomic` was given. */
const UNLINKED_STORE_WARNED = Symbol.for('@kya-os/mcp/delegation-graph-unlinked-store-warned');

/** Fixed words, so nothing a store or a caller holds is ever written into the log line. */
const UNLINKED_STORE_WARNING =
  '[kya-os] DelegationGraphManager linked a delegation under its parent through a graph storage provider ' +
  'without registerNodeAtomic, writing the whole parent back as it read it, so a revocation of the parent ' +
  'made meanwhile through another process is lost. Managers over one storage provider object in one ' +
  'process take turns; across processes, implement AtomicDelegationGraphStorageProvider ' +
  "(registerNodeAtomic) on the store, changing only the parent's children, as MemoryDelegationGraphStorage does.";

/** Options of {@link DelegationGraphManager}. */
export interface DelegationGraphOptions {
  /**
   * The record of the delegation each status list entry was allocated to:
   * the `StatusList2021Manager` that allocates the entries, with
   * `allocateStatusEntry(purpose, { delegationId })`, and that
   * `CascadingRevocationManager` sets and clears them on, which throws a
   * `TypeError` when given another. With it, the graph registers a delegation
   * only with an entry allocated to its id, and retires the entry when it
   * removes the delegation. Without it, the graph cannot tell whose an entry
   * is, and warns once (see `registerDelegation`).
   */
  statusEntryOwners?: StatusEntryOwners;
}

export class DelegationGraphManager {
  private readonly entrySources: StatusEntrySources;
  /**
   * Runs the registrations that carry one status list entry one at a time, by the entry's key, so
   * no two check and store that entry at once. Registrations with other entries run alongside.
   */
  private readonly registrations = new KeyedLock();
  /**
   * Runs the changes to one stored node one at a time, by the node's id: each reads the node and
   * writes it back whole, so two at once would lose one. Shared by every manager over the same
   * storage provider object, and each waits for its turn at most 10 seconds (`nodeTurnsOf`). A
   * change to a node and then to its parent takes the node's turn first, never the other way round.
   */
  private readonly nodeTurns: NodeTurns;

  /**
   * @param options.statusEntryOwners - The `StatusList2021Manager` that
   *   allocates the graph's entries, so the graph registers a delegation only
   *   with an entry allocated to it. A value without `getStatusEntryOwner`
   *   throws a `TypeError`.
   */
  constructor(
    private storage: DelegationGraphStorageProvider,
    options: DelegationGraphOptions = {},
  ) {
    this.nodeTurns = nodeTurnsOf(storage);
    const owners = options.statusEntryOwners;
    if (owners !== undefined && !readsStatusEntryOwners(owners)) {
      throw new TypeError(
        'DelegationGraphManager was given statusEntryOwners without getStatusEntryOwner and retireStatusEntry ' +
          'methods: pass the StatusList2021Manager that allocates the entries',
      );
    }
    this.entrySources = {
      owners,
      registered: async (entry) =>
        supportsStatusEntryLookup(storage)
          ? storage.getNodeIdsByStatusEntry(entryKey(canonicalStatusEntry(entry)))
          : undefined,
    };
  }

  /**
   * Register a delegation in the graph: a root when `parentId` is `null`, else
   * a child linked under its registered parent. Registering an id again is a
   * no-op that returns the stored node when every registered field matches,
   * and throws when any differs.
   *
   * `credentialStatus`, or a `credentialStatusId` of the form
   * `<statusListCredential>#<index>`, is the status list entry that revoking
   * the delegation sets and restoring it clears. It must be an entry the
   * operator allocated for this delegation with
   * `StatusList2021Manager.allocateStatusEntry(purpose, { delegationId })`,
   * `delegationId` being the `id` given here. Choose that id as the operator:
   * never read it, or the entry, from a submitted credential alone, since
   * whoever signs a re-delegation writes both.
   *
   * A graph built with `statusEntryOwners` registers a delegation only with an
   * entry allocated to its `id` and not retired. Any other, one allocated to
   * another delegation, without a `delegationId`, not allocated yet (an index
   * past the end of its list among them), of a list the manager never created,
   * or retired when its delegation was removed, is refused: nothing is stored,
   * and a `RefusalError` of code `delegation_malformed` is thrown, in words
   * that name no other delegation and do not say whether the entry is in use.
   * This holds across managers over one storage provider, since only the
   * entry's owner can pass it.
   *
   * A graph built without it cannot tell which delegation an entry was
   * allocated to, and logs a warning once per process. It refuses, in the same
   * words, an entry another registered delegation holds, when the storage
   * provider implements `getNodeIdsByStatusEntry`, as
   * `MemoryDelegationGraphStorage` does; so a child that carries its parent's
   * entry, one bit for a subtree, is refused. It cannot refuse an entry
   * allocated and not yet registered, nor the entry of a delegation since
   * removed with `removeDelegation`: wire `statusEntryOwners` to refuse both.
   *
   * Registrations that carry one entry run one at a time within this manager,
   * and those with other entries alongside them, so, without owners, two that
   * carry one entry are never both registered through one manager; through two
   * managers over one storage provider, they can be.
   * An index no status list can hold is refused in both modes. A graph built
   * without owners does not know a list's size: it registers an index past the
   * end of one, and cascading revocation reports that entry as left unchanged.
   */
  async registerDelegation(params: {
    id: string;
    parentId: string | null;
    issuerDid: string;
    subjectDid: string;
    credentialStatusId?: string;
    credentialStatus?: CredentialStatus;
  }): Promise<DelegationNode> {
    const node: DelegationNode = {
      id: params.id,
      parentId: params.parentId,
      children: [],
      issuerDid: params.issuerDid,
      subjectDid: params.subjectDid,
      credentialStatusId: params.credentialStatusId,
      ...(params.credentialStatus ? { credentialStatus: params.credentialStatus } : {}),
    };

    if (params.parentId === params.id) {
      throw new Error(`Delegation ${params.id} cannot be its own parent`);
    }

    if (params.parentId) {
      const parent = await this.storage.getNode(params.parentId);
      if (!parent) {
        throw new Error(`Parent delegation not found: ${params.parentId}`);
      }
    }

    // Registering an id again is a no-op when nothing registered changes, so
    // a retry is safe. Anything else would replace the stored node, losing its
    // revocation state and children or relinking it under its own descendant,
    // so it is refused.
    const existing = await this.storage.getNode(params.id);
    if (existing) {
      const conflict = registrationConflict(existing, node);
      if (conflict === undefined) {
        return existing;
      }
      throw new Error(
        `Delegation ${params.id} is already registered with a different ${conflict}`,
      );
    }

    const credentialStatus = nodeStatusEntry(node);
    if (credentialStatus === undefined) {
      await this.storeNode(node);
    } else {
      await this.registrations.run(entryKey(credentialStatus), async () => {
        await assertRegistrable(node.id, credentialStatus, this.entrySources);
        await this.storeNode(node);
      });
    }
    return node;
  }

  /**
   * The record of each entry's owner the graph reads: the `statusEntryOwners`
   * it was built with, or `undefined`.
   */
  get statusEntryOwners(): StatusEntryOwners | undefined {
    return this.entrySources.owners;
  }

  /**
   * Store a new node and link it under its parent: atomically when the provider can, and in the
   * parent's turn, so no other change to the parent through a manager of this store is lost.
   */
  private async storeNode(node: DelegationNode): Promise<void> {
    const parentId = node.parentId;
    if (!parentId) {
      await this.linkNode(node);
      return;
    }
    await this.nodeTurns.take(parentId, `given the child ${describeValue(node.id)}`, () => this.linkNode(node));
  }

  /** Store `node` and link it under its parent, which the caller holds the turn of. */
  private async linkNode(node: DelegationNode): Promise<void> {
    if (supportsAtomicRegistration(this.storage)) {
      await this.storage.registerNodeAtomic(node);
      return;
    }
    await this.storage.setNode(node);
    if (node.parentId) {
      try {
        await this.addChildToParent(node.parentId, node.id);
      } catch (error) {
        try {
          await this.storage.deleteNode(node.id);
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            'Delegation registration failed and its non-atomic rollback also failed',
            { cause: error },
          );
        }
        throw error;
      }
    }
  }

  private async addChildToParent(parentId: string, childId: string): Promise<void> {
    const parent = await this.storage.getNode(parentId);
    if (!parent) {
      throw new Error(`Parent delegation not found: ${parentId}`);
    }

    if (!parent.children.includes(childId)) {
      warnOncePerProcess(UNLINKED_STORE_WARNED, UNLINKED_STORE_WARNING);
      parent.children.push(childId);
      await this.storage.setNode(parent);
    }
  }

  async getNode(delegationId: string): Promise<DelegationNode | null> {
    return this.storage.getNode(delegationId);
  }

  /**
   * Whose status list entry `entry` is, as registration and
   * `CascadingRevocationManager` read it: the delegation it was allocated to,
   * when the graph was built with `statusEntryOwners` and an owner was
   * recorded; else the delegations registered with it, however each writes
   * it, when the storage provider implements `getNodeIdsByStatusEntry`; else
   * `undefined`. An index no status list can hold throws.
   */
  getStatusEntryClaim(entry: CredentialStatus): Promise<StatusEntryClaim | undefined> {
    return readClaim(canonicalStatusEntry(entry), this.entrySources);
  }

  /**
   * Record (or clear) the graph's revocation mark on one node, and report
   * whether the stored node now carries it. The node is read back because a
   * provider that persists a fixed set of node fields may silently drop
   * `revoked`. Descendants are left to the caller; cascading revocation walks
   * the subtree itself.
   */
  async setRevoked(delegationId: string, revoked: boolean): Promise<boolean> {
    const change = revoked ? 'marked revoked' : 'cleared of its revocation mark';
    return this.nodeTurns.take(delegationId, change, async () => {
      const node = await this.storage.getNode(delegationId);
      if (!node) {
        throw new Error(`Delegation not found: ${delegationId}`);
      }
      await this.storage.setNode({ ...node, revoked });
      const stored = await this.storage.getNode(delegationId);
      return (stored?.revoked ?? false) === revoked;
    });
  }

  async getChildren(delegationId: string): Promise<DelegationNode[]> {
    return this.storage.getChildren(delegationId);
  }

  async getDescendants(delegationId: string): Promise<DelegationNode[]> {
    return this.storage.getDescendants(delegationId);
  }

  async getChain(delegationId: string): Promise<DelegationNode[]> {
    return this.storage.getChain(delegationId);
  }

  async isAncestor(ancestorId: string, descendantId: string): Promise<boolean> {
    const chain = await this.getChain(descendantId);
    return chain.some((node) => node.id === ancestorId);
  }

  async getDepth(delegationId: string): Promise<number> {
    const chain = await this.getChain(delegationId);
    return chain.length - 1;
  }

  /**
   * Whether the graph holds a chain from a root to `delegationId` in which each delegation was
   * issued by the subject of its parent. A chain that stops at a node the graph does not hold, as
   * a replica that has not received it or a store that lost it reads, is invalid, as is one that
   * ends at another delegation or whose links do not follow each `parentId`.
   */
  async validateChain(delegationId: string): Promise<{ valid: boolean; reason?: string }> {
    const chain = await this.getChain(delegationId);

    if (chain.length === 0) {
      return { valid: false, reason: 'Delegation not found' };
    }
    const broken = graphChainBreak(chain, delegationId);
    if (broken !== undefined) {
      return { valid: false, reason: `Invalid chain: ${broken}` };
    }

    for (let i = 1; i < chain.length; i++) {
      const parent = chain[i - 1]!;
      const child = chain[i]!;

      if (child.issuerDid !== parent.subjectDid) {
        return {
          valid: false,
          reason: `Invalid chain: ${child.id} issued by ${child.issuerDid} but parent ${parent.id} subject is ${parent.subjectDid}`,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Remove a delegation from the graph. In a graph built with
   * `statusEntryOwners`, the entry allocated to it is retired first, so no
   * delegation, under any id, is registered with it again; a node that
   * carries an entry allocated to another retires nothing.
   *
   * Throws, removing nothing, for a delegation with delegations registered
   * under it, which would be left under a parent the graph does not hold, so
   * that none could be read to a root: remove them first. Throws too for a
   * delegation revoked in the graph that has no status list entry, since the
   * graph holds the only record of its revocation and a delegation it does
   * not hold reads as not revoked: restore it first to remove it.
   */
  async removeDelegation(delegationId: string): Promise<void> {
    await removeDelegationNode(
      { storage: this.storage, turns: this.nodeTurns, owners: this.entrySources.owners },
      delegationId,
    );
  }
}

export function createDelegationGraph(
  storage: DelegationGraphStorageProvider,
  options?: DelegationGraphOptions,
): DelegationGraphManager {
  return new DelegationGraphManager(storage, options);
}
