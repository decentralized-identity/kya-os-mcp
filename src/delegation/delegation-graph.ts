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
import { assertRegistrable, type StatusEntryRecords } from './status-entry-claim.js';
import { readsStatusEntryOwners, type StatusEntryOwners } from './status-entry-owner.js';

export { statusEntryKey } from './delegation-status-entry.js';

export interface DelegationNode {
  id: string;
  parentId: string | null;
  children: string[];
  issuerDid: string;
  subjectDid: string;
  /**
   * Reference to the node's status list entry. Revocation flips a status bit
   * only when it has the form `<statusListCredential>#<index>`; prefer
   * {@link credentialStatus}, which needs no parsing. The same rule holds as
   * for `credentialStatus`: it must name the entry the operator allocated for
   * this delegation.
   */
  credentialStatusId?: string;
  /**
   * The node's status list entry, which revoking the delegation sets and
   * restoring it clears. It must be an entry the operator allocated for this
   * delegation (`StatusList2021Manager.allocateStatusEntry`), and no other
   * delegation's. A credential states such an entry, but carrying one does
   * not make it the delegation's: whoever signs a re-delegation writes the
   * entry it carries, and can write another delegation's.
   */
  credentialStatus?: CredentialStatus;
  /**
   * Set when the delegation is revoked in the graph (SPEC.md §6.5 step 1).
   * Recorded independently of the status list bit, so revocation holds even
   * for a delegation that has no status list entry.
   */
  revoked?: boolean;
}

export interface DelegationGraphStorageProvider {
  getNode(delegationId: string): Promise<DelegationNode | null>;
  setNode(node: DelegationNode): Promise<void>;
  getChildren(delegationId: string): Promise<DelegationNode[]>;
  getChain(delegationId: string): Promise<DelegationNode[]>;
  getDescendants(delegationId: string): Promise<DelegationNode[]>;
  deleteNode(delegationId: string): Promise<void>;
}

/** Optional transaction seam for providers that can link parent and child atomically. */
export interface AtomicDelegationGraphStorageProvider extends DelegationGraphStorageProvider {
  /**
   * Insert `node` and link it under its parent in one step. When the id is
   * already stored, a node identical in every registered field is a no-op,
   * and any other SHOULD be rejected: overwriting would drop the stored node's
   * revocation state and children. `DelegationGraphManager` checks first, but
   * only the provider can close the race between that check and the write.
   * A provider that also implements {@link StatusEntryIndexedGraphStorageProvider}
   * SHOULD likewise reject a new node whose {@link statusEntryKey} another
   * stored node has, for the same reason.
   */
  registerNodeAtomic(node: DelegationNode): Promise<void>;
}

/**
 * Optional, stronger contract for providers that can find the nodes
 * registered with a status list entry. With it, `registerDelegation` refuses an
 * entry another delegation is registered with, and `CascadingRevocationManager`
 * refuses to set or clear one that belongs to a delegation outside what it
 * revokes or restores, even for entries allocated with no `delegationId`.
 */
export interface StatusEntryIndexedGraphStorageProvider extends DelegationGraphStorageProvider {
  /**
   * The ids of every stored node whose {@link statusEntryKey} is `entryKey`,
   * in any order, or none. Index each node by `statusEntryKey(node)` as it is
   * stored, as `MemoryDelegationGraphStorage` does.
   */
  getNodeIdsByStatusEntry(entryKey: string): Promise<string[]>;
}

/** Options of {@link DelegationGraphManager}. */
export interface DelegationGraphOptions {
  /**
   * The record of the delegation each status list entry was allocated to:
   * the `StatusList2021Manager` that allocates them. With it,
   * `registerDelegation` refuses an entry allocated to another delegation,
   * even before that delegation is registered.
   */
  statusEntryOwners?: StatusEntryOwners;
}

function supportsAtomicRegistration(
  storage: DelegationGraphStorageProvider,
): storage is AtomicDelegationGraphStorageProvider {
  return 'registerNodeAtomic' in storage &&
    typeof storage.registerNodeAtomic === 'function';
}

function supportsStatusEntryLookup(
  storage: DelegationGraphStorageProvider,
): storage is StatusEntryIndexedGraphStorageProvider {
  return 'getNodeIdsByStatusEntry' in storage &&
    typeof storage.getNodeIdsByStatusEntry === 'function';
}

export class DelegationGraphManager {
  private readonly entryRecords: StatusEntryRecords;

  /**
   * @param options.statusEntryOwners - The `StatusList2021Manager` that
   *   allocates the graph's entries, so registration can refuse an entry
   *   allocated to another delegation. A value without `getStatusEntryOwner`
   *   throws a `TypeError`.
   */
  constructor(
    private storage: DelegationGraphStorageProvider,
    options: DelegationGraphOptions = {},
  ) {
    const owners = options.statusEntryOwners;
    if (owners !== undefined && !readsStatusEntryOwners(owners)) {
      throw new TypeError(
        'DelegationGraphManager was given statusEntryOwners without a getStatusEntryOwner method: pass the ' +
          'StatusList2021Manager that allocates the entries',
      );
    }
    this.entryRecords = { owners, graph: this };
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
   * `StatusList2021Manager.allocateStatusEntry`. Never pass the entry a
   * submitted credential carries unless it is that entry: whoever signs a
   * re-delegation writes it, and can write another delegation's. Registration
   * stores nothing, and throws a `RefusalError` of code
   * `delegation_malformed`, for an entry:
   *
   * - allocated to another delegation, when it was allocated with a
   *   `delegationId` and the graph was built with `statusEntryOwners`;
   * - another delegation is registered with, when it records no owner and the
   *   storage provider implements `getNodeIdsByStatusEntry`, as
   *   `MemoryDelegationGraphStorage` does;
   * - whose index no status list can hold.
   *
   * With neither record nothing can tell whose the entry is: it is registered
   * as given, and a warning is logged once per process.
   * `CascadingRevocationManager` applies the same records when it revokes and
   * restores.
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
    if (credentialStatus !== undefined) {
      await assertRegistrable(node.id, credentialStatus, this.entryRecords);
    }

    if (supportsAtomicRegistration(this.storage)) {
      await this.storage.registerNodeAtomic(node);
    } else {
      await this.storage.setNode(node);
      if (params.parentId) {
        try {
          await this.addChildToParent(params.parentId, params.id);
        } catch (error) {
          try {
            await this.storage.deleteNode(params.id);
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

    return node;
  }

  private async addChildToParent(parentId: string, childId: string): Promise<void> {
    const parent = await this.storage.getNode(parentId);
    if (!parent) {
      throw new Error(`Parent delegation not found: ${parentId}`);
    }

    if (!parent.children.includes(childId)) {
      parent.children.push(childId);
      await this.storage.setNode(parent);
    }
  }

  async getNode(delegationId: string): Promise<DelegationNode | null> {
    return this.storage.getNode(delegationId);
  }

  /**
   * The ids of the delegations registered with status list entry `entry`,
   * however each writes it, or `undefined` when the storage provider cannot
   * look them up: it does not implement `getNodeIdsByStatusEntry`. An index no
   * status list can hold throws.
   */
  async getDelegationIdsByStatusEntry(entry: CredentialStatus): Promise<string[] | undefined> {
    if (!supportsStatusEntryLookup(this.storage)) {
      return undefined;
    }
    return this.storage.getNodeIdsByStatusEntry(entryKey(canonicalStatusEntry(entry)));
  }

  /**
   * Record (or clear) the graph's revocation mark on one node, and report
   * whether the stored node now carries it. The node is read back because a
   * provider that persists a fixed set of node fields may silently drop
   * `revoked`. Descendants are left to the caller; cascading revocation walks
   * the subtree itself.
   */
  async setRevoked(delegationId: string, revoked: boolean): Promise<boolean> {
    const node = await this.storage.getNode(delegationId);
    if (!node) {
      throw new Error(`Delegation not found: ${delegationId}`);
    }
    await this.storage.setNode({ ...node, revoked });
    const stored = await this.storage.getNode(delegationId);
    return (stored?.revoked ?? false) === revoked;
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

  async validateChain(delegationId: string): Promise<{ valid: boolean; reason?: string }> {
    const chain = await this.getChain(delegationId);

    if (chain.length === 0) {
      return { valid: false, reason: 'Delegation not found' };
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

      if (child.parentId !== parent.id) {
        return {
          valid: false,
          reason: `Invalid chain: ${child.id} parentId=${child.parentId} but actual parent is ${parent.id}`,
        };
      }
    }

    return { valid: true };
  }

  async removeDelegation(delegationId: string): Promise<void> {
    const node = await this.storage.getNode(delegationId);
    if (!node) return;

    if (node.parentId) {
      const parent = await this.storage.getNode(node.parentId);
      if (parent) {
        parent.children = parent.children.filter((id) => id !== delegationId);
        await this.storage.setNode(parent);
      }
    }

    await this.storage.deleteNode(delegationId);
  }
}

export function createDelegationGraph(
  storage: DelegationGraphStorageProvider,
  options?: DelegationGraphOptions,
): DelegationGraphManager {
  return new DelegationGraphManager(storage, options);
}
