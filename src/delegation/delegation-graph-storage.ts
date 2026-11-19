/**
 * Delegation Graph Storage
 *
 * The contract a `DelegationGraphManager` keeps its nodes through, and the optional, stronger
 * contracts a provider may also implement, with how the manager tells it does.
 */

import type { CredentialStatus } from '../types/protocol.js';

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
  /**
   * Set on the record a removed delegation leaves when it read as revoked and had no status list
   * entry, so the graph held the only record of its revocation (`removeDelegation`): a revoked
   * root, unlinked from its parent, that keeps the id reading as revoked. It is never restored,
   * registered again, nor given children.
   */
  removed?: boolean;
}

/**
 * Where a `DelegationGraphManager` keeps its nodes. Each change the manager makes to a stored node
 * reads it and writes it back whole; every manager over one provider object takes its turn at a
 * node, so none loses another's change. A provider written to from more than one process should
 * implement {@link AtomicDelegationGraphStorageProvider} too.
 */
export interface DelegationGraphStorageProvider {
  getNode(delegationId: string): Promise<DelegationNode | null>;
  setNode(node: DelegationNode): Promise<void>;
  getChildren(delegationId: string): Promise<DelegationNode[]>;
  getChain(delegationId: string): Promise<DelegationNode[]>;
  getDescendants(delegationId: string): Promise<DelegationNode[]>;
  deleteNode(delegationId: string): Promise<void>;
}

/**
 * Optional transaction seam for providers that can link parent and child atomically. Without it the
 * manager links a child by writing back the whole parent it read, so a revocation of the parent
 * stored meanwhile by another process is lost; the first such link in a process warns once.
 */
export interface AtomicDelegationGraphStorageProvider extends DelegationGraphStorageProvider {
  /**
   * Insert `node` and link it under its parent in one step, changing nothing of the parent but
   * adding `node.id` to its `children`: writing back the rest of the parent as it was read would
   * lose a revocation of the parent stored in between. Reject, storing nothing, a node whose
   * parent is not stored, or is stored as `removed`: a record a removal left holds no children,
   * and `DelegationGraphManager` reads the parent again in its turn, but only the provider can
   * close the race with a removal by another process. When the id is
   * already stored, a node identical in every registered field is a no-op,
   * and any other SHOULD be rejected: overwriting would drop the stored node's
   * revocation state and children. `DelegationGraphManager` checks first, but
   * only the provider can close the race between that check and the write.
   */
  registerNodeAtomic(node: DelegationNode): Promise<void>;
}

/**
 * Optional, stronger contract for providers that can find the nodes
 * registered with a status list entry. A graph built without
 * `statusEntryOwners` needs it to refuse an entry another delegation is
 * registered with, to name the delegations a revocation revokes too when it
 * sets an entry they share, and to refuse a restore that would clear one.
 * A graph built with `statusEntryOwners` needs it only for entries whose owner
 * was never recorded.
 */
export interface StatusEntryIndexedGraphStorageProvider extends DelegationGraphStorageProvider {
  /**
   * The ids of every stored node whose {@link statusEntryKey} is `entryKey`,
   * in any order, or none. Index each node by `statusEntryKey(node)` as it is
   * stored, as `MemoryDelegationGraphStorage` does. A stored node for which
   * `statusEntryKey` throws, one stored before entries were checked whose
   * index no list can hold, sets no bit: leave it out of the index, and out of
   * every answer, rather than fail every lookup.
   */
  getNodeIdsByStatusEntry(entryKey: string): Promise<string[]>;
}

export function supportsAtomicRegistration(
  storage: DelegationGraphStorageProvider,
): storage is AtomicDelegationGraphStorageProvider {
  return 'registerNodeAtomic' in storage &&
    typeof storage.registerNodeAtomic === 'function';
}

export function supportsStatusEntryLookup(
  storage: DelegationGraphStorageProvider,
): storage is StatusEntryIndexedGraphStorageProvider {
  return 'getNodeIdsByStatusEntry' in storage &&
    typeof storage.getNodeIdsByStatusEntry === 'function';
}

