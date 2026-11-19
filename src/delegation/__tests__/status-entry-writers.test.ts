/**
 * Whose each status list entry is, while several `StatusList2021Manager`s write one store through
 * the conditional write, as the replicas of one issuing service do. An allocation records its
 * entry's owner only once the list holds the entry's index, so an allocation that fails, whether
 * its list write was refused every time, could not reach the store, or its owner record could not
 * be written, leaves an index no delegation can be registered with. Owner records sit apart from
 * the lists, so no list write, however often it was tried again, brings a retired entry back, and
 * a revocation or restoration through one replica is never lost to another's write.
 */
import { describe, expect, it } from 'vitest';
import type { CredentialStatus, StatusList2021Credential } from '../../types/protocol.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager } from '../delegation-graph.js';
import type { StatusEntryOwner } from '../status-entry-owner.js';
import { isStatusListWriteConflict, type StatusList2021Manager } from '../statuslist-manager.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import {
  ENTRY,
  LIST,
  REGISTRATION_REFUSED,
  REMOVED_WHILE_REVOKED,
  leftUnchanged,
  refusal,
  rejectionMessage,
} from './helpers/status-entry-operator.js';
import { proofOver, replica, signedOverItself } from './helpers/status-list-writers.js';

/**
 * A memory store that logs each owner an allocation records and each conditional write it refused,
 * and can be made to refuse or fail the writes to come.
 */
class WatchedStore extends MemoryStatusListStorage {
  readonly ownerWrites: { entry: string; owner: StatusEntryOwner }[] = [];
  refusedWrites = 0;
  /** How many of the conditional writes to come are refused, as when another writer stores the list first each time. */
  refusing = 0;
  /** Thrown by the next conditional write, as by a store that cannot be reached. */
  nextWriteFailure: Error | undefined;
  /** Thrown by the next owner record written. */
  nextOwnerFailure: Error | undefined;

  override async setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean> {
    const failure = this.nextWriteFailure;
    this.nextWriteFailure = undefined;
    if (failure !== undefined) throw failure;
    const refused = this.refusing > 0;
    if (refused) this.refusing--;
    const stored = !refused && (await super.setStatusListIfMatch(statusListId, credential, etag));
    if (!stored) this.refusedWrites++;
    return stored;
  }

  override async setEntryOwnerIfAbsent(statusListId: string, index: number, owner: StatusEntryOwner): Promise<boolean> {
    const failure = this.nextOwnerFailure;
    this.nextOwnerFailure = undefined;
    if (failure !== undefined) throw failure;
    this.ownerWrites.push({ entry: `${statusListId}#${index}`, owner: { ...owner } });
    return super.setEntryOwnerIfAbsent(statusListId, index, owner);
  }
}

/** A signer that holds every signature until `release()`; `waiting` settles once `writers` are held. */
function heldSigner(writers: number) {
  let held = 0;
  let allWaiting!: () => void;
  const waiting = new Promise<void>((resolve) => {
    allWaiting = resolve;
  });
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  const sign = async (canonical: string) => {
    if (++held === writers) allWaiting();
    await released;
    return proofOver(canonical);
  };
  return { sign, waiting, release };
}

/** Entry `index` of the revocation list, as a credential that names it carries it. */
function entryAt(index: number): CredentialStatus {
  return {
    id: ENTRY(index),
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential: LIST,
  };
}

function params(id: string, credentialStatus: CredentialStatus, parentId: string | null = null) {
  return {
    id,
    parentId,
    issuerDid: parentId === null ? 'did:web:operator.example' : `did:web:${parentId}.example`,
    subjectDid: `did:web:${id}.example`,
    credentialStatus: { ...credentialStatus },
  };
}

/** A graph over `nodes` that reads the owners `manager` records. */
function wiredGraph(manager: StatusList2021Manager, nodes = new MemoryDelegationGraphStorage()): DelegationGraphManager {
  return new DelegationGraphManager(nodes, { statusEntryOwners: manager });
}

async function expectNoneRegisteredWith(graph: DelegationGraphManager, entry: CredentialStatus, ids: string[]) {
  for (const id of ids) {
    expect(await refusal(graph.registerDelegation(params(id, entry)))).toEqual({
      code: 'delegation_malformed',
      message: REGISTRATION_REFUSED(id),
    });
  }
}

const NO_WAIT = { sleep: async () => undefined };

describe('allocating entries with their owners over a conditional store', () => {
  it('gives each of five managers allocating on one new list at once its own index, with one owner record each', async () => {
    const storage = new WatchedStore();
    const { sign, release, waiting } = heldSigner(5);
    const ids = ['d0', 'd1', 'd2', 'd3', 'd4'];

    const allocations = Promise.all(
      ids.map((delegationId) => replica(storage, { sign }).allocateStatusEntry('revocation', { delegationId })),
    );
    // Every manager has read no list and is signing a new one: one creation is stored, and the
    // other four are refused and tried again over the list now stored.
    await waiting;
    release();
    const entries = await allocations;

    expect(storage.refusedWrites).toBe(4);
    expect(await storage.getStatusListVersionCount(LIST)).toBe(1);
    expect(new Set(entries.map((entry) => entry.id)).size).toBe(5);
    expect(storage.getIndexCount(LIST)).toBe(5);
    expect(storage.ownerWrites).toHaveLength(5);
    expect(new Map(storage.ownerWrites.map(({ entry, owner }) => [entry, owner]))).toEqual(
      new Map(entries.map((entry, i) => [entry.id, { delegationId: ids[i], retired: false }])),
    );

    const graph = wiredGraph(replica(storage));
    await expectNoneRegisteredWith(graph, entries[1]!, ['d0', 'd2']);
    for (const [i, entry] of entries.entries()) {
      await graph.registerDelegation(params(ids[i]!, entry));
    }
  });

  it('records no owner for an index whose list a conditional store refused every time, and registers none with it', async () => {
    const storage = new WatchedStore();
    storage.refusing = 3;
    const contended = replica(storage, { options: { maxWriteConflicts: 2, ...NO_WAIT } });

    const error = await contended.allocateStatusEntry('revocation', { delegationId: 'first' }).catch((e: unknown) => e);

    expect(isStatusListWriteConflict(error)).toBe(true);
    expect(storage.refusedWrites).toBe(3);
    expect(storage.ownerWrites).toEqual([]);
    expect(await storage.getStatusList(LIST)).toBeNull();

    const issuer = replica(storage);
    const next = await issuer.allocateStatusEntry('revocation', { delegationId: 'first' });
    expect(next.id).toBe(ENTRY(1));
    expect(storage.ownerWrites).toEqual([{ entry: ENTRY(1), owner: { delegationId: 'first', retired: false } }]);

    const graph = wiredGraph(issuer);
    await expectNoneRegisteredWith(graph, entryAt(0), ['first', 'other']);
    await graph.registerDelegation(params('first', next));
  });

  it('records no owner when the list write cannot reach the store', async () => {
    const storage = new WatchedStore();
    storage.nextWriteFailure = new Error('status store unreachable');

    await expect(replica(storage).allocateStatusEntry('revocation', { delegationId: 'first' })).rejects.toThrow(
      'status store unreachable',
    );

    expect(storage.ownerWrites).toEqual([]);
    await expectNoneRegisteredWith(wiredGraph(replica(storage)), entryAt(0), ['first', 'other']);
  });

  it('leaves an index no delegation can take when its owner record fails after the list was written', async () => {
    const storage = new WatchedStore();
    storage.nextOwnerFailure = new Error('owner records unreachable');
    const issuer = replica(storage);

    await expect(issuer.allocateStatusEntry('revocation', { delegationId: 'first' })).rejects.toThrow(
      'owner records unreachable',
    );

    expect(await storage.getStatusList(LIST)).not.toBeNull();
    expect(await storage.getEntryOwner(LIST, 0)).toBeNull();
    const graph = wiredGraph(issuer);
    await expectNoneRegisteredWith(graph, entryAt(0), ['first', 'other']);

    const next = await issuer.allocateStatusEntry('revocation', { delegationId: 'first' });
    expect(next.id).toBe(ENTRY(1));
    await graph.registerDelegation(params('first', next));
  });
});

describe('revoking, restoring and retiring entries through replicas of one store', () => {
  it('keeps a retired entry retired, and every revocation and restoration, when replicas write one list at once', async () => {
    const statusStore = new WatchedStore();
    const nodes = new MemoryDelegationGraphStorage();
    const issuer = replica(statusStore);
    const issuerGraph = wiredGraph(issuer, nodes);
    const entries = new Map<string, CredentialStatus>();
    for (const id of ['a', 'b', 'c']) {
      const entry = await issuer.allocateStatusEntry('revocation', { delegationId: id });
      entries.set(id, entry);
      await issuerGraph.registerDelegation(params(id, entry));
    }
    await new CascadingRevocationManager(issuerGraph, issuer).revokeDelegation('b');

    const { sign, release, waiting } = heldSigner(3);
    const replicas = [0, 1, 2].map(() => {
      const manager = replica(statusStore, { sign });
      return new CascadingRevocationManager(wiredGraph(manager, nodes), manager);
    });
    const writes = Promise.all([
      replicas[0]!.revokeDelegation('a'),
      replicas[1]!.restoreDelegation('b'),
      replicas[2]!.revokeDelegation('c'),
    ]);
    // Each replica has read the list and is signing its change when c is removed, retiring c's entry.
    await waiting;
    await issuerGraph.removeDelegation('c');
    release();
    await writes;

    expect(statusStore.refusedWrites).toBeGreaterThanOrEqual(2);
    const reader = replica(statusStore);
    const bits = Object.fromEntries(
      await Promise.all([...entries].map(async ([id, entry]) => [id, await reader.checkStatus(entry)])),
    );
    expect(bits).toEqual({ a: true, b: false, c: true });
    expect(await signedOverItself(statusStore, LIST)).toBe(true);
    expect(await reader.getStatusEntryOwner(entries.get('c')!)).toEqual({ delegationId: 'c', retired: true });
    const readerGraph = wiredGraph(reader, nodes);
    await expectNoneRegisteredWith(readerGraph, entries.get('c')!, ['other']);
    // c read as revoked when it was removed, so it left a revoked record that refuses its id.
    expect(await rejectionMessage(readerGraph.registerDelegation(params('c', entries.get('c')!)))).toBe(REMOVED_WHILE_REVOKED('c'));
  });

  it('revokes the rest of a subtree when one entry is refused every time, and a second call sets that entry', async () => {
    const storage = new WatchedStore();
    const manager = replica(storage, { options: { maxWriteConflicts: 1, ...NO_WAIT } });
    const graph = wiredGraph(manager);
    const entries = new Map<string, CredentialStatus>();
    for (const [id, parentId] of [['root', null], ['left', 'root'], ['right', 'root']] as const) {
      const entry = await manager.allocateStatusEntry('revocation', { delegationId: id });
      entries.set(id, entry);
      await graph.registerDelegation(params(id, entry, parentId));
    }
    const cascade = new CascadingRevocationManager(graph, manager);
    const bits = async () =>
      Object.fromEntries(await Promise.all([...entries].map(async ([id, entry]) => [id, await manager.checkStatus(entry)])));

    // The root's write is refused both times it is tried; the writes after it are stored.
    storage.refusing = 2;
    const error = await leftUnchanged(cascade.revokeDelegation('root'));

    expect(error.events.map((event) => event.delegationId)).toEqual(['root', 'left', 'right']);
    expect(error.unchanged).toEqual([
      expect.objectContaining({ delegationId: 'root', reason: 'status-list-error', credentialStatus: entries.get('root') }),
    ]);
    expect(isStatusListWriteConflict(error.unchanged[0]!.cause)).toBe(true);
    expect(await bits()).toEqual({ root: false, left: true, right: true });

    expect(await cascade.revokeDelegation('root')).toHaveLength(3);
    expect(await bits()).toEqual({ root: true, left: true, right: true });
  });
});
