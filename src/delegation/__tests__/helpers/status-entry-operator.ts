/**
 * An operator's status list, delegation graph and cascade, for the tests of whose a status list
 * entry is. A test names its setup: whether entries are allocated with their delegation and the
 * graph reads those owners, what the graph's storage provider can do, and whether the status list
 * storage reads a list's URL as the URL parser writes it.
 */
import { expect } from 'vitest';
import type { CredentialStatus } from '../../../types/protocol.js';
import { RefusalError } from '../../../utils/refusal.js';
import { statusListGzipCodec } from '../../../utils/statuslist-gzip.js';
import { CascadingRevocationManager } from '../../cascading-revocation.js';
import {
  DelegationGraphManager,
  type DelegationGraphStorageProvider,
  type StatusEntryIndexedGraphStorageProvider,
} from '../../delegation-graph.js';
import type { StatusEntryOwnerStorageProvider } from '../../status-entry-owner.js';
import { StatusEntryUnchangedError } from '../../status-entry-unchanged-error.js';
import { StatusList2021Manager } from '../../statuslist-manager.js';
import { MemoryDelegationGraphStorage } from '../../storage/memory-graph-storage.js';
import { MemoryStatusListStorage } from '../../storage/memory-statuslist-storage.js';

export const OPERATOR = 'did:web:operator.example';
export const LIST = 'https://status.example/revocation/v1';
export const ENTRY = (index: number): string => `${LIST}#${index}`;

/** The once-per-process warning a graph built without `statusEntryOwners` gives. */
export const UNWIRED_WARNED = Symbol.for('@kya-os/mcp/status-entry-owners-unwired-warned');

/** Forget that the warning was given, so a test sees whether its own setup gives it. */
export function forgetWarning(): void {
  delete (globalThis as { [key: symbol]: unknown })[UNWIRED_WARNED];
}

/** What `promise` rejects with. */
async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
}

/** The code and message of the `RefusalError` that `promise` rejects with. */
export async function refusal(promise: Promise<unknown>): Promise<{ code: string; message: string }> {
  const error = await rejection(promise);
  expect(error).toBeInstanceOf(RefusalError);
  const refused = error as RefusalError;
  return { code: refused.code, message: refused.message };
}

/** The `StatusEntryUnchangedError` that `promise` rejects with. */
export async function leftUnchanged(promise: Promise<unknown>): Promise<StatusEntryUnchangedError> {
  const error = await rejection(promise);
  expect(error).toBeInstanceOf(StatusEntryUnchangedError);
  expect(error).not.toBeInstanceOf(RefusalError);
  return error as StatusEntryUnchangedError;
}

/** The registration refusal, the same whether the entry is unallocated, another's or in use. */
export const REGISTRATION_REFUSED = (id: string): string =>
  `Delegation "${id}" cannot be registered with the status list entry it carries: a delegation must be ` +
  'registered with an entry allocated for it. Allocate one with allocateStatusEntry(purpose, { delegationId }), ' +
  'and register the delegation with that entry.';

/** A provider written to the base contract alone: no atomic registration, no lookup by status entry. */
export function baseContract(memory: MemoryDelegationGraphStorage): DelegationGraphStorageProvider {
  return {
    getNode: (id) => memory.getNode(id),
    setNode: (node) => memory.setNode(node),
    getChildren: (id) => memory.getChildren(id),
    getChain: (id) => memory.getChain(id),
    getDescendants: (id) => memory.getDescendants(id),
    deleteNode: (id) => memory.deleteNode(id),
  };
}

/** A provider that can look entries up, but registers a node in two writes, as a non-atomic store does. */
export function lookupOnly(memory: MemoryDelegationGraphStorage): StatusEntryIndexedGraphStorageProvider {
  return { ...baseContract(memory), getNodeIdsByStatusEntry: (key) => memory.getNodeIdsByStatusEntry(key) };
}

/** A status list store keyed by a list's URL as the URL parser writes it, as a store that normalises URLs is. */
export function normalising(memory: MemoryStatusListStorage): StatusEntryOwnerStorageProvider {
  const href = (id: string): string => new URL(id).href;
  return {
    getStatusList: (id) => memory.getStatusList(href(id)),
    setStatusList: (id, credential) => memory.setStatusList(href(id), credential),
    allocateIndex: (id) => memory.allocateIndex(href(id)),
    setEntryOwner: (id, index, delegationId) => memory.setEntryOwner(href(id), index, delegationId),
    getEntryOwner: (id, index) => memory.getEntryOwner(href(id), index),
  };
}

export function statusListManager(storage: StatusEntryOwnerStorageProvider = new MemoryStatusListStorage()): StatusList2021Manager {
  return new StatusList2021Manager(
    storage,
    { getDid: () => 'did:web:status.example', getKeyId: () => 'did:web:status.example#key-1' },
    async () => ({ type: 'Ed25519Signature2020', proofValue: 'z' }),
    statusListGzipCodec,
    statusListGzipCodec,
    { statusListBaseUrl: 'https://status.example', defaultListSize: 1024 },
  );
}

export interface OperatorSetup {
  /**
   * `wired`: each entry is allocated with its delegation, and the graph reads those owners.
   * `half-wired`: each entry is allocated with its delegation, but the graph is built without
   * `statusEntryOwners`. `none` (the default): entries are allocated with no delegation.
   */
  owners?: 'wired' | 'half-wired' | 'none';
  /** `memory` (the default), `lookup` for a non-atomic store with a lookup, `base` for neither. */
  store?: 'memory' | 'lookup' | 'base';
  /** Keep the status lists in a store that normalises their URLs. */
  normalising?: boolean;
}

export function operator(setup: OperatorSetup = {}) {
  const owners = setup.owners ?? 'none';
  const manager = statusListManager(setup.normalising ? normalising(new MemoryStatusListStorage()) : undefined);
  const memory = new MemoryDelegationGraphStorage();
  const storage = { memory, lookup: lookupOnly(memory), base: baseContract(memory) }[setup.store ?? 'memory'];
  const graph = new DelegationGraphManager(storage, owners === 'wired' ? { statusEntryOwners: manager } : {});
  /** A graph over the same nodes that checks nothing, as one built before entries were checked. */
  const before = new DelegationGraphManager(baseContract(memory));
  const cascade = new CascadingRevocationManager(graph, manager);
  const entries = new Map<string, CredentialStatus>();

  const params = (id: string, parentId: string | null, credentialStatus?: CredentialStatus) => ({
    id,
    parentId,
    issuerDid: parentId === null ? OPERATOR : `did:web:${parentId}.example`,
    subjectDid: `did:web:${id}.example`,
    ...(credentialStatus ? { credentialStatus } : {}),
  });
  const allocate = async (id: string): Promise<CredentialStatus> => {
    const entry = await manager.allocateStatusEntry('revocation', owners === 'none' ? undefined : { delegationId: id });
    entries.set(id, entry);
    return entry;
  };
  /** Allocate an entry for `id` and register `id` with it, as an honest operator does. */
  const issue = async (id: string, parentId: string | null = null) =>
    graph.registerDelegation(params(id, parentId, await allocate(id)));
  /** Register `id` carrying `entry`, the entry its issuer wrote. */
  const carrying = (id: string, parentId: string, entry: CredentialStatus) =>
    graph.registerDelegation(params(id, parentId, { ...entry }));
  /** Register `id` carrying `entry` through a graph that checks nothing, as a node stored before the check was. */
  const carryingBefore = (id: string, parentId: string, entry: CredentialStatus) =>
    before.registerDelegation(params(id, parentId, { ...entry }));
  /** Every allocated entry's bit, by the delegation it was allocated for. */
  const bits = async (): Promise<Record<string, boolean>> =>
    Object.fromEntries(await Promise.all([...entries].map(async ([id, entry]) => [id, await manager.checkStatus(entry)])));
  const entry = (id: string): CredentialStatus => entries.get(id)!;

  return { manager, memory, graph, cascade, entries, params, allocate, issue, carrying, carryingBefore, bits, entry };
}
