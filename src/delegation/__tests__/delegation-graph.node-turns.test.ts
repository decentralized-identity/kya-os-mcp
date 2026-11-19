/**
 * Every change the graph makes to a stored node reads the node and writes it back whole: linking a
 * child under its parent, marking a revocation, unlinking a removed child. Two such changes to one
 * node at once lose one of them: a registration under a delegation being revoked wrote the parent
 * back as it read it, without the revocation's mark, so the revocation, reported done, was gone.
 * So every manager over one storage provider object takes its turn at a node, and a manager that
 * links a child through a store without `registerNodeAtomic`, which another process may write to
 * meanwhile, warns once per process.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import {
  DelegationGraphManager,
  type DelegationGraphStorageProvider,
  type DelegationNode,
} from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';

const WARNED = Symbol.for('@kya-os/mcp/delegation-graph-unlinked-store-warned');
const registry = globalThis as { [WARNED]?: true };
let previous: true | undefined;

beforeEach(() => {
  previous = registry[WARNED];
  delete registry[WARNED];
});

afterEach(() => {
  if (previous === undefined) delete registry[WARNED];
  else registry[WARNED] = previous;
  vi.restoreAllMocks();
});

/** A key-value store: rows read as copies and written whole, with a gate that holds back the writes `hold` picks. */
class RowStore implements DelegationGraphStorageProvider {
  private readonly rows = new Map<string, string>();
  hold: ((node: DelegationNode) => boolean) | undefined;
  private readonly held: (() => void)[] = [];
  private reached!: () => void;
  readonly holding = new Promise<void>((resolve) => {
    this.reached = resolve;
  });

  release(): void {
    this.hold = undefined;
    for (const write of this.held.splice(0)) write();
  }

  async getNode(id: string): Promise<DelegationNode | null> {
    const row = this.rows.get(id);
    return row === undefined ? null : (JSON.parse(row) as DelegationNode);
  }

  async setNode(node: DelegationNode): Promise<void> {
    const row = JSON.stringify(node);
    if (this.hold?.(node)) {
      await new Promise<void>((resolve) => {
        this.held.push(resolve);
        this.reached();
      });
    }
    this.rows.set(node.id, row);
  }

  async getChildren(id: string): Promise<DelegationNode[]> {
    const children = await Promise.all(((await this.getNode(id))?.children ?? []).map((child) => this.getNode(child)));
    return children.filter((child): child is DelegationNode => child !== null);
  }

  async getChain(id: string): Promise<DelegationNode[]> {
    const chain: DelegationNode[] = [];
    for (let current: string | null = id; current; ) {
      const node: DelegationNode | null = await this.getNode(current);
      if (node === null) break;
      chain.unshift(node);
      current = node.parentId;
    }
    return chain;
  }

  async getDescendants(id: string): Promise<DelegationNode[]> {
    const found: DelegationNode[] = [];
    for (const queue = [id]; queue.length > 0; ) {
      for (const child of await this.getChildren(queue.shift()!)) {
        found.push(child);
        queue.push(child.id);
      }
    }
    return found;
  }

  async deleteNode(id: string): Promise<void> {
    this.rows.delete(id);
  }
}

/** Long enough for a change that does not wait its turn to be made in full. */
const aMoment = () => new Promise((resolve) => setTimeout(resolve, 20));

const AGENT = { id: 'agent', parentId: null, issuerDid: 'did:web:operator.example', subjectDid: 'did:web:agent.example' };
const CHILD = { id: 'agent-child', parentId: 'agent', issuerDid: 'did:web:agent.example', subjectDid: 'did:web:mule.example' };

/** A graph over `storage` with the agent registered, and a cascade over a second manager of the same store. */
async function wired(storage: DelegationGraphStorageProvider) {
  const { manager } = await realStatusListManager();
  const registering = new DelegationGraphManager(storage);
  const revoking = new CascadingRevocationManager(new DelegationGraphManager(storage), manager);
  await registering.registerDelegation(AGENT);
  return { registering, revoking };
}

describe('DelegationGraphManager: every manager over one store takes its turn at a node', () => {
  it('keeps a revocation made while a re-delegation is linked under the revoked delegation', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const store = new RowStore();
    const { registering, revoking } = await wired(store);

    store.hold = (node) => node.id === 'agent' && node.children.includes('agent-child');
    const registered = registering.registerDelegation(CHILD);
    await store.holding;
    const revoked = revoking.revokeDelegation('agent', { reason: 'compromised' });
    await aMoment();
    store.release();
    await registered;
    // The revocation waited for the link, so it cascades to the new child too.
    expect((await revoked).map((event) => event.delegationId)).toEqual(['agent', 'agent-child']);

    expect(await revoking.isRevoked('agent')).toMatchObject({ revoked: true });
    expect(await revoking.isRevoked('agent-child')).toMatchObject({ revoked: true });
    expect((await store.getNode('agent'))?.children).toEqual(['agent-child']);
  });

  it('keeps a child linked while its parent is marked revoked through another manager', async () => {
    const storage = new MemoryDelegationGraphStorage();
    const { registering, revoking } = await wired(storage);
    const setNode = storage.setNode.bind(storage);
    let linking: Promise<unknown> | undefined;
    // The revocation's write of the agent waits until a registration under the agent has begun.
    vi.spyOn(storage, 'setNode').mockImplementation(async (node) => {
      if (node.id === 'agent' && node.revoked === true && linking === undefined) {
        linking = registering.registerDelegation(CHILD);
        await aMoment();
      }
      await setNode(node);
    });
    await revoking.revokeDelegation('agent');
    await linking;

    expect(await storage.getNode('agent')).toMatchObject({ revoked: true, children: ['agent-child'] });
    expect(await revoking.isRevoked('agent-child')).toMatchObject({ revoked: true, revokedAncestor: 'agent' });
  });

  it('does not remove a delegation while a child is linked under it', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const store = new RowStore();
    const { registering } = await wired(store);
    store.hold = (node) => node.id === 'agent' && node.children.includes('agent-child');
    const registered = registering.registerDelegation(CHILD);
    await store.holding;
    const removed = new DelegationGraphManager(store).removeDelegation('agent');
    await aMoment();
    store.release();
    await registered;

    await expect(removed).rejects.toThrow('Delegation agent is not removed: delegations are registered under it (agent-child)');
    expect(await store.getNode('agent')).toMatchObject({ children: ['agent-child'] });
  });
});

describe('DelegationGraphManager: a store without registerNodeAtomic', () => {
  it('warns once per process, when it first links a child, that another process can lose a revocation', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const store = new RowStore();
    const { registering } = await wired(store);
    expect(warn).not.toHaveBeenCalled();

    await registering.registerDelegation(CHILD);
    await registering.registerDelegation({ ...CHILD, id: 'second-child' });
    expect(warn.mock.calls).toEqual([
      [
        '[kya-os] DelegationGraphManager linked a delegation under its parent through a graph storage provider ' +
          'without registerNodeAtomic, writing the whole parent back as it read it, so a revocation of the parent ' +
          'made meanwhile through another process is lost. Managers over one storage provider object in one ' +
          'process take turns; across processes, implement AtomicDelegationGraphStorageProvider ' +
          "(registerNodeAtomic) on the store, changing only the parent's children, as MemoryDelegationGraphStorage does.",
      ],
    ]);
  });

  it('does not warn over a store with registerNodeAtomic', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { registering } = await wired(new MemoryDelegationGraphStorage());
    await registering.registerDelegation(CHILD);
    expect(warn).not.toHaveBeenCalled();
  });
});
