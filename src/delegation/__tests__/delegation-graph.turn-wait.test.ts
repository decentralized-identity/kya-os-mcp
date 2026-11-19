/**
 * A change to a graph node waits its turn behind another change to that node, and a store that
 * never finishes that other change, as a stuck connection does, would hold it forever: a
 * revocation would never land, and the delegation would stay valid with nobody told. So each
 * change waits at most 10 seconds, the longest one wait of a status list write, and then throws a
 * transient `deadline_exceeded` `RefusalError` naming the node, having changed nothing, so its
 * caller knows to make it again. A cascading revocation still walks its whole subtree first.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { isTransientRefusal } from '../../refusal-codes.js';
import { RefusalError } from '../../utils/refusal.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager, type DelegationNode } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';

const WAIT_MS = 10_000;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** A memory store whose writes of the nodes `hold` picks never finish, and which says when one starts. */
function stuckStore() {
  const storage = new MemoryDelegationGraphStorage();
  let reached!: () => void;
  const stuck = new Promise<void>((resolve) => {
    reached = resolve;
  });
  const hold = { node: (_node: DelegationNode) => false };
  const setNode = storage.setNode.bind(storage);
  vi.spyOn(storage, 'setNode').mockImplementation(async (node) => {
    if (!hold.node(node)) return setNode(node);
    reached();
    return new Promise<void>(() => undefined);
  });
  return { storage, hold, stuck };
}

/** A root, two delegations under it and one under the first, none with a status list entry. */
async function wired() {
  const { storage, hold, stuck } = stuckStore();
  const { manager } = await realStatusListManager();
  const graph = new DelegationGraphManager(storage);
  const revocation = new CascadingRevocationManager(new DelegationGraphManager(storage), manager);
  const links: [string, string | null, string, string][] = [
    ['root', null, 'did:web:user.example', 'did:web:a.example'],
    ['first', 'root', 'did:web:a.example', 'did:web:b.example'],
    ['second', 'root', 'did:web:a.example', 'did:web:c.example'],
    ['under-first', 'first', 'did:web:b.example', 'did:web:d.example'],
  ];
  for (const [id, parentId, issuerDid, subjectDid] of links) {
    await graph.registerDelegation({ id, parentId, issuerDid, subjectDid });
  }
  return { storage, hold, stuck, graph, revocation };
}

/** What `run` rejects with once `waits` waits are over, or a failure when it settles otherwise. */
async function afterTheWait(run: Promise<unknown>, waits = 1): Promise<unknown> {
  const settled = run.then(
    () => expect.unreachable('expected a rejection'),
    (error: unknown) => error,
  );
  await vi.advanceTimersByTimeAsync(WAIT_MS * waits);
  return settled;
}

const STALLED = (id: string, change: string) =>
  `Delegation "${id}" was not ${change}: another change to its node in the graph did not finish within ` +
  '10 seconds, so this change never got its turn and changed nothing. Make it again';

describe('DelegationGraphManager: a change waits at most 10 seconds for its turn at a node', () => {
  it('throws a transient error naming the node when the write before it never finishes, and changes nothing', async () => {
    const { hold, stuck, graph } = await wired();
    hold.node = (node) => node.id === 'second' && node.revoked === true;
    void graph.setRevoked('second', true);
    await stuck;

    const error = await afterTheWait(graph.setRevoked('second', false));
    expect(error).toBeInstanceOf(RefusalError);
    expect(error).toMatchObject({ code: 'deadline_exceeded', message: STALLED('second', 'cleared of its revocation mark') });
    expect(isTransientRefusal((error as RefusalError).code)).toBe(true);
  });

  it('refuses a link and a removal that never get their turn, storing nothing', async () => {
    const { storage, hold, stuck, graph } = await wired();
    hold.node = (node) => node.id === 'first' && node.revoked === true;
    void graph.setRevoked('first', true);
    await stuck;

    const link = graph.registerDelegation({ id: 'late', parentId: 'first', issuerDid: 'did:web:b.example', subjectDid: 'did:web:e.example' });
    expect(await afterTheWait(link)).toMatchObject({ code: 'deadline_exceeded', message: STALLED('first', 'given the child "late"') });
    expect(await storage.getNode('late')).toBeNull();

    const removal = graph.removeDelegation('under-first');
    expect(await afterTheWait(removal)).toMatchObject({
      code: 'deadline_exceeded',
      message: STALLED('first', 'unlinked from "under-first", which is so not removed'),
    });
    expect(await storage.getNode('under-first')).not.toBeNull();
  });
});

describe('CascadingRevocationManager.revokeDelegation: a node whose turn never comes', () => {
  it('marks the rest of the subtree, then throws a transient error naming the node it could not mark', async () => {
    const { hold, stuck, graph, revocation } = await wired();
    // Another change to `first` is stuck writing it.
    hold.node = (node) => node.id === 'first' && node.revoked === true;
    void graph.setRevoked('first', true);
    await stuck;

    const error = await afterTheWait(revocation.revokeDelegation('root'));
    expect(error).toBeInstanceOf(RefusalError);
    expect(error).toMatchObject({
      code: 'deadline_exceeded',
      message:
        'Revocation of delegation "root" did not land in full: delegation "first" was not marked revoked, since ' +
        'another change to its node in the graph did not finish within 10 seconds. Revoke delegation "root" again',
    });
    for (const id of ['root', 'second', 'under-first']) {
      expect(await revocation.isRevoked(id)).toMatchObject({ revoked: true });
    }
  });

  it('counts each other node it could not mark', async () => {
    const { hold, stuck, revocation, graph } = await wired();
    hold.node = (node) => ['first', 'second'].includes(node.id) && node.revoked === true;
    void graph.setRevoked('first', true);
    await stuck;
    void graph.setRevoked('second', true);

    // Each node waits its own turn, one after the other.
    const error = await afterTheWait(revocation.revokeDelegation('root'), 2);
    expect((error as Error).message).toBe(
      'Revocation of delegation "root" did not land in full: delegation "first" was not marked revoked, since ' +
        'another change to its node in the graph did not finish within 10 seconds. One more delegation of the ' +
        'subtree was not marked either. Revoke delegation "root" again',
    );
  });

  it('counts every other node it could not mark', async () => {
    const { hold, stuck, revocation, graph } = await wired();
    hold.node = (node) => ['first', 'second', 'under-first'].includes(node.id) && node.revoked === true;
    void graph.setRevoked('first', true);
    await stuck;
    void graph.setRevoked('second', true);
    void graph.setRevoked('under-first', true);

    const error = await afterTheWait(revocation.revokeDelegation('root'), 3);
    expect((error as Error).message).toContain('2 more delegations of the subtree were not marked either.');
  });

  it('throws any other error of a mark at once, as before', async () => {
    const { graph, revocation } = await wired();
    const setRevoked = graph.setRevoked.bind(graph);
    vi.spyOn(DelegationGraphManager.prototype, 'setRevoked').mockImplementation(async function (this: DelegationGraphManager, id, revoked) {
      if (id === 'second') throw new Error('Delegation not found: second');
      return setRevoked(id, revoked);
    });
    await expect(revocation.revokeDelegation('root')).rejects.toThrow('Delegation not found: second');
  });
});
