/**
 * A delegation's status list entry is the one the operator allocated for it. The issuer of a
 * re-delegation writes the entry its credential carries, so it can name another delegation's entry:
 * the graph refuses to register such an entry, and cascading revocation never sets or clears a bit
 * that belongs to a delegation the revocation or the restore does not reach.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { logger } from '../../logging/index.js';
import type { CredentialStatus } from '../../types/protocol.js';
import { RefusalError } from '../../utils/refusal.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager, type DelegationGraphStorageProvider } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';

const OPERATOR = 'did:web:operator.example';

/** A provider written to the base contract alone: no atomic registration, no lookup by status entry. */
function baseContract(memory: MemoryDelegationGraphStorage): DelegationGraphStorageProvider {
  return {
    getNode: (id) => memory.getNode(id),
    setNode: (node) => memory.setNode(node),
    getChildren: (id) => memory.getChildren(id),
    getChain: (id) => memory.getChain(id),
    getDescendants: (id) => memory.getDescendants(id),
    deleteNode: (id) => memory.deleteNode(id),
  };
}

/**
 * An operator's status list, graph and cascade. `owners` allocates each entry with the delegation
 * it is for; `lookup: false` keeps the graph to a provider that cannot look up an entry's
 * delegations. `registeredBefore` registers through the base contract over the same nodes, as a
 * graph did before it checked entries, so a test can hold such a node.
 */
async function operator(options: { owners?: boolean; lookup?: boolean; wireOwners?: boolean } = {}) {
  const { manager } = await realStatusListManager();
  const memory = new MemoryDelegationGraphStorage();
  const graph = new DelegationGraphManager(
    options.lookup === false ? baseContract(memory) : memory,
    options.wireOwners ? { statusEntryOwners: manager } : {},
  );
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
    const entry = await manager.allocateStatusEntry('revocation', options.owners ? { delegationId: id } : undefined);
    entries.set(id, entry);
    return entry;
  };
  /** Allocate an entry for `id` and register it, as an honest operator does. */
  const issue = async (id: string, parentId: string | null = null) =>
    graph.registerDelegation(params(id, parentId, await allocate(id)));
  /** Register `id` carrying the entry its issuer wrote, a copy of `named`'s. */
  const carrying = (id: string, parentId: string, named: string) =>
    graph.registerDelegation(params(id, parentId, { ...entries.get(named)! }));
  const carryingBefore = (id: string, parentId: string, named: string) =>
    before.registerDelegation(params(id, parentId, { ...entries.get(named)! }));
  /** Every allocated entry's bit, by the delegation it was allocated for. */
  const bits = async () =>
    Object.fromEntries(await Promise.all([...entries].map(async ([id, entry]) => [id, await manager.checkStatus(entry)])));

  return { manager, memory, graph, cascade, entries, params, allocate, issue, carrying, carryingBefore, bits };
}

/** The code and message of the `RefusalError` that `promise` rejects with. */
async function refusal(promise: Promise<unknown>): Promise<{ code: string; message: string }> {
  const error: unknown = await promise.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
  expect(error).toBeInstanceOf(RefusalError);
  return { code: (error as RefusalError).code, message: (error as RefusalError).message };
}

const malformed = (message: string) => ({ code: 'delegation_malformed', message });

const ENTRY = (index: number) => `https://status.example/revocation/v1#${index}`;

describe('registerDelegation with an entry another delegation holds', () => {
  it('refuses a child that names its root entry, so revoking the child cannot reach the root', async () => {
    const op = await operator();
    await op.issue('root');
    await op.issue('agent', 'root');

    expect(await refusal(op.carrying('child', 'agent', 'root'))).toEqual(
      malformed(
        `Delegation child cannot be registered with status list entry ${ENTRY(0)}: the entry is registered to another ` +
          "delegation, and revoking or restoring either delegation would change the other's status. Register each " +
          'delegation with an entry allocated for it, from allocateStatusEntry(purpose, { delegationId }).',
      ),
    );
    expect(await op.graph.getNode('child')).toBeNull();
    expect((await op.graph.getNode('agent'))?.children).toEqual([]);
    await op.cascade.revokeDelegation('agent');
    expect(await op.bits()).toEqual({ root: false, agent: true });
    expect(await op.cascade.isRevoked('root')).toEqual({ revoked: false });
  });

  it('refuses a sibling root entry however the index is written', async () => {
    const op = await operator();
    await op.issue('victim');
    await op.issue('attacker');
    const victim = op.entries.get('victim')!;

    for (const credentialStatus of [
      { ...victim },
      { ...victim, statusListIndex: '00' },
      { ...victim, statusListIndex: 0 as unknown as string },
      { ...victim, id: 'urn:uuid:5d1c4c7e-0000-4000-8000-000000000000', type: 'BitstringStatusListEntry' as const },
    ]) {
      await expect(op.graph.registerDelegation(op.params('child', 'attacker', credentialStatus))).rejects.toThrow(
        `Delegation child cannot be registered with status list entry ${ENTRY(0)}: the entry is registered to another delegation`,
      );
    }
    await expect(
      op.graph.registerDelegation({ ...op.params('child', 'attacker'), credentialStatusId: victim.id }),
    ).rejects.toThrow(`with status list entry ${ENTRY(0)}: the entry is registered to another delegation`);
    expect(await op.graph.getNode('child')).toBeNull();
  });

  it('refuses an entry allocated to another delegation before that one is registered', async () => {
    const op = await operator({ owners: true, wireOwners: true });
    await op.issue('attacker');
    const victim = await op.allocate('victim');

    expect(await refusal(op.carrying('child', 'attacker', 'victim'))).toEqual(
      malformed(
        `Delegation child cannot be registered with status list entry ${ENTRY(1)}: the entry was allocated to another ` +
          "delegation, and revoking or restoring either delegation would change the other's status. Register each " +
          'delegation with an entry allocated for it, from allocateStatusEntry(purpose, { delegationId }).',
      ),
    );
    await expect(op.graph.registerDelegation(op.params('victim', null, victim))).resolves.toMatchObject({ id: 'victim' });
  });

  it('refuses the entry in the memory store itself, which closes the race between the check and the write', async () => {
    const op = await operator();
    await op.issue('victim');
    await op.issue('attacker');
    const node = { ...op.params('child', 'attacker', { ...op.entries.get('victim')! }), children: [] };

    const refused = await refusal(op.memory.registerNodeAtomic(node));
    expect(refused.code).toBe('delegation_malformed');
    expect(refused.message).toContain(
      `Delegation child cannot be registered with status list entry ${ENTRY(0)}: the entry is registered to another delegation`,
    );
    expect(await op.memory.getNode('child')).toBeNull();
    expect((await op.memory.getNode('attacker'))?.children).toEqual([]);
  });
});

describe('revokeDelegation and restoreDelegation of a delegation that carries another delegation entry', () => {
  it('leaves a sibling root live when a child that names its entry is revoked', async () => {
    // A provider that cannot look entries up lets the child in; the entries' recorded owners still hold.
    const op = await operator({ owners: true, lookup: false });
    await op.issue('victim');
    await op.issue('attacker');
    await op.carrying('child', 'attacker', 'victim');

    expect(await refusal(op.cascade.revokeDelegation('child'))).toEqual(
      malformed(
        `Delegation child is revoked in the delegation graph, but its status list entry ${ENTRY(0)} was left unchanged: ` +
          'the entry was allocated to a delegation outside the subtree of child, and setting it would revoke that ' +
          'delegation too. A verifier that reads only the status list does not see this revocation; issue the ' +
          'delegation again with an entry allocated for it.',
      ),
    );
    expect(await op.bits()).toEqual({ victim: false, attacker: false });
    expect(await op.cascade.isRevoked('victim')).toEqual({ revoked: false });
    expect((await op.cascade.isRevoked('child')).revoked).toBe(true);
  });

  it('revokes the rest of the subtree, then says which entries it left unchanged', async () => {
    const op = await operator({ owners: true, lookup: false });
    await op.issue('victim');
    await op.issue('other');
    await op.issue('attacker');
    await op.carrying('child', 'attacker', 'victim');
    await op.issue('honest', 'attacker');
    await op.carrying('second', 'honest', 'other');
    const events: string[] = [];

    const revoking = op.cascade.revokeDelegation('attacker', { onRevoke: (event) => void events.push(event.delegationId) });

    expect(await refusal(revoking)).toEqual(
      malformed(
        `Delegations child (${ENTRY(0)}) and second (${ENTRY(1)}) are revoked in the delegation graph, but their ` +
          'status list entries were left unchanged: each entry belongs to a delegation outside the subtree of ' +
          'attacker, and setting it would revoke that delegation too. A verifier that reads only the status list ' +
          'does not see these revocations; issue each delegation again with an entry allocated for it.',
      ),
    );
    expect(events).toEqual(['attacker', 'child', 'honest', 'second']);
    expect(await op.bits()).toEqual({ victim: false, other: false, attacker: true, honest: true });
    for (const id of ['attacker', 'child', 'honest', 'second']) expect((await op.graph.getNode(id))?.revoked, id).toBe(true);
  });

  it('keeps a revoked root revoked on the published list when a child that names its entry is restored', async () => {
    const op = await operator({ owners: true, lookup: false });
    await op.issue('root');
    await op.carrying('child', 'root', 'root');
    // The child is in the root's subtree, so revoking the root may set the bit it names.
    await expect(op.cascade.revokeDelegation('root')).resolves.toHaveLength(2);
    expect(await op.bits()).toEqual({ root: true });

    expect(await refusal(op.cascade.restoreDelegation('child'))).toEqual(
      malformed(
        `Delegation child was not restored: its status list entry ${ENTRY(0)} was allocated to another delegation, ` +
          "and clearing it would restore that delegation's status too. It stays revoked; issue the delegation again " +
          'with an entry allocated for it.',
      ),
    );
    expect(await op.bits()).toEqual({ root: true });
    expect((await op.graph.getNode('child'))?.revoked).toBe(true);
    expect((await op.cascade.isRevoked('root')).revoked).toBe(true);
  });

  it('reads whose an entry is from the graph when no owner was recorded, for a node registered before the check', async () => {
    const op = await operator();
    await op.issue('victim');
    await op.issue('root');
    await op.carryingBefore('child', 'root', 'victim');
    await op.carryingBefore('reuse', 'root', 'root');

    await expect(op.cascade.revokeDelegation('child')).rejects.toThrow(
      `its status list entry ${ENTRY(0)} was left unchanged: the entry is registered to a delegation outside the subtree of child`,
    );
    expect(await op.bits()).toEqual({ victim: false, root: false });
    await expect(op.cascade.revokeDelegation('reuse')).rejects.toThrow(
      `its status list entry ${ENTRY(1)} was left unchanged: the entry is registered to a delegation outside the subtree of reuse`,
    );
    expect(await op.bits()).toEqual({ victim: false, root: false });

    // Revoking the root reaches every delegation registered with its entry, so its bit is set.
    await expect(op.cascade.revokeDelegation('root')).rejects.toThrow('Delegation child is revoked in the delegation graph');
    expect(await op.bits()).toEqual({ victim: false, root: true });
    await expect(op.cascade.restoreDelegation('reuse')).rejects.toThrow(
      `Delegation reuse was not restored: its status list entry ${ENTRY(1)} is registered to another delegation`,
    );
    await expect(op.cascade.restoreDelegation('root')).rejects.toThrow(
      `Delegation root was not restored: its status list entry ${ENTRY(1)} is registered to another delegation`,
    );
    expect(await op.bits()).toEqual({ victim: false, root: true });
  });

  it('never changes an entry allocated outside the subtree it revokes or the delegation it restores', async () => {
    const op = await operator({ owners: true, lookup: false });
    await op.issue('a');
    await op.issue('b', 'a');
    await op.issue('c', 'b');
    await op.issue('s');
    await op.carrying('p', 'b', 's');
    await op.carrying('q', 'b', 'a');
    await op.carrying('r', 'c', 'b');

    await expect(op.cascade.revokeDelegation('b')).rejects.toThrow(
      `Delegations p (${ENTRY(3)}) and q (${ENTRY(0)}) are revoked in the delegation graph`,
    );
    expect(await op.bits()).toEqual({ a: false, b: true, c: true, s: false });

    await expect(op.cascade.revokeDelegation('a')).rejects.toThrow(`Delegation p is revoked in the delegation graph`);
    expect(await op.bits()).toEqual({ a: true, b: true, c: true, s: false });

    for (const id of ['p', 'q', 'r']) {
      await expect(op.cascade.restoreDelegation(id), id).rejects.toThrow(`Delegation ${id} was not restored`);
    }
    expect(await op.bits()).toEqual({ a: true, b: true, c: true, s: false });
    await op.cascade.restoreDelegation('c');
    expect(await op.bits()).toEqual({ a: true, b: true, c: false, s: false });
  });
});

describe('an operator that allocates one entry per delegation and registers it with that delegation', () => {
  for (const [setup, options] of [
    ['allocating with no owner', {}],
    ['allocating each entry with its delegation', { owners: true }],
    ['allocating with owners the graph reads', { owners: true, wireOwners: true }],
    ['over a provider that cannot look entries up', { lookup: false }],
  ] as const) {
    it(`revokes and restores as before, ${setup}`, async () => {
      const op = await operator(options);
      await op.issue('root');
      await op.issue('child', 'root');
      await op.issue('sibling', 'root');
      await op.issue('grandchild', 'child');
      await op.issue('other');
      // A retry of a registration is still a no-op.
      await op.graph.registerDelegation(op.params('child', 'root', op.entries.get('child')));

      await op.cascade.revokeDelegation('child');
      expect(await op.bits()).toEqual({ root: false, child: true, sibling: false, grandchild: true, other: false });
      const events = await op.cascade.revokeDelegation('root');
      expect(events.map((event) => event.delegationId)).toEqual(['root', 'child', 'sibling', 'grandchild']);
      expect(await op.bits()).toEqual({ root: true, child: true, sibling: true, grandchild: true, other: false });

      await op.cascade.restoreDelegation('root');
      expect(await op.bits()).toEqual({ root: false, child: true, sibling: true, grandchild: true, other: false });
      expect(await op.cascade.isRevoked('root')).toEqual({ revoked: false });
      expect(await op.cascade.isRevoked('other')).toEqual({ revoked: false });
    });
  }

  it('registers and revokes a delegation by its legacy status id, as before', async () => {
    const op = await operator();
    const entry = await op.allocate('root');
    await op.graph.registerDelegation({ ...op.params('root', null), credentialStatusId: entry.id });
    await op.graph.registerDelegation({ ...op.params('root', null), credentialStatusId: entry.id });

    await op.cascade.revokeDelegation('root');
    expect(await op.bits()).toEqual({ root: true });
    expect(await op.graph.getDelegationIdsByStatusEntry(entry)).toEqual(['root']);
  });
});

describe('when nothing records whose an entry is', () => {
  const WARNED = Symbol.for('@kya-os/mcp/status-entry-owners-unknown-warned');
  const registry = globalThis as { [WARNED]?: true };
  let previous: true | undefined;

  beforeEach(() => {
    previous = registry[WARNED];
    delete registry[WARNED];
  });

  afterEach(() => {
    if (previous === undefined) delete registry[WARNED];
    else registry[WARNED] = previous;
  });

  it('takes the entry for the delegation that carries it, and warns once per process in fixed words', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const op = await operator({ lookup: false });
    await op.issue('root');
    await op.issue('child', 'root');
    await op.cascade.revokeDelegation('root');

    expect(await op.bits()).toEqual({ root: true, child: true });
    expect(warn.mock.calls).toEqual([
      [
        '[kya-os] A status list entry was registered, set or cleared with no record of whose it is: the status list ' +
          'manager recorded no owner for it, and the delegation graph storage provider cannot look up the delegations ' +
          'registered with it. The entry a delegation carries was taken as its own, so a re-delegation that names ' +
          "another delegation's entry can revoke or restore that delegation. Allocate each entry with " +
          'allocateStatusEntry(purpose, { delegationId }), or implement getNodeIdsByStatusEntry in the graph storage ' +
          'provider, as MemoryDelegationGraphStorage does.',
      ],
    ]);
  });

  it('does not warn when the graph and the cascade read the owners, or the graph can look entries up', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    for (const options of [{ owners: true, wireOwners: true, lookup: false }, {}]) {
      const op = await operator(options);
      await op.issue('root');
      await op.cascade.revokeDelegation('root');
      await op.cascade.restoreDelegation('root');
    }
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('DelegationGraphManager statusEntryOwners', () => {
  it('throws a TypeError for a value that cannot tell an entry owner', () => {
    for (const statusEntryOwners of [{}, null, 'manager']) {
      expect(
        () => new DelegationGraphManager(new MemoryDelegationGraphStorage(), { statusEntryOwners } as never),
      ).toThrow(
        new TypeError(
          'DelegationGraphManager was given statusEntryOwners without a getStatusEntryOwner method: pass the ' +
            'StatusList2021Manager that allocates the entries',
        ),
      );
    }
  });
});

describe('a revocation that leaves an entry unchanged over a provider that drops the graph mark', () => {
  it('throws at once that it recorded nothing, and sets no bit', async () => {
    const { manager } = await realStatusListManager();
    const memory = new MemoryDelegationGraphStorage();
    const dropping: DelegationGraphStorageProvider = {
      ...baseContract(memory),
      setNode: ({ revoked: _revoked, ...node }) => memory.setNode(node),
    };
    const graph = new DelegationGraphManager(dropping);
    const victim = await manager.allocateStatusEntry('revocation', { delegationId: 'victim' });
    await graph.registerDelegation({ id: 'victim', parentId: null, issuerDid: OPERATOR, subjectDid: 'did:web:victim.example', credentialStatus: victim });
    await graph.registerDelegation({ id: 'other', parentId: null, issuerDid: OPERATOR, subjectDid: 'did:web:other.example', credentialStatus: { ...victim } });

    await expect(new CascadingRevocationManager(graph, manager).revokeDelegation('other')).rejects.toThrow(
      new Error(
        `Revocation of delegation other was not recorded: its status list entry ${ENTRY(0)} was allocated to a ` +
          'delegation outside the subtree of other, so it was left unchanged, and the graph storage provider did not ' +
          'persist DelegationNode.revoked. A DelegationGraphStorageProvider must store the revoked field to revoke ' +
          'delegations without a status list entry.',
      ),
    );
    expect(await manager.checkStatus(victim)).toBe(false);
  });
});
