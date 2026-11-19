/**
 * The graph is the record of revocation for a delegation with no status list entry, and of every
 * ancestor's revocation for its descendants. A chain the storage provider returns that does not
 * read from a root to the delegation asked about, as one that stops at a node a replica has not
 * received or a store lost, says nothing of an ancestor above the gap. So `isRevoked` refuses to
 * answer for it, `validateChain` and `validateDelegation` refuse it, and `removeDelegation` makes
 * no such gap, nor erases a revocation the graph alone records: it keeps a revoked record of that
 * id. A delegation the graph never held still reads as not revoked: the chain walk asks about every
 * credential, a leaf never registered among them.
 */
import { describe, expect, it, vi } from 'vitest';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager, type DelegationNode } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import { RefusalError } from '../../utils/refusal.js';

const UNREADABLE = (id: string) =>
  `The delegation graph holds no chain from delegation "${id}" to a root, so whether it is revoked cannot be read`;

/** A root, its child and its grandchild, none with a status list entry, over a store the test can reach. */
async function graphOfThree(entries = false) {
  const { manager } = await realStatusListManager();
  const storage = new MemoryDelegationGraphStorage();
  const graph = new DelegationGraphManager(storage);
  const revocation = new CascadingRevocationManager(graph, manager);
  const links: [string, string | null, string, string][] = [
    ['root', null, 'did:web:user.example', 'did:web:a.example'],
    ['middle', 'root', 'did:web:a.example', 'did:web:b.example'],
    ['leaf', 'middle', 'did:web:b.example', 'did:web:c.example'],
  ];
  for (const [id, parentId, issuerDid, subjectDid] of links) {
    const credentialStatus = entries ? await manager.allocateStatusEntry('revocation') : undefined;
    await graph.registerDelegation({ id, parentId, issuerDid, subjectDid, ...(credentialStatus ? { credentialStatus } : {}) });
  }
  return { storage, graph, revocation, manager };
}

/** What `run` threw, or a failure when it settled otherwise. */
async function thrown(run: Promise<unknown>): Promise<Error> {
  return run.then(
    () => expect.unreachable('expected a throw'),
    (error: unknown) => error as Error,
  );
}

describe('CascadingRevocationManager.isRevoked: a chain that does not read from a root', () => {
  it('refuses to answer for a delegation below a node the graph does not hold, above which the root is revoked', async () => {
    const { storage, revocation } = await graphOfThree();
    await revocation.revokeDelegation('root');
    await storage.deleteNode('middle');

    const error = await thrown(revocation.isRevoked('leaf'));
    expect(error).toBeInstanceOf(RefusalError);
    expect(error).toMatchObject({ code: 'status_unavailable', message: UNREADABLE('leaf') });
    expect(await revocation.validateDelegation('leaf')).toEqual({
      valid: false,
      reason: 'Invalid chain: leaf names parent middle, which the graph does not hold',
    });
  });

  it('refuses a chain that ends at another delegation, or whose links do not follow each parentId', async () => {
    const { storage, graph, revocation } = await graphOfThree();
    const [root, middle, leaf] = await storage.getChain('leaf');
    const answers: [string, DelegationNode[], string][] = [
      ['middle', [root!, middle!, leaf!], 'Invalid chain: the chain the graph holds for middle ends at leaf'],
      ['leaf', [root!, leaf!], 'Invalid chain: leaf parentId=middle but actual parent is root'],
    ];
    for (const [id, chain, reason] of answers) {
      vi.spyOn(storage, 'getChain').mockResolvedValueOnce(chain).mockResolvedValueOnce(chain);
      expect(await thrown(revocation.isRevoked(id))).toMatchObject({ code: 'status_unavailable', message: UNREADABLE(id) });
      expect(await graph.validateChain(id)).toEqual({ valid: false, reason });
    }
  });

  it('still answers not revoked for a delegation the graph never held, and reads a whole chain as before', async () => {
    const { revocation } = await graphOfThree();
    expect(await revocation.isRevoked('never-registered')).toStrictEqual({ revoked: false });
    await revocation.revokeDelegation('middle');
    expect(await revocation.isRevoked('leaf')).toStrictEqual({
      revoked: true,
      reason: 'Ancestor revoked',
      revokedAncestor: 'middle',
    });
    expect(await revocation.validateDelegation('leaf')).toEqual({ valid: false, reason: 'Ancestor middle is revoked' });
  });
});

describe('DelegationGraphManager.removeDelegation: no gap, and no revocation erased', () => {
  it('refuses a delegation with delegations under it, and removes it once they are removed', async () => {
    const { graph } = await graphOfThree();
    const error = await thrown(graph.removeDelegation('middle'));
    expect(error.message).toBe(
      'Delegation middle is not removed: delegations are registered under it (leaf). Remove it with ' +
        '{ subtree: true }, which removes them first, or remove them first, since a delegation whose parent ' +
        'the graph does not hold cannot be read to a root',
    );
    expect((await graph.getNode('root'))?.children).toEqual(['middle']);
    expect(await graph.getNode('middle')).not.toBeNull();

    await graph.removeDelegation('leaf');
    await graph.removeDelegation('middle');
    expect(await graph.getNode('middle')).toBeNull();
    expect((await graph.getNode('root'))?.children).toEqual([]);
  });

  it('keeps a revoked record of a removed revoked delegation with no status list entry, without restoring it first', async () => {
    const { graph, revocation } = await graphOfThree();
    await revocation.revokeDelegation('leaf');
    await graph.removeDelegation('leaf');

    expect(await graph.getNode('leaf')).toEqual({
      id: 'leaf',
      parentId: null,
      children: [],
      issuerDid: 'did:web:b.example',
      subjectDid: 'did:web:c.example',
      revoked: true,
      removed: true,
    });
    expect((await graph.getNode('middle'))?.children).toEqual([]);
    expect(await revocation.isRevoked('leaf')).toEqual({ revoked: true, reason: 'Directly revoked', revokedAncestor: undefined });
    expect(await revocation.validateDelegation('leaf')).toEqual({ valid: false, reason: 'Delegation is revoked' });
    // Removing it again changes nothing, and the parent it was under can be removed now.
    await graph.removeDelegation('leaf');
    expect(await graph.getNode('leaf')).toMatchObject({ removed: true, revoked: true });
    await graph.removeDelegation('middle');
    expect(await revocation.isRevoked('leaf')).toMatchObject({ revoked: true });
  });

  it('keeps that record for one under a revoked ancestor, or whose chain does not read to a root', async () => {
    const { graph, revocation } = await graphOfThree();
    await revocation.revokeDelegation('middle');
    await graph.registerDelegation({ id: 'late', parentId: 'middle', issuerDid: 'did:web:b.example', subjectDid: 'did:web:d.example' });
    expect((await graph.getNode('late'))?.revoked).toBeUndefined();
    await graph.removeDelegation('late');
    expect(await revocation.isRevoked('late')).toMatchObject({ revoked: true });

    const gap = await graphOfThree();
    await gap.storage.deleteNode('middle');
    await gap.graph.removeDelegation('leaf');
    expect(await gap.graph.getNode('leaf')).toMatchObject({ removed: true, revoked: true });
  });

  it('removes a delegation that stands, and one with no status list entry that never was revoked, whole', async () => {
    const { graph } = await graphOfThree();
    await graph.removeDelegation('leaf');
    expect(await graph.getNode('leaf')).toBeNull();
  });

  it('refuses to register the removed id again, to register under it, and to restore it', async () => {
    const { graph, revocation } = await graphOfThree();
    await revocation.revokeDelegation('leaf');
    await graph.removeDelegation('leaf');

    const again = { id: 'leaf', parentId: 'middle', issuerDid: 'did:web:b.example', subjectDid: 'did:web:c.example' };
    expect((await thrown(graph.registerDelegation(again))).message).toBe(
      'Delegation leaf was removed while revoked, and its id stays revoked: register the delegation under another id',
    );
    const under = { id: 'under', parentId: 'leaf', issuerDid: 'did:web:c.example', subjectDid: 'did:web:d.example' };
    expect((await thrown(graph.registerDelegation(under))).message).toBe(
      'Parent delegation leaf was removed while revoked: register the delegation under one that stands',
    );
    expect((await thrown(revocation.restoreDelegation('leaf'))).message).toBe(
      'Delegation leaf was removed while revoked, and its id stays revoked: it is not restored',
    );
    expect(await revocation.isRevoked('leaf')).toMatchObject({ revoked: true });
  });

  it('keeps a revoked record of a revoked delegation whose status list entry records its revocation too', async () => {
    const { graph, revocation } = await graphOfThree(true);
    await revocation.revokeDelegation('leaf');
    await graph.removeDelegation('leaf');
    expect(await graph.getNode('leaf')).toMatchObject({ removed: true, revoked: true });
    expect(await revocation.isRevoked('leaf')).toMatchObject({ revoked: true });
  });

  it('keeps a revoked record of a revoked delegation whose status list entry never recorded the revocation', async () => {
    const { graph, revocation, manager } = await graphOfThree(true);
    const entry = (await graph.getNode('leaf'))!.credentialStatus!;
    vi.spyOn(manager, 'updateStatus').mockRejectedValueOnce(new Error('status list store unavailable'));
    await expect(revocation.revokeDelegation('leaf')).rejects.toThrow();
    expect(await revocation.isRevoked('leaf')).toMatchObject({ revoked: true });
    expect(await manager.checkStatus(entry)).toBe(false);

    await graph.removeDelegation('leaf');
    expect(await graph.getNode('leaf')).toMatchObject({ removed: true, revoked: true });
    expect(await revocation.isRevoked('leaf')).toMatchObject({ revoked: true });
    expect(await revocation.validateDelegation('leaf')).toEqual({ valid: false, reason: 'Delegation is revoked' });
  });

  it('removes a delegation with a status list entry that never was revoked whole, so its id registers again', async () => {
    const { graph } = await graphOfThree(true);
    await graph.removeDelegation('leaf');
    expect(await graph.getNode('leaf')).toBeNull();
    await graph.registerDelegation({ id: 'leaf', parentId: 'middle', issuerDid: 'did:web:b.example', subjectDid: 'did:web:c.example' });
    expect(await graph.getNode('leaf')).toMatchObject({ id: 'leaf', parentId: 'middle' });
  });
});
