/**
 * `removeDelegation(id, { subtree: true })` removes a delegation and every delegation under it in
 * one call, children first, each as `removeDelegation` removes one: its entry retired, and a
 * revoked record left where the graph alone records its revocation. Like a cascading revocation,
 * it never stops part way: a delegation it cannot remove keeps every delegation above it, so each
 * one left still reads to a root, the rest of the subtree is removed, and it then throws a
 * `SubtreeRemovalError` that says what was and was not removed.
 */
import { describe, expect, it, vi } from 'vitest';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager, SubtreeRemovalError } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import type { CredentialStatus } from '../../types/protocol.js';

/**
 * A graph whose entries the status list manager owns: `top` over `a` and `b`, `a` over `c` and
 * `d`, each with an entry allocated to it unless `entries` is false.
 */
async function tree(entries = true) {
  const { manager } = await realStatusListManager();
  const storage = new MemoryDelegationGraphStorage();
  const graph = new DelegationGraphManager(storage, { statusEntryOwners: manager });
  const revocation = new CascadingRevocationManager(graph, manager);
  const entryOf = new Map<string, CredentialStatus>();
  const links: [string, string | null][] = [['top', null], ['a', 'top'], ['b', 'top'], ['c', 'a'], ['d', 'a']];
  for (const [id, parentId] of links) {
    const credentialStatus = entries ? await manager.allocateStatusEntry('revocation', { delegationId: id }) : undefined;
    if (credentialStatus) entryOf.set(id, credentialStatus);
    await graph.registerDelegation({
      id,
      parentId,
      issuerDid: parentId === null ? 'did:web:user.example' : `did:web:${parentId}.example`,
      subjectDid: `did:web:${id}.example`,
      ...(credentialStatus ? { credentialStatus } : {}),
    });
  }
  return { manager, storage, graph, revocation, entryOf };
}

describe('DelegationGraphManager.removeDelegation with { subtree: true }', () => {
  it('removes a delegation and every delegation under it, children first, retiring each one entry', async () => {
    const { manager, storage, graph, entryOf } = await tree();
    const deleted: string[] = [];
    const deleteNode = storage.deleteNode.bind(storage);
    vi.spyOn(storage, 'deleteNode').mockImplementation(async (id) => {
      deleted.push(id);
      await deleteNode(id);
    });

    await graph.removeDelegation('a', { subtree: true });

    expect(deleted).toEqual(['d', 'c', 'a']);
    for (const id of ['a', 'c', 'd']) {
      expect(await graph.getNode(id)).toBeNull();
      expect(await manager.getStatusEntryOwner(entryOf.get(id)!)).toEqual({ delegationId: id, retired: true });
    }
    expect((await graph.getNode('top'))?.children).toEqual(['b']);
    expect(await graph.validateChain('b')).toEqual({ valid: true });
  });

  it('leaves a revoked record for each delegation of a revoked subtree the graph alone records', async () => {
    const { graph, revocation } = await tree(false);
    await revocation.revokeDelegation('a');
    await graph.removeDelegation('a', { subtree: true });
    for (const id of ['a', 'c', 'd']) {
      expect(await graph.getNode(id)).toMatchObject({ parentId: null, revoked: true, removed: true });
      expect(await revocation.isRevoked(id)).toMatchObject({ revoked: true });
    }
    expect(await revocation.isRevoked('b')).toEqual({ revoked: false });
  });

  it('removes the rest when one cannot be removed, keeps every delegation above it, then says so', async () => {
    const { storage, graph } = await tree();
    const deleteNode = storage.deleteNode.bind(storage);
    vi.spyOn(storage, 'deleteNode').mockImplementation(async (id) => {
      if (id === 'c') throw new Error('store unreachable');
      await deleteNode(id);
    });

    const error = await graph.removeDelegation('top', { subtree: true }).then(
      () => expect.unreachable('expected a SubtreeRemovalError'),
      (thrown: unknown) => thrown as SubtreeRemovalError,
    );
    expect(error).toBeInstanceOf(SubtreeRemovalError);
    expect(error.name).toBe('SubtreeRemovalError');
    expect(error.removed).toEqual(['d', 'b']);
    expect(error.notRemoved).toEqual([{ delegationId: 'c', cause: new Error('store unreachable') }]);
    expect(error.kept).toEqual(['a', 'top']);
    expect(error.message).toBe(
      'Delegation "top" and the delegations under it were not all removed: delegation "c" was not, for the ' +
        'reason in notRemoved. Every delegation above one not removed is kept, so each one left reads to a root ' +
        '(2 kept, 2 removed). Remove delegation "top" with { subtree: true } again',
    );
    expect(await graph.validateChain('c')).toEqual({ valid: true });
    expect((await graph.getNode('a'))?.children).toEqual(['c']);

    vi.mocked(storage.deleteNode).mockImplementation(deleteNode);
    await graph.removeDelegation('top', { subtree: true });
    expect(await graph.getNode('top')).toBeNull();
  });

  it('counts each other delegation it could not remove', async () => {
    const { storage, graph } = await tree();
    const deleteNode = storage.deleteNode.bind(storage);
    vi.spyOn(storage, 'deleteNode').mockImplementation(async (id) => {
      if (id === 'c' || id === 'b') throw new Error('store unreachable');
      await deleteNode(id);
    });
    const error = (await graph.removeDelegation('top', { subtree: true }).catch((thrown: unknown) => thrown)) as SubtreeRemovalError;
    expect(error.notRemoved.map((entry) => entry.delegationId)).toEqual(['c', 'b']);
    expect(error.message).toContain('delegation "c" was not, and one more was not, for the reasons in notRemoved');
  });

  it('counts every other delegation it could not remove', async () => {
    const { storage, graph } = await tree();
    vi.spyOn(storage, 'deleteNode').mockRejectedValue(new Error('store unreachable'));
    const error = (await graph.removeDelegation('top', { subtree: true }).catch((thrown: unknown) => thrown)) as SubtreeRemovalError;
    expect(error.notRemoved.map((entry) => entry.delegationId)).toEqual(['d', 'c', 'b']);
    expect(error.kept).toEqual(['a', 'top']);
    expect(error.message).toContain('delegation "d" was not, and 2 more were not, for the reasons in notRemoved');
  });

  it('removes nothing for a delegation the graph does not hold, and one delegation alone as without the option', async () => {
    const { graph } = await tree();
    await graph.removeDelegation('missing', { subtree: true });
    await graph.removeDelegation('d', { subtree: true });
    expect(await graph.getNode('d')).toBeNull();
    expect((await graph.getNode('a'))?.children).toEqual(['c']);
  });

  it('is named by the refusal of a delegation with delegations under it, without the option', async () => {
    const { graph } = await tree();
    await expect(graph.removeDelegation('a')).rejects.toThrow(
      'Delegation a is not removed: delegations are registered under it (c, d). Remove it with ' +
        '{ subtree: true }, which removes them first, or remove them first, since a delegation whose parent ' +
        'the graph does not hold cannot be read to a root',
    );
  });
});
