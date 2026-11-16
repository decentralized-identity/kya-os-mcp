/**
 * CascadingRevocationManager reads its status list's answer as every other reader of a revocation
 * answer does, through the shared reader: only a literal `false` is a clear bit and only a literal
 * `true` a set one. The manager it is typed against answers a boolean, but a subclass, a wrapper or
 * a fault can answer anything, and `undefined`, `null`, `0` or `""`, read by truthiness, left a
 * delegation whose status could not be read looking live. Any other answer now reads as revoked,
 * with a reason that says the status could not be read; `isRevoked` does not throw on it, as it did
 * not before.
 */
import { describe, expect, it } from 'vitest';
import { NOT_BOOLEANS } from '../../__tests__/utils/revocation-answers.js';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import type { StatusList2021Manager } from '../statuslist-manager.js';

const unreadable = (named: string) =>
  `Credential status could not be read: the status list resolver's answer (${named}) is neither true nor false`;

/**
 * A manager over a root and its child, each with a status entry, whose status list answers
 * `answers[id]` for a delegation's entry, and a clear bit for one it has no answer for.
 */
async function managerAnswering(answers: Record<string, unknown>) {
  const { manager } = await realStatusListManager();
  const graph = new DelegationGraphManager(new MemoryDelegationGraphStorage());
  const idOf = new Map<string, string>();
  for (const [id, parentId] of [['root', null], ['child', 'root']] as [string, string | null][]) {
    const credentialStatus = await manager.allocateStatusEntry('revocation');
    idOf.set(credentialStatus.statusListIndex, id);
    const issuerDid = parentId === null ? 'did:web:acme.example' : `did:web:${parentId}.example`;
    await graph.registerDelegation({ id, parentId, issuerDid, subjectDid: `did:web:${id}.example`, credentialStatus });
  }
  const asked: string[] = [];
  const statusList = {
    checkStatus: async (entry: { statusListIndex: string }) => {
      const id = idOf.get(entry.statusListIndex)!;
      asked.push(id);
      return id in answers ? answers[id] : false;
    },
  } as unknown as StatusList2021Manager;
  return { cascade: new CascadingRevocationManager(graph, statusList), asked };
}

describe("CascadingRevocationManager and its status list's answer", () => {
  it('reads a literal false as a clear bit and a literal true as a set one', async () => {
    const clear = await managerAnswering({});
    expect(await clear.cascade.isRevoked('child')).toStrictEqual({ revoked: false });
    expect(clear.asked).toEqual(['root', 'child']);
    expect(await clear.cascade.validateDelegation('child')).toEqual({ valid: true });
    const set = await managerAnswering({ child: true });
    expect(await set.cascade.isRevoked('child')).toStrictEqual({ revoked: true, reason: 'Directly revoked', revokedAncestor: undefined });
    const above = await managerAnswering({ root: true });
    expect(await above.cascade.isRevoked('child')).toStrictEqual({ revoked: true, reason: 'Ancestor revoked', revokedAncestor: 'root' });
  });

  it.each(NOT_BOOLEANS)("reads the delegation's own status as revoked, and says why, when the list answers %s", async (_label, answer, named) => {
    const { cascade } = await managerAnswering({ child: answer });
    expect(await cascade.isRevoked('child')).toStrictEqual({ revoked: true, reason: unreadable(named), revokedAncestor: undefined });
    expect(await cascade.isRevoked('root')).toStrictEqual({ revoked: false });
    expect(await cascade.validateDelegation('child')).toEqual({ valid: false, reason: 'Delegation is revoked' });
    expect(await cascade.getRevokedInSubtree('root')).toEqual(['child']);
  });

  it.each(NOT_BOOLEANS)("reads a delegation as revoked through its ancestor when the list answers %s for the ancestor", async (_label, answer, named) => {
    const { cascade, asked } = await managerAnswering({ root: answer });
    expect(await cascade.isRevoked('child')).toStrictEqual({ revoked: true, reason: unreadable(named), revokedAncestor: 'root' });
    // The walk stops at the ancestor, as it does at one whose bit is set.
    expect(asked).toEqual(['root']);
    expect(await cascade.validateDelegation('child')).toEqual({ valid: false, reason: 'Ancestor root is revoked' });
    expect(await cascade.getRevokedInSubtree('root')).toEqual(['root', 'child']);
  });

  it('still rejects when its status list throws', async () => {
    const { manager } = await realStatusListManager();
    const graph = new DelegationGraphManager(new MemoryDelegationGraphStorage());
    await graph.registerDelegation({ id: 'root', parentId: null, issuerDid: 'did:web:acme.example', subjectDid: 'did:web:a.example', credentialStatus: await manager.allocateStatusEntry('revocation') });
    const statusList = { checkStatus: async () => { throw new Error('list unreachable'); } } as unknown as StatusList2021Manager;
    await expect(new CascadingRevocationManager(graph, statusList).isRevoked('root')).rejects.toThrow('list unreachable');
  });
});
