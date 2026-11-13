/**
 * StatusList2021Manager writes a status bit from the operator's own record of an entry it issued,
 * which a storage layer may hand back with the index as a number, so `updateStatus` takes a
 * non-negative safe integer as well as a decimal string: refusing it would leave a revoked
 * credential's bit clear. CascadingRevocationManager reads the graph's stored entries, the same
 * records, the same way. `checkStatus` reads an entry as a credential states it, and takes a string
 * alone, as every status-list reader does.
 */

import { describe, it, expect } from 'vitest';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
  type RealStatusListSetup,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import type { CredentialStatus } from '../../types/protocol.js';

async function realManager(): Promise<RealStatusListSetup> {
  const crypto = createRealCryptoProvider();
  return createRealStatusListManager(crypto, await createRealIdentity(crypto), {
    statusListBaseUrl: 'https://status.example',
  });
}

/** `entry` as a storage layer that keeps its index as a number hands it back. */
const numbered = (entry: CredentialStatus, statusListIndex: unknown = Number(entry.statusListIndex)): CredentialStatus =>
  ({ ...entry, statusListIndex }) as unknown as CredentialStatus;

describe('StatusList2021Manager and an index stored as a number', () => {
  it('updateStatus sets and clears the bit a reader of the string index then sees', async () => {
    const { manager } = await realManager();
    await manager.allocateStatusEntry('revocation');
    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(numbered(entry), true);
    expect(await manager.checkStatus(entry)).toBe(true);
    await manager.updateStatus(numbered(entry), false);
    expect(await manager.checkStatus(entry)).toBe(false);
  });

  it('checkStatus, a reader, still refuses it', async () => {
    const { manager } = await realManager();
    const entry = await manager.allocateStatusEntry('revocation');
    await expect(manager.checkStatus(numbered(entry))).rejects.toThrow(
      new Error('Invalid statusListIndex of type number: must be a non-negative decimal string'),
    );
  });

  it('updateStatus refuses a negative, fractional, unsafe or non-finite number, and anything else not a string, and sets no bit', async () => {
    const { manager, storage } = await realManager();
    const entry = await manager.allocateStatusEntry('revocation');
    const before = await storage.getStatusList(entry.statusListCredential);
    const refused: [unknown, string][] = [
      ...[-1, 7.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY].map(
        (index): [unknown, string] => [index, 'of type number'],
      ),
      [['7'], 'of type array'],
      [JSON.parse('{"toString":"7"}'), 'of type object'],
      [null, 'of type null'],
    ];
    for (const [index, named] of refused) {
      await expect(manager.updateStatus(numbered(entry, index), true)).rejects.toThrow(
        new Error(`Invalid statusListIndex ${named}: must be a non-negative safe integer or a non-negative decimal string`),
      );
    }
    expect(await storage.getStatusList(entry.statusListCredential)).toEqual(before);
  });
});

describe('CascadingRevocationManager over a graph that stores its indexes as numbers', () => {
  it('reads each delegation as 1.22.0 did, before and after a revocation', async () => {
    const { manager } = await realManager();
    const graph = new DelegationGraphManager(new MemoryDelegationGraphStorage());
    const entries = new Map<string, CredentialStatus>();
    for (const [id, parentId] of [['root', null], ['child', 'root'], ['other', null]] as [string, string | null][]) {
      const entry = await manager.allocateStatusEntry('revocation');
      entries.set(id, entry);
      await graph.registerDelegation({ id, parentId, issuerDid: 'did:web:acme.example', subjectDid: `did:web:${id}.example`, credentialStatus: numbered(entry) });
    }
    const cascade = new CascadingRevocationManager(graph, manager);
    for (const id of entries.keys()) expect(await cascade.isRevoked(id), id).toEqual({ revoked: false });
    expect(await cascade.validateDelegation('other')).toEqual({ valid: true });
    expect(await cascade.getRevokedInSubtree('root')).toEqual([]);

    await cascade.revokeDelegation('root');
    expect(await cascade.isRevoked('child')).toEqual({ revoked: true, reason: 'Ancestor revoked', revokedAncestor: 'root' });
    expect(await cascade.isRevoked('other')).toEqual({ revoked: false });
    expect(await cascade.validateDelegation('other')).toEqual({ valid: true });
    expect(await cascade.getRevokedInSubtree('root')).toEqual(['root', 'child']);

    // A bit set outside the cascade, with no mark on the graph, is read from the stored entry.
    await manager.updateStatus(entries.get('other')!, true);
    expect(await cascade.isRevoked('other')).toEqual({ revoked: true, reason: 'Directly revoked', revokedAncestor: undefined });
  });

  it('revokes the whole subtree, setting the bit of every delegation in it', async () => {
    const { manager } = await realManager();
    const graph = new DelegationGraphManager(new MemoryDelegationGraphStorage());
    const tree: [string, string | null][] = [['root', null], ['child', 'root'], ['sibling', 'root'], ['grandchild', 'child']];
    const entries = new Map<string, CredentialStatus>();
    for (const [id, parentId] of tree) {
      const entry = await manager.allocateStatusEntry('revocation');
      entries.set(id, entry);
      await graph.registerDelegation({ id, parentId, issuerDid: 'did:web:acme.example', subjectDid: `did:web:${id}.example`, credentialStatus: numbered(entry) });
    }

    const events = await new CascadingRevocationManager(graph, manager).revokeDelegation('root');

    expect(events.map((event) => event.delegationId).sort()).toEqual(['child', 'grandchild', 'root', 'sibling']);
    for (const [id, entry] of entries) {
      expect(await manager.checkStatus(entry), id).toBe(true);
      expect((await graph.getNode(id))?.revoked, id).toBe(true);
    }
  });
});
