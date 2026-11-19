/**
 * `allocateStatusEntry(purpose, { delegationId })` records which delegation an entry is for, and
 * `getStatusEntryOwner` reads it back, so the graph and the cascade can tell the entry a delegation
 * was given from one its credential merely names. An owner is recorded only by a storage provider
 * that can keep one; asking any other to keep one throws before an index is taken.
 */
import { describe, expect, it, vi } from 'vitest';
import { realStatusListManager } from '../../__tests__/utils/status-list-manager.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { StatusList2021Manager, type StatusListStorageProvider } from '../statuslist-manager.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import { RefusalError } from '../../utils/refusal.js';
import { CascadingRevocationManager } from '../cascading-revocation.js';
import { DelegationGraphManager } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import { normalising, statusListManager } from './helpers/status-entry-operator.js';

/** A storage provider written to the base contract alone: it cannot record an entry's owner. */
function baseContract(memory: MemoryStatusListStorage): StatusListStorageProvider {
  return {
    getStatusList: (id) => memory.getStatusList(id),
    setStatusList: (id, credential) => memory.setStatusList(id, credential),
    allocateIndex: vi.fn((id: string) => memory.allocateIndex(id)),
  };
}

/** A store whose `allocateIndex` gives index 0 every time, against its contract. */
class RepeatingIndexStore extends MemoryStatusListStorage {
  override async allocateIndex(): Promise<number> {
    return 0;
  }
}

function managerOver(storage: StatusListStorageProvider): StatusList2021Manager {
  return new StatusList2021Manager(
    storage,
    { getDid: () => 'did:web:status.example', getKeyId: () => 'did:web:status.example#key-1' },
    async () => ({ type: 'Ed25519Signature2020', proofValue: 'z' }),
    statusListGzipCodec,
    statusListGzipCodec,
    { statusListBaseUrl: 'https://status.example', defaultListSize: 1024 },
  );
}

describe('StatusList2021Manager owners', () => {
  it('records the delegation an entry is allocated to, and reads it back however the entry writes its index', async () => {
    const { manager, storage } = await realStatusListManager();
    const owned = await manager.allocateStatusEntry('revocation', { delegationId: 'delegation-1' });
    const unowned = await manager.allocateStatusEntry('revocation');
    const suspension = await manager.allocateStatusEntry('suspension', { delegationId: 'delegation-2' });

    expect(owned).toEqual({
      id: 'https://status.example/revocation/v1#0',
      type: 'StatusList2021Entry',
      statusPurpose: 'revocation',
      statusListIndex: '0',
      statusListCredential: 'https://status.example/revocation/v1',
    });
    const one = { delegationId: 'delegation-1', retired: false };
    expect(await manager.getStatusEntryOwner(owned)).toEqual(one);
    expect(await manager.getStatusEntryOwner({ ...owned, statusListIndex: '00' })).toEqual(one);
    expect(await manager.getStatusEntryOwner({ ...owned, statusListIndex: 0 as unknown as string })).toEqual(one);
    expect(await manager.getStatusEntryOwner(unowned)).toBeUndefined();
    expect(await manager.getStatusEntryOwner(suspension)).toEqual({ delegationId: 'delegation-2', retired: false });
    expect(await manager.getStatusEntryOwner({ ...owned, statusListCredential: 'https://status.example/suspension/v1' })).toEqual({
      delegationId: 'delegation-2',
      retired: false,
    });
    expect(await manager.getStatusEntryOwner({ ...owned, statusListCredential: 'https://other.example/revocation/v1' })).toBeUndefined();
    expect(await storage.getEntryOwner('https://status.example/revocation/v1', 0)).toEqual(one);
  });

  it('retires an entry it recorded an owner for, keeping the owner, and retires nothing else', async () => {
    const { manager } = await realStatusListManager();
    const owned = await manager.allocateStatusEntry('revocation', { delegationId: 'delegation-1' });
    const unowned = await manager.allocateStatusEntry('revocation');

    await manager.retireStatusEntry({ ...owned, statusListIndex: '00' });
    await manager.retireStatusEntry(unowned);
    await manager.retireStatusEntry(owned);

    expect(await manager.getStatusEntryOwner(owned)).toEqual({ delegationId: 'delegation-1', retired: true });
    expect(await manager.getStatusEntryOwner(unowned)).toBeUndefined();
  });

  it('refuses an index that already has an owner, as a store that gives an index twice hands back, recording nothing', async () => {
    const manager = managerOver(new RepeatingIndexStore());
    const first = await manager.allocateStatusEntry('revocation', { delegationId: 'first' });

    for (const delegationId of ['second', 'first']) {
      await expect(manager.allocateStatusEntry('revocation', { delegationId })).rejects.toThrow(
        new Error(
          'Status list "https://status.example/revocation/v1" gave index 0, which already has an owner recorded, so ' +
            'no entry was allocated: allocateIndex must give each index once across every manager of the store',
        ),
      );
    }
    expect(await manager.getStatusEntryOwner(first)).toEqual({ delegationId: 'first', retired: false });

    // The first delegation's entry is still its own, so revoking it sets the bit.
    const graph = new DelegationGraphManager(new MemoryDelegationGraphStorage(), { statusEntryOwners: manager });
    await graph.registerDelegation({
      id: 'first',
      parentId: null,
      issuerDid: 'did:web:operator.example',
      subjectDid: 'did:web:first.example',
      credentialStatus: first,
    });
    await new CascadingRevocationManager(graph, manager).revokeDelegation('first');
    expect(await manager.checkStatus(first)).toBe(true);
  });

  it('throws a TypeError, recording nothing, when setEntryOwnerIfAbsent answers anything but a boolean', async () => {
    const storage = new MemoryStatusListStorage();
    storage.setEntryOwnerIfAbsent = async () => undefined as unknown as boolean;

    await expect(managerOver(storage).allocateStatusEntry('revocation', { delegationId: 'first' })).rejects.toThrow(
      new TypeError(
        'StatusEntryOwnerStorageProvider.setEntryOwnerIfAbsent must resolve true when it recorded the owner and ' +
          'false when the entry already had one',
      ),
    );
    expect(await storage.getEntryOwner('https://status.example/revocation/v1', 0)).toBeNull();
  });

  it('refuses to record an owner its storage provider cannot keep, before it takes an index', async () => {
    const memory = new MemoryStatusListStorage();
    const storage = baseContract(memory);
    const manager = managerOver(storage);
    // A provider with no set-if-absent cannot keep an owner safely either.
    const withoutIfAbsent = {
      ...baseContract(memory),
      setEntryOwner: memory.setEntryOwner.bind(memory),
      getEntryOwner: memory.getEntryOwner.bind(memory),
    };

    for (const provider of [storage, withoutIfAbsent]) {
      await expect(managerOver(provider).allocateStatusEntry('revocation', { delegationId: 'delegation-1' })).rejects.toThrow(
        new TypeError(
          'allocateStatusEntry was given a delegationId, but the status list storage provider cannot record which ' +
            'delegation an entry was allocated to. Implement setEntryOwnerIfAbsent, setEntryOwner and getEntryOwner ' +
            '(StatusEntryOwnerStorageProvider), as MemoryStatusListStorage does, or allocate without a delegationId.',
        ),
      );
      expect(provider.allocateIndex).not.toHaveBeenCalled();
    }
    expect(memory.getAllStatusListIds()).toEqual([]);

    // Without an owner it allocates as before, and reads no owner.
    const entry = await manager.allocateStatusEntry('revocation');
    expect(entry.statusListIndex).toBe('0');
    expect(await manager.getStatusEntryOwner(entry)).toBeUndefined();
  });

  it('refuses a delegationId that is not a non-empty string, before it takes an index', async () => {
    const memory = new MemoryStatusListStorage();
    const allocateIndex = vi.spyOn(memory, 'allocateIndex');
    const manager = managerOver(memory);

    for (const [delegationId, named] of [
      ['', 'a value ""'],
      [7, '7'],
      [null, 'a value of type null'],
    ] as const) {
      await expect(
        manager.allocateStatusEntry('revocation', { delegationId: delegationId as unknown as string }),
      ).rejects.toThrow(
        new TypeError(
          `allocateStatusEntry was given ${named} as delegationId: it must be a non-empty string, the id the ` +
            'delegation is registered under in the delegation graph',
        ),
      );
    }
    expect(allocateIndex).not.toHaveBeenCalled();
    await expect(manager.allocateStatusEntry('revocation', { delegationId: undefined })).resolves.toMatchObject({
      statusListIndex: '0',
    });
  });

  it('sets an entry only under the id its list was created with, and reads as before', async () => {
    const memory = new MemoryStatusListStorage();
    const before = statusListManager(memory);
    const own = await before.allocateStatusEntry('revocation', { delegationId: 'delegation-1' });
    // The same storage, under a manager whose base URL has since changed.
    const after = new StatusList2021Manager(
      memory,
      { getDid: () => 'did:web:status.example', getKeyId: () => 'did:web:status.example#key-1' },
      async () => ({ type: 'Ed25519Signature2020', proofValue: 'z' }),
      statusListGzipCodec,
      statusListGzipCodec,
      { statusListBaseUrl: 'https://lists.example', defaultListSize: 1024 },
    );

    await after.updateStatus(own, true);
    expect(await after.checkStatus(own)).toBe(true);
    expect(await after.getStatusEntryOwner(own)).toEqual({ delegationId: 'delegation-1', retired: false });
  });

  it('never sets an entry that names its list by another spelling, over a store that reads it as the same list', async () => {
    const manager = statusListManager(normalising(new MemoryStatusListStorage()));
    const own = await manager.allocateStatusEntry('revocation', { delegationId: 'delegation-1' });

    for (const list of ['https://STATUS.example:443/revocation/v1', 'https://status.example/revocation/./v1']) {
      const respelled = { ...own, id: `${list}#0`, statusListCredential: list };

      const set = await manager.updateStatus(respelled, true).then(() => undefined, (thrown: unknown) => thrown);
      expect(set).toBeInstanceOf(RefusalError);
      expect((set as RefusalError).code).toBe('delegation_malformed');
      expect((set as RefusalError).message).toBe(
        `Status list ${JSON.stringify(list)} reads as the list "https://status.example/revocation/v1", so no entry ` +
          'of it is set or cleared: an entry names its list by the id the list was created with',
      );
      // A read is answered as before, from the list the store holds.
      expect(await manager.checkStatus(respelled)).toBe(false);
    }
    expect(await manager.checkStatus(own)).toBe(false);
  });
});
