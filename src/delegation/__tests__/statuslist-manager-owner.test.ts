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

/** A storage provider written to the base contract alone: it cannot record an entry's owner. */
function baseContract(memory: MemoryStatusListStorage): StatusListStorageProvider {
  return {
    getStatusList: (id) => memory.getStatusList(id),
    setStatusList: (id, credential) => memory.setStatusList(id, credential),
    allocateIndex: vi.fn((id: string) => memory.allocateIndex(id)),
  };
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
    expect(await manager.getStatusEntryOwner(owned)).toBe('delegation-1');
    expect(await manager.getStatusEntryOwner({ ...owned, statusListIndex: '00' })).toBe('delegation-1');
    expect(await manager.getStatusEntryOwner({ ...owned, statusListIndex: 0 as unknown as string })).toBe('delegation-1');
    expect(await manager.getStatusEntryOwner(unowned)).toBeUndefined();
    expect(await manager.getStatusEntryOwner(suspension)).toBe('delegation-2');
    expect(await manager.getStatusEntryOwner({ ...owned, statusListCredential: 'https://status.example/suspension/v1' })).toBe(
      'delegation-2',
    );
    expect(await manager.getStatusEntryOwner({ ...owned, statusListCredential: 'https://other.example/revocation/v1' })).toBeUndefined();
    expect(await storage.getEntryOwner('https://status.example/revocation/v1', 0)).toBe('delegation-1');
  });

  it('refuses to record an owner its storage provider cannot keep, before it takes an index', async () => {
    const memory = new MemoryStatusListStorage();
    const storage = baseContract(memory);
    const manager = managerOver(storage);

    await expect(manager.allocateStatusEntry('revocation', { delegationId: 'delegation-1' })).rejects.toThrow(
      new TypeError(
        'allocateStatusEntry was given a delegationId, but the status list storage provider cannot record which ' +
          'delegation an entry was allocated to. Implement setEntryOwner and getEntryOwner ' +
          '(StatusEntryOwnerStorageProvider), as MemoryStatusListStorage does, or allocate without a delegationId.',
      ),
    );
    expect(storage.allocateIndex).not.toHaveBeenCalled();
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
});
