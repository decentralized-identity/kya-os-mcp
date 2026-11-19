/**
 * What `StatusList2021Manager` asks of the store it is built over. A store with only the three
 * methods every store had before the conditional write is read and written as before, and the
 * first write a manager makes to one in a process warns, once, that it is safe with one manager
 * only and what to do about it. A store with the conditional write gets no warning, and one that
 * answers a conditional write with anything but a boolean is refused before it is trusted.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import {
  StatusList2021Manager,
  createStatusListManager,
  type StatusListStorageProvider,
} from '../statuslist-manager.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import type { VCSigningFunction } from '../vc-issuer.js';
import type { StatusList2021Credential } from '../../types/protocol.js';
import { OwnMapStore, replica } from './helpers/status-list-writers.js';

const identity = { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#key-1' };
const sign: VCSigningFunction = async () => ({ type: 'Ed25519Signature2020', proofValue: 'x' });
const options = { statusListBaseUrl: 'https://status.example', defaultListSize: 1024 };

/** A store with only the three methods every store had to implement, over `memory`, counting its writes. */
function plainStore(memory = new MemoryStatusListStorage()): StatusListStorageProvider & { writes: number } {
  const store = {
    writes: 0,
    getStatusList: (statusListId: string) => memory.getStatusList(statusListId),
    setStatusList: async (statusListId: string, credential: StatusList2021Credential) => {
      store.writes++;
      await memory.setStatusList(statusListId, credential);
    },
    allocateIndex: (statusListId: string) => memory.allocateIndex(statusListId),
  };
  return store;
}

const WARNED = Symbol.for('@kya-os/mcp/statuslist-unconditional-store-warned');
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

describe('StatusList2021Manager over a store with no conditional write', () => {
  it('reads and writes the list once for each change, as before', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const store = plainStore();
    const manager = createStatusListManager(store, identity, sign, undefined, undefined, options);

    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(entry, true);

    expect(await manager.checkStatus(entry)).toBe(true);
    expect(store.writes).toBe(2);
  });

  it('warns on the first write, once per process, across copies of the package, in fixed words that say what to do', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const first = new StatusList2021Manager(plainStore(), identity, sign, undefined, undefined, options);
    const second = createStatusListManager(plainStore(), identity, sign, undefined, undefined, options);
    expect(warn).not.toHaveBeenCalled();

    await first.allocateStatusEntry('revocation');
    await second.allocateStatusEntry('suspension');

    expect(warn).toHaveBeenCalledTimes(1);
    const [args] = warn.mock.calls;
    expect(args).toHaveLength(1);
    const [message] = args as [string];
    expect(message).toMatch(/^\[kya-os\] StatusList2021Manager wrote to a status-list store with no conditional write/);
    expect(message).toMatch(/a revocation can be lost/);
    expect(message).toMatch(
      /Implement ConditionalStatusListStorageProvider \(getStatusListWithEtag and setStatusListIfMatch\) on the store/,
    );
    expect(message).toMatch(/or write through one manager per store\./);
    expect(message).toMatch(/UPGRADING\.md, "Status-list stores take a conditional write", has the detail\.$/);

    vi.resetModules();
    const reloaded = await import('../statuslist-manager.js');
    const logging = await import('../../logging/index.js');
    const reloadedWarn = vi.spyOn(logging.logger, 'warn').mockImplementation(() => {});
    await new reloaded.StatusList2021Manager(plainStore(), identity, sign, undefined, undefined, options)
      .allocateStatusEntry('revocation');
    expect(reloadedWarn).not.toHaveBeenCalled();
  });

  it('does not warn for a manager that only reads, since only writes can be lost', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const memory = new MemoryStatusListStorage();
    const entry = await createStatusListManager(memory, identity, sign, undefined, undefined, options)
      .allocateStatusEntry('revocation');
    const reader = createStatusListManager(plainStore(memory), identity, sign, undefined, undefined, options);

    expect(await reader.checkStatus(entry)).toBe(false);
    expect(await reader.getRevokedIndices(entry.statusListCredential)).toEqual([]);
    await reader.allocateStatusEntry('revocation');

    expect(warn).not.toHaveBeenCalled();
  });

  it('warns over a store that implements only half of the conditional write', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const memory = new MemoryStatusListStorage();
    const half = Object.assign(plainStore(), {
      getStatusListWithEtag: (statusListId: string) => memory.getStatusListWithEtag(statusListId),
    });

    await new StatusList2021Manager(half, identity, sign, undefined, undefined, options).allocateStatusEntry('revocation');

    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('StatusList2021Manager over a store with the conditional write', () => {
  it('does not warn when it writes', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const manager = createStatusListManager(new MemoryStatusListStorage(), identity, sign, undefined, undefined, options);

    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(entry, true);

    expect(warn).not.toHaveBeenCalled();
  });

  it('reads and writes through a Proxy around MemoryStatusListStorage', async () => {
    const store = new Proxy(new MemoryStatusListStorage(), {});
    const manager = createStatusListManager(store, identity, sign, undefined, undefined, options);

    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(entry, true);

    expect(await manager.checkStatus(entry)).toBe(true);
    expect(store.getAllStatusListIds()).toEqual([entry.statusListCredential]);
  });

  it('throws a TypeError when the store answers a conditional write with anything but a boolean', async () => {
    class UnansweringStore extends MemoryStatusListStorage {
      override async setStatusListIfMatch(
        statusListId: string,
        credential: StatusList2021Credential,
        etag: string | null,
      ): Promise<boolean> {
        await super.setStatusListIfMatch(statusListId, credential, etag);
        return undefined as unknown as boolean;
      }
    }
    const manager = new StatusList2021Manager(new UnansweringStore(), identity, sign, undefined, undefined, options);

    await expect(manager.allocateStatusEntry('revocation')).rejects.toThrow(
      new TypeError(
        'ConditionalStatusListStorageProvider.setStatusListIfMatch must resolve true when it stored the list ' +
          'and false when it refused it',
      ),
    );
  });

  it.each([undefined, '', 7])(
    'throws a TypeError, and writes nothing, when the store reads a list with the etag %s',
    async (etag) => {
      /** A store that, once `blank` is on, reads each stored list with `etag` in place of its own. */
      class EtaglessStore extends MemoryStatusListStorage {
        blank = false;
        conditionalWrites = 0;

        override async getStatusListWithEtag(statusListId: string) {
          const stored = await super.getStatusListWithEtag(statusListId);
          return stored === null || !this.blank ? stored : { ...stored, etag: etag as unknown as string };
        }

        override async setStatusListIfMatch(
          statusListId: string,
          credential: StatusList2021Credential,
          expected: string | null,
        ): Promise<boolean> {
          this.conditionalWrites++;
          return super.setStatusListIfMatch(statusListId, credential, expected);
        }
      }
      const store = new EtaglessStore();
      const manager = new StatusList2021Manager(store, identity, sign, undefined, undefined, options);
      const entry = await manager.allocateStatusEntry('revocation');
      store.blank = true;
      store.conditionalWrites = 0;

      await expect(manager.updateStatus(entry, true)).rejects.toThrow(
        new TypeError(
          'ConditionalStatusListStorageProvider.getStatusListWithEtag must answer a stored list with its etag, ' +
            'a string that is not empty',
        ),
      );
      expect(store.conditionalWrites).toBe(0);
      expect(await manager.checkStatus(entry)).toBe(false);
    },
  );
});

describe('StatusList2021Manager over a subclass of MemoryStatusListStorage', () => {
  it('reads and writes through the subclass, so one that counts its writes sees each, with no warning', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    class CountingStore extends MemoryStatusListStorage {
      reads = 0;
      writes = 0;

      override async getStatusList(statusListId: string): Promise<StatusList2021Credential | null> {
        this.reads++;
        return super.getStatusList(statusListId);
      }

      override async setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void> {
        this.writes++;
        await super.setStatusList(statusListId, credential);
      }
    }
    const store = new CountingStore();
    const manager = createStatusListManager(store, identity, sign, undefined, undefined, options);

    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(entry, true);

    expect(store.writes).toBe(2);
    // The manager reads the list once for each change, and the store once more to see that no list
    // is stored before it creates one.
    expect(store.reads).toBe(3);
    expect(await manager.checkStatus(entry)).toBe(true);
    expect(warn).not.toHaveBeenCalled();
  });

  it('keeps every change over a subclass that keeps its lists in a map of its own, with no super', async () => {
    const store = new OwnMapStore();
    const first = replica(store);
    const second = replica(store);

    const revokedFirst = await first.allocateStatusEntry('revocation');
    await first.updateStatus(revokedFirst, true);
    // The list is stored, so allocating again must not store an empty one over it.
    const revokedSecond = await second.allocateStatusEntry('revocation');
    const revokedThird = await first.allocateStatusEntry('revocation');
    await Promise.all([first.updateStatus(revokedSecond, true), second.updateStatus(revokedThird, true)]);

    expect(await first.getRevokedIndices(revokedFirst.statusListCredential)).toEqual([0, 1, 2]);
    expect(await second.checkStatus(revokedFirst)).toBe(true);
  });
});
