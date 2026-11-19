/**
 * What `StatusList2021Manager` asks of the store it is built over. A store with only the three
 * methods every store had before the conditional write is read and written as before, and the
 * first manager built over one in a process warns, once, that it is safe with one manager only
 * and what to do about it. A store with the conditional write gets no warning, and one that
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

const identity = { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#key-1' };
const sign: VCSigningFunction = async () => ({ type: 'Ed25519Signature2020', proofValue: 'x' });
const options = { statusListBaseUrl: 'https://status.example', defaultListSize: 1024 };

/** A store with only the three methods every store had to implement, over memory, counting its writes. */
function plainStore(): StatusListStorageProvider & { writes: number } {
  const memory = new MemoryStatusListStorage();
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

  it('warns once per process, across copies of the package, in fixed words that say what to do', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    new StatusList2021Manager(plainStore(), identity, sign);
    createStatusListManager(plainStore(), identity, sign);

    expect(warn).toHaveBeenCalledTimes(1);
    const [args] = warn.mock.calls;
    expect(args).toHaveLength(1);
    const [message] = args as [string];
    expect(message).toMatch(/^\[kya-os\] StatusList2021Manager was built over a status-list store with no conditional write/);
    expect(message).toMatch(/a revocation can be lost/);
    expect(message).toMatch(/Implement getStatusListWithEtag and setStatusListIfMatch on the store/);
    expect(message).toMatch(/or write through one manager per store\.$/);

    vi.resetModules();
    const reloaded = await import('../statuslist-manager.js');
    const logging = await import('../../logging/index.js');
    const reloadedWarn = vi.spyOn(logging.logger, 'warn').mockImplementation(() => {});
    new reloaded.StatusList2021Manager(plainStore(), identity, sign);
    expect(reloadedWarn).not.toHaveBeenCalled();
  });

  it('warns over a store that implements only half of the conditional write', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const memory = new MemoryStatusListStorage();
    const half = Object.assign(plainStore(), {
      getStatusListWithEtag: (statusListId: string) => memory.getStatusListWithEtag(statusListId),
    });

    new StatusList2021Manager(half, identity, sign);

    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('StatusList2021Manager over a store with the conditional write', () => {
  it('does not warn', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    new StatusList2021Manager(new MemoryStatusListStorage(), identity, sign);
    createStatusListManager(new MemoryStatusListStorage(), identity, sign);
    expect(warn).not.toHaveBeenCalled();
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
});
