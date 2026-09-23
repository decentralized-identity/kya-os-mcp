import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  admitNonce,
  checkNonceStore,
  type NonceAdmissionStore,
} from '../../providers/nonce-admission.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { logger } from '../../logging/index.js';

/** A store written before consume() existed: sequential has/add over a Map. */
function legacyStore(): NonceAdmissionStore & { has: ReturnType<typeof vi.fn>; add: ReturnType<typeof vi.fn> } {
  const seen = new Set<string>();
  return {
    has: vi.fn(async (nonce: string, did?: string) => seen.has(`${did}\0${nonce}`)),
    add: vi.fn(async (nonce: string, _ttl: number, did?: string) => { seen.add(`${did}\0${nonce}`); }),
  };
}

afterEach(() => vi.restoreAllMocks());

describe('admitNonce', () => {
  it('uses consume when present and never touches has/add', async () => {
    const store = new MemoryNonceCacheProvider();
    const has = vi.spyOn(store, 'has');
    const add = vi.spyOn(store, 'add');
    expect(await admitNonce(store, 'n', 60, 'did:key:zA')).toBe(true);
    expect(await admitNonce(store, 'n', 60, 'did:key:zA')).toBe(false);
    expect(has).not.toHaveBeenCalled();
    expect(add).not.toHaveBeenCalled();
  });

  it('admits concurrent duplicates exactly once through an atomic consume', async () => {
    const store = new MemoryNonceCacheProvider();
    const results = await Promise.all(Array.from({ length: 6 }, () => admitNonce(store, 'n', 60, 'did:key:zA')));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('treats any consume result other than literal true as a replay', async () => {
    const store = { ...legacyStore(), consume: vi.fn().mockResolvedValue('OK') } as unknown as NonceAdmissionStore;
    expect(await admitNonce(store, 'n', 60)).toBe(false);
  });

  it('falls back to has then add without consume, rejecting a sequential replay', async () => {
    const store = legacyStore();
    expect(await admitNonce(store, 'n', 60, 'did:key:zA')).toBe(true);
    expect(await admitNonce(store, 'n', 60, 'did:key:zA')).toBe(false);
    expect(store.add).toHaveBeenCalledOnce();
    expect(store.add).toHaveBeenCalledWith('n', 60, 'did:key:zA');
  });

  it('warns once per store about the non-atomic fallback', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const first = legacyStore();
    checkNonceStore(first);
    await admitNonce(first, 'a', 60);
    await admitNonce(first, 'b', 60);
    await admitNonce(legacyStore(), 'a', 60);
    expect(warn).toHaveBeenCalledTimes(2);
    expect(String(warn.mock.calls[0]?.[0])).toContain('no atomic consume()');
  });

  it('refuses the fallback under requireAtomicNonce without touching the store', async () => {
    const store = legacyStore();
    await expect(admitNonce(store, 'n', 60, undefined, { requireAtomicNonce: true })).rejects.toThrow('requireAtomicNonce');
    expect(store.has).not.toHaveBeenCalled();
    expect(store.add).not.toHaveBeenCalled();
  });

  it('propagates storage failures so callers deny', async () => {
    const store = { ...legacyStore(), consume: vi.fn().mockRejectedValue(new Error('storage down')) };
    await expect(admitNonce(store, 'n', 60)).rejects.toThrow('storage down');
  });
});

describe('checkNonceStore', () => {
  it('accepts an atomic store silently, even under requireAtomicNonce', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    expect(() => checkNonceStore(new MemoryNonceCacheProvider(), { requireAtomicNonce: true })).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it('refuses a store without consume under requireAtomicNonce, without warning', () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    expect(() => checkNonceStore(legacyStore(), { requireAtomicNonce: true })).toThrow(TypeError);
    expect(warn).not.toHaveBeenCalled();
  });
});
