/**
 * A built-in resolver's cache holds at most 128 documents and 8 MiB of compact JSON, each for its
 * TTL, and evicts the least recently used entry first. It holds documents the walk froze, so a hit
 * is served as stored. Concurrent resolutions of one DID share one load until the resolution
 * deadline passes; a load still pending then is dropped, so the next resolution starts a fresh one.
 */

import { describe, it, expect, vi } from 'vitest';
import { DidDocumentCache, type LoadedDidDocument } from '../did-document-cache.js';
import { DID_RESOLUTION_TIMEOUT_MS, MAX_DID_DOCUMENT_BYTES as MiB } from '../did-resource-policy.js';
import type { DIDDocument } from '../vc-verifier.types.js';

const TTL = 60_000;
const document = (id: string): DIDDocument => ({ id: `did:web:${id}.example` });

/** A cache holding `keys`, least recently used first, each charged `bytes`. */
function holding(keys: string[], bytes: number): DidDocumentCache {
  const cache = new DidDocumentCache();
  for (const key of keys) cache.set(key, document(key), bytes, TTL);
  return cache;
}

/** Which of `keys` `cache` still holds, without a lookup changing their order of use. */
function held(cache: DidDocumentCache, keys: string[]): string[] {
  const entries = (cache as unknown as { entries: Map<string, unknown> }).entries;
  return keys.filter(key => entries.has(key));
}

const keys = (prefix: string, count: number) => Array.from({ length: count }, (_, i) => `${prefix}${i}`);

describe('DidDocumentCache', () => {
  it('holds exactly 8 MiB, and stores nothing for a size that is not a whole number of bytes up to 1 MiB', () => {
    const full = holding(keys('full-', 8), MiB);
    expect(held(full, keys('full-', 8))).toEqual(keys('full-', 8));
    const cache = new DidDocumentCache();
    for (const bytes of [MiB + 1, -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      cache.set('x', document('x'), bytes, TTL);
      expect(cache.get('x')).toBeUndefined();
    }
  });

  it('holds 128 documents, and evicts the least recently used for the 129th', () => {
    const cache = holding(keys('d', 128), 100);
    expect(cache.get('d0')).toEqual(document('d0'));
    cache.set('new', document('new'), 100, TTL);
    expect(held(cache, ['d0', 'd1', 'd2', 'new'])).toEqual(['d0', 'd2', 'new']);
  });

  it('evicts as many least recently used entries as a new one needs, in order of use', () => {
    const cache = holding(keys('half-', 16), MiB / 2);
    cache.get('half-0');
    cache.get('half-1');
    cache.set('big', document('big'), MiB, TTL);
    expect(held(cache, [...keys('half-', 16), 'big'])).toEqual(['half-0', 'half-1', ...keys('half-', 16).slice(4), 'big']);
  });

  it('charges a DID set again once, at its new size', () => {
    const cache = holding(keys('full-', 7), MiB);
    for (const bytes of [MiB, 1, MiB]) cache.set('again', document('again'), bytes, TTL);
    expect(held(cache, [...keys('full-', 7), 'again'])).toEqual([...keys('full-', 7), 'again']);
    cache.set('one-more', document('one-more'), 1, TTL);
    expect(held(cache, ['full-0', 'full-1', 'one-more'])).toEqual(['full-1', 'one-more']);
  });

  it('serves a hit as stored, and nothing after its TTL', () => {
    const cache = new DidDocumentCache();
    const stored = Object.freeze(document('frozen'));
    cache.set('frozen', stored, 10, TTL);
    expect(cache.get('frozen')).toBe(stored);
    cache.set('expired', document('expired'), 1, -1);
    expect(cache.get('expired')).toBeUndefined();
    cache.set('invalid-ttl', document('invalid-ttl'), 1, Number.NaN);
    expect(cache.get('invalid-ttl')).toBeUndefined();
  });

  it('releases the bytes of an entry that expired when a lookup finds it, so it keeps storing new documents', () => {
    vi.useFakeTimers();
    try {
      const cache = new DidDocumentCache();
      for (const key of keys('old-', 8)) cache.set(key, document(key), MiB, 1_000);
      vi.advanceTimersByTime(1_000);
      for (const key of keys('old-', 8)) expect(cache.get(key)).toBeUndefined();
      for (const key of keys('new-', 8)) cache.set(key, document(key), MiB, TTL);
      expect(held(cache, keys('new-', 8))).toEqual(keys('new-', 8));
    } finally { vi.useRealTimers(); }
  });

  it('gives concurrent resolutions of one DID one load, and caches what it loaded', async () => {
    const cache = new DidDocumentCache();
    let finish!: (loaded: LoadedDidDocument | null) => void;
    const load = vi.fn(() => new Promise<LoadedDidDocument | null>(resolve => { finish = resolve; }));
    const resolving = Array.from({ length: 50 }, () => cache.resolve('one', TTL, load));
    expect(load).toHaveBeenCalledOnce();
    finish({ document: document('one'), bytes: 10 });
    expect(await Promise.all(resolving)).toEqual(Array(50).fill(document('one')));
    expect(await cache.resolve('one', TTL, load)).toEqual(document('one'));
    expect(load).toHaveBeenCalledOnce();
  });

  it('caches nothing for a failed load, nor for a load pending across a clear', async () => {
    const cache = new DidDocumentCache();
    expect(await cache.resolve('failed', TTL, async () => null)).toBeNull();
    expect(cache.get('failed')).toBeUndefined();
    let finish!: (loaded: LoadedDidDocument | null) => void;
    const pending = cache.resolve('cleared', TTL, () => new Promise(resolve => { finish = resolve; }));
    cache.clear();
    finish({ document: document('cleared'), bytes: 10 });
    expect(await pending).toEqual(document('cleared'));
    expect(cache.get('cleared')).toBeUndefined();
  });

  it('caches nothing for a load pending across a delete of its DID, and starts the next resolution afresh', async () => {
    const cache = new DidDocumentCache();
    const finishers: ((loaded: LoadedDidDocument | null) => void)[] = [];
    const load = vi.fn(() => new Promise<LoadedDidDocument | null>(resolve => { finishers.push(resolve); }));
    const stale = cache.resolve('deleted', TTL, load);
    const other = cache.resolve('kept', TTL, load);
    cache.delete('deleted');
    const fresh = cache.resolve('deleted', TTL, load);
    expect(load).toHaveBeenCalledTimes(3);
    finishers[0]!({ document: { ...document('deleted'), stale: true } as DIDDocument, bytes: 10 });
    finishers[1]!({ document: document('kept'), bytes: 10 });
    expect(await stale).toMatchObject({ stale: true });
    expect(cache.get('deleted')).toBeUndefined();
    finishers[2]!({ document: document('deleted'), bytes: 10 });
    expect(await fresh).toEqual(document('deleted'));
    expect(await other).toEqual(document('kept'));
    expect([cache.get('deleted'), cache.get('kept')]).toEqual([document('deleted'), document('kept')]);
  });

  it('shares a load until the resolution deadline, then starts the next resolution afresh, and caches nothing the dropped load returns', async () => {
    vi.useFakeTimers();
    try {
      const cache = new DidDocumentCache();
      let finishHung!: (loaded: LoadedDidDocument | null) => void;
      const hung = vi.fn(() => new Promise<LoadedDidDocument | null>(resolve => { finishHung = resolve; }));
      const fresh = vi.fn(async () => ({ document: document('fresh'), bytes: 10 }));
      void cache.resolve('slow', TTL, hung);
      await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS - 1);
      void cache.resolve('slow', TTL, fresh);
      expect([hung.mock.calls.length, fresh.mock.calls.length]).toEqual([1, 0]);
      await vi.advanceTimersByTimeAsync(1);
      const afresh = cache.resolve('slow', TTL, fresh);
      expect([hung.mock.calls.length, fresh.mock.calls.length]).toEqual([1, 1]);
      expect(await afresh).toEqual(document('fresh'));
      finishHung({ document: { ...document('slow'), stale: true } as DIDDocument, bytes: 10 });
      await vi.advanceTimersByTimeAsync(0);
      expect(cache.get('slow')).toEqual(document('fresh'));
    } finally { vi.useRealTimers(); }
  });

  it('leaves no timer behind once a load settles, found or not', async () => {
    vi.useFakeTimers();
    try {
      const cache = new DidDocumentCache();
      expect(await cache.resolve('found', TTL, async () => ({ document: document('found'), bytes: 10 }))).toEqual(document('found'));
      expect(await cache.resolve('missing', TTL, async () => null)).toBeNull();
      await expect(cache.resolve('failed', TTL, async () => { throw new Error('offline'); })).rejects.toThrow('offline');
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });
});
