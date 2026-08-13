import { describe, it, expect } from 'vitest';
import { TtlCache } from '../ttl-cache.js';

describe('TtlCache', () => {
  it('serves an unexpired value and deletes an expired one on read', async () => {
    const cache = new TtlCache<string>({ ttlMs: 10, maxEntries: 10 });
    cache.set('k', 'v');
    expect(cache.get('k')).toBe('v');
    await new Promise((r) => setTimeout(r, 15));
    expect(cache.get('k')).toBeUndefined();
  });

  it('ttlMs <= 0 disables storage entirely', () => {
    const cache = new TtlCache<string>({ ttlMs: 0, maxEntries: 10 });
    cache.set('k', 'v');
    expect(cache.get('k')).toBeUndefined();
  });

  it('evicts the oldest entry at maxEntries (FIFO)', () => {
    const cache = new TtlCache<number>({ ttlMs: 60_000, maxEntries: 2 });
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    expect(cache.get('a')).toBeUndefined();
    expect(cache.get('b')).toBe(2);
    expect(cache.get('c')).toBe(3);
  });

  it('overwriting a key keeps order coherent — refresh survives, oldest neighbor evicts', () => {
    const cache = new TtlCache<number>({ ttlMs: 60_000, maxEntries: 2 });
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('a', 3); // refresh: delete + re-insert as newest, no phantom order entry
    cache.set('c', 4); // full → evicts 'b' (now the oldest), never the refreshed 'a'
    expect(cache.get('a')).toBe(3);
    expect(cache.get('c')).toBe(4);
    expect(cache.get('b')).toBeUndefined();
  });

  it('repeated overwrites of one key never evict below capacity', () => {
    const cache = new TtlCache<number>({ ttlMs: 60_000, maxEntries: 2 });
    cache.set('k', 1);
    for (let i = 0; i < 100; i++) cache.set('k', i); // concurrent-miss shape: same key, many sets
    cache.set('other', 7);
    expect(cache.get('k')).toBe(99);
    expect(cache.get('other')).toBe(7); // no phantom 'k' entries to mis-evict against
  });

  it('maxEntries <= 0 disables storage (parity with ttlMs)', () => {
    const cache = new TtlCache<string>({ ttlMs: 60_000, maxEntries: 0 });
    cache.set('k', 'v');
    expect(cache.get('k')).toBeUndefined();
  });

  it('deleteWhere removes matching keys only', () => {
    const cache = new TtlCache<number>({ ttlMs: 60_000, maxEntries: 10 });
    cache.set('di id-1 x', 1);
    cache.set('jwt id-1 y', 2);
    cache.set('di id-2 z', 3);
    cache.deleteWhere((key) => key.includes('id-1'));
    expect(cache.get('di id-1 x')).toBeUndefined();
    expect(cache.get('jwt id-1 y')).toBeUndefined();
    expect(cache.get('di id-2 z')).toBe(3);
  });
});
