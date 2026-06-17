import { describe, it, expect } from 'vitest';
import { MemorySessionStore } from '../session-store.js';
import type { SessionContext } from '../../types/protocol.js';

/**
 * MemorySessionStore is the default, dev/reference impl of the optional
 * SessionStore seam. It must reproduce the prior in-Map behavior: get/set/
 * delete, an entries() snapshot for the manager's TTL sweep, insertion-order
 * eviction past maxSessions, and a synchronous best-effort size().
 */

function session(id: string, over: Partial<SessionContext> = {}): SessionContext {
  return {
    sessionId: id,
    audience: 'did:key:zServer',
    nonce: `nonce-${id}`,
    timestamp: 1000,
    createdAt: 1000,
    lastActivity: 1000,
    ttlMinutes: 30,
    identityState: 'anonymous',
    ...over,
  };
}

describe('MemorySessionStore', () => {
  it('set then get returns the session and counts it', async () => {
    const store = new MemorySessionStore();
    await store.set('s1', session('s1'));
    expect((await store.get('s1'))?.sessionId).toBe('s1');
    expect(store.size()).toBe(1);
  });

  it('get returns undefined for an unknown id', async () => {
    const store = new MemorySessionStore();
    expect(await store.get('nope')).toBeUndefined();
  });

  it('delete removes the session', async () => {
    const store = new MemorySessionStore();
    await store.set('s1', session('s1'));
    await store.delete('s1');
    expect(await store.get('s1')).toBeUndefined();
    expect(store.size()).toBe(0);
  });

  it('entries snapshots all sessions', async () => {
    const store = new MemorySessionStore();
    await store.set('s1', session('s1'));
    await store.set('s2', session('s2'));
    const ids = (await store.entries()).map(([id]) => id).sort();
    expect(ids).toEqual(['s1', 's2']);
  });

  it('clear removes everything', async () => {
    const store = new MemorySessionStore();
    await store.set('s1', session('s1'));
    await store.clear();
    expect(store.size()).toBe(0);
    expect(await store.entries()).toEqual([]);
  });

  it('evicts the oldest session past maxSessions (insertion order)', async () => {
    const store = new MemorySessionStore({ maxSessions: 2 });
    await store.set('s1', session('s1'));
    await store.set('s2', session('s2'));
    await store.set('s3', session('s3')); // evicts s1
    expect(await store.get('s1')).toBeUndefined();
    expect(await store.get('s2')).toBeDefined();
    expect(await store.get('s3')).toBeDefined();
    expect(store.size()).toBe(2);
  });

  it('updating an existing session neither double-counts nor evicts', async () => {
    const store = new MemorySessionStore({ maxSessions: 2 });
    await store.set('s1', session('s1'));
    await store.set('s1', session('s1', { lastActivity: 2000 })); // update, not new
    await store.set('s2', session('s2'));
    expect(await store.get('s1')).toBeDefined();
    expect(await store.get('s2')).toBeDefined();
    expect(store.size()).toBe(2);
  });

  it('cleanup compacts bookkeeping for deleted ids without resurrecting them', async () => {
    const store = new MemorySessionStore({ maxSessions: 2 });
    await store.set('s1', session('s1'));
    await store.delete('s1');
    await store.cleanup();
    await store.set('s2', session('s2'));
    await store.set('s3', session('s3'));
    expect(await store.get('s1')).toBeUndefined();
    expect(await store.get('s2')).toBeDefined();
    expect(await store.get('s3')).toBeDefined();
  });
});
