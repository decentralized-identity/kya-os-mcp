import { describe, it, expect } from 'vitest';
import { MemoryPendingFlowStore, type PendingFlow } from '../pending-flow-store.js';

/**
 * MemoryPendingFlowStore is the dev/reference impl of the PKCE pending-flow
 * seam. `get` is non-consuming (pre-exchange validation); `delete` consumes
 * after a successful exchange — kept separate so a transient IdP error never
 * burns the resume token. TTL expiry uses an injectable clock (mirrors
 * MemoryGrantStore's test structure).
 */

function flow(over: Partial<PendingFlow> = {}): PendingFlow {
  return {
    agentDid: over.agentDid ?? 'did:key:zAgent',
    scopes: over.scopes ?? ['vault:read'],
    state: over.state ?? 'state-1',
    codeVerifier: over.codeVerifier ?? 'verifier-1',
    redirectUri: over.redirectUri ?? 'https://app.example/cb',
    ...over,
  };
}

describe('MemoryPendingFlowStore', () => {
  it('put then get returns the flow without consuming it', async () => {
    const store = new MemoryPendingFlowStore();
    await store.put('tok', flow({ codeVerifier: 'v1' }), 60_000);
    expect((await store.get('tok'))?.codeVerifier).toBe('v1');
    // Non-consuming: a second get still returns it.
    expect(await store.get('tok')).toBeDefined();
  });

  it('get returns undefined for an unknown token', async () => {
    const store = new MemoryPendingFlowStore();
    expect(await store.get('never-issued')).toBeUndefined();
  });

  it('delete consumes the flow (one-time use after exchange)', async () => {
    const store = new MemoryPendingFlowStore();
    await store.put('tok', flow(), 60_000);
    await store.delete('tok');
    expect(await store.get('tok')).toBeUndefined();
  });

  it('consume atomically returns the flow then removes it (one-time use)', async () => {
    const store = new MemoryPendingFlowStore();
    await store.put('tok', flow({ codeVerifier: 'v1' }), 60_000);
    expect((await store.consume('tok'))?.codeVerifier).toBe('v1');
    // Gone afterward — a second consume (or get) sees nothing.
    expect(await store.consume('tok')).toBeUndefined();
    expect(await store.get('tok')).toBeUndefined();
  });

  it('consume returns undefined for an unknown or expired token', async () => {
    let t = 1_000;
    const store = new MemoryPendingFlowStore({ now: () => t });
    expect(await store.consume('nope')).toBeUndefined();
    await store.put('tok', flow(), 1_000); // expires at 2_000
    t = 2_001;
    expect(await store.consume('tok')).toBeUndefined();
  });

  it('expires a flow past its TTL (injected clock)', async () => {
    let t = 1_000;
    const store = new MemoryPendingFlowStore({ now: () => t });
    await store.put('tok', flow(), 5_000); // expires at 6_000
    t = 6_001;
    expect(await store.get('tok')).toBeUndefined();
  });

  it('cleanup drops only expired flows', async () => {
    let t = 1_000;
    const store = new MemoryPendingFlowStore({ now: () => t });
    await store.put('a', flow(), 1_000); // expires 2_000
    await store.put('b', flow(), 10_000); // expires 11_000
    t = 3_000;
    await store.cleanup();
    expect(await store.get('a')).toBeUndefined();
    expect(await store.get('b')).toBeDefined();
  });

  it('returns a copy — mutating the result does not corrupt the store', async () => {
    const store = new MemoryPendingFlowStore();
    await store.put('tok', flow({ codeVerifier: 'v1' }), 60_000);
    const got = await store.get('tok');
    if (got) got.codeVerifier = 'tampered';
    expect((await store.get('tok'))?.codeVerifier).toBe('v1');
  });
});
