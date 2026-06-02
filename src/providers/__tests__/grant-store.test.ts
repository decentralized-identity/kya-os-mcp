import { describe, it, expect } from 'vitest';
import { MemoryGrantStore, type Grant } from '../grant-store.js';

/**
 * GrantStore is the provider seam for an approved authorization grant — the
 * post-approval, durable counterpart to the pending ResumeTokenStore. A grant
 * binds to the agent DID (durable authority) and optionally to a session (the
 * confused-deputy-safe, no-paste retry convenience). The memory implementation
 * is the dev/reference impl; production injects Redis / a Durable Object /
 * Postgres behind the same interface.
 */

function grant(over: Partial<Grant> = {}): Grant {
  return {
    id: over.id ?? 'grant-1',
    agentDid: over.agentDid ?? 'did:key:zAgentA',
    scopes: over.scopes ?? ['vault:read'],
    issuedAt: over.issuedAt ?? 1_000,
    status: over.status ?? 'active',
    ...over,
  };
}

describe('MemoryGrantStore', () => {
  it('binds a grant and finds it by agent DID', async () => {
    const store = new MemoryGrantStore();
    await store.bind(grant({ agentDid: 'did:key:zAgentA' }));
    const found = await store.getByAgent('did:key:zAgentA');
    expect(found).toHaveLength(1);
    expect(found[0]?.scopes).toContain('vault:read');
  });

  it('returns no grants for an agent that has none', async () => {
    const store = new MemoryGrantStore();
    await store.bind(grant({ agentDid: 'did:key:zAgentA' }));
    expect(await store.getByAgent('did:key:zAgentB')).toEqual([]);
  });

  it('binds to a session and resolves by session — the no-paste retry path', async () => {
    const store = new MemoryGrantStore();
    await store.bind(grant({ sessionId: 'sess-1' }));
    const found = await store.getBySession('sess-1');
    expect(found).toHaveLength(1);
  });

  it('does NOT return one session\'s grant to another session (confused-deputy guard)', async () => {
    const store = new MemoryGrantStore();
    await store.bind(grant({ sessionId: 'sess-A', agentDid: 'did:key:zAgentA' }));
    expect(await store.getBySession('sess-A')).toHaveLength(1);
    expect(await store.getBySession('sess-B')).toEqual([]);
  });

  it('soft-revokes (status + reason) without deleting the record', async () => {
    const store = new MemoryGrantStore();
    await store.bind(grant({ id: 'g1', agentDid: 'did:key:zAgentA' }));
    await store.revoke('g1', 'user logged out');
    // A revoked grant is not returned from active lookups.
    expect(await store.getByAgent('did:key:zAgentA')).toEqual([]);
    // But the record is retained (soft revoke) and reflects the reason.
    const record = await store.getById('g1');
    expect(record?.status).toBe('revoked');
    expect(record?.revocationReason).toBe('user logged out');
  });

  it('treats an expired grant as inactive', async () => {
    const store = new MemoryGrantStore({ now: () => 5_000 });
    await store.bind(grant({ agentDid: 'did:key:zAgentA', expiresAt: 4_000 }));
    expect(await store.getByAgent('did:key:zAgentA')).toEqual([]);
  });

  it('cleanup removes expired records', async () => {
    let t = 1_000;
    const store = new MemoryGrantStore({ now: () => t });
    await store.bind(grant({ id: 'g1', expiresAt: 2_000 }));
    t = 3_000;
    await store.cleanup();
    expect(await store.getById('g1')).toBeUndefined();
  });

  it('optionally narrows a session lookup by required scopes', async () => {
    const store = new MemoryGrantStore();
    await store.bind(grant({ sessionId: 'sess-1', scopes: ['vault:read'] }));
    expect(await store.getBySession('sess-1', ['vault:read'])).toHaveLength(1);
    expect(await store.getBySession('sess-1', ['vault:write'])).toEqual([]);
  });
});
