import { describe, expect, it, vi } from 'vitest';
import { LegacyAuditSinkAdapter } from '../adapters/legacy-audit-log.js';

const context = {
  identity: { did: 'did:key:zAgent', kid: 'did:key:zAgent#key' },
  session: { sessionId: 'secret-session', audience: 'did:web:server.example' },
  requestHash: `sha256:${'a'.repeat(64)}`,
  responseHash: `sha256:${'b'.repeat(64)}`,
  verified: 'yes' as const,
  scopeId: 'calendar:read',
};

describe('LegacyAuditSinkAdapter', () => {
  it('does not preserve legacy per-session deduplication', async () => {
    const record = vi.fn(async () => ({ status: 'pending' as const, event: {} as never }));
    const adapter = new LegacyAuditSinkAdapter({ record });
    await adapter.logAuditRecord(context);
    await adapter.logAuditRecord(context);
    expect(record).toHaveBeenCalledTimes(2);
    expect(adapter.capability).toBe('legacy-capture');
    expect(record.mock.calls[0]?.[0]).toMatchObject({
      actor: { kind: 'public_did' },
      resource: { kind: 'public_did' },
    });
  });

  it('accepts explicit pairwise classification when the caller knows the DID is pairwise', async () => {
    const record = vi.fn(async () => ({ status: 'pending' as const, event: {} as never }));
    const adapter = new LegacyAuditSinkAdapter({ record }, {
      identityKind: 'pairwise_did', resourceKind: 'pairwise_did',
    });
    await adapter.logAuditRecord(context);
    expect(record.mock.calls[0]?.[0]).toMatchObject({
      actor: { kind: 'pairwise_did' },
      resource: { kind: 'pairwise_did' },
    });
  });

  it('does not copy raw session identifiers or arbitrary legacy event data', async () => {
    const record = vi.fn(async () => ({ status: 'pending' as const, event: {} as never }));
    const adapter = new LegacyAuditSinkAdapter({ record });
    await adapter.logEvent({
      eventType: 'custom',
      identity: context.identity,
      session: context.session,
      eventData: { secret: 'do-not-copy' },
    });
    expect(JSON.stringify(record.mock.calls)).not.toContain('secret-session');
    expect(JSON.stringify(record.mock.calls)).not.toContain('do-not-copy');
  });
});
