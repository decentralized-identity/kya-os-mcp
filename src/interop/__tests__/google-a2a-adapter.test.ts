import { fromGoogleA2A, toGoogleA2A } from '../google-a2a-adapter.js';
import type { GoogleA2AEnvelope } from '../a2a-types.js';

function validEnvelope(): GoogleA2AEnvelope {
  return {
    agentCard: { name: 'Acme Planner', provider: { organization: 'Acme' } },
    message: { role: 'agent', messageId: 'msg-1' },
    delegation: {
      id: 'del-123',
      issuer: 'did:web:issuer.example',
      subject: 'did:web:agent.example',
      scopes: ['calendar.read', 'calendar.write'],
    },
  };
}

describe('fromGoogleA2A', () => {
  it('decodes a valid envelope into a DelegationRecord', () => {
    const res = fromGoogleA2A(validEnvelope());
    expect(res.success).toBe(true);
    const record = res.record!;
    expect(record.id).toBe('del-123');
    expect(record.issuerDid).toBe('did:web:issuer.example');
    expect(record.subjectDid).toBe('did:web:agent.example');
    expect(record.vcId).toBe('urn:uuid:del-123');
    expect(record.constraints.scopes).toEqual(['calendar.read', 'calendar.write']);
    expect(record.status).toBe('active');
    expect(record.metadata?.sourceFormat).toBe('google-a2a');
  });

  it('carries the delegation signature as an opaque passthrough', () => {
    const env = validEnvelope();
    env.delegation!.signature = 'opaque-sig-value';
    const res = fromGoogleA2A(env);
    expect(res.record!.signature).toBe('opaque-sig-value');
  });

  it('defaults signature to empty string when absent', () => {
    const res = fromGoogleA2A(validEnvelope());
    expect(res.record!.signature).toBe('');
  });

  it('maps parent to parentId when present and omits it otherwise', () => {
    const withParent = validEnvelope();
    withParent.delegation!.parent = 'del-parent';
    expect(fromGoogleA2A(withParent).record!.parentId).toBe('del-parent');
    expect('parentId' in fromGoogleA2A(validEnvelope()).record!).toBe(false);
  });

  it('preserves notBefore/notAfter into constraints', () => {
    const env = validEnvelope();
    env.delegation!.notBefore = 1000;
    env.delegation!.notAfter = 2000;
    const c = fromGoogleA2A(env).record!.constraints;
    expect(c.notBefore).toBe(1000);
    expect(c.notAfter).toBe(2000);
  });

  it('rejects (never throws) when delegation is missing', () => {
    const res = fromGoogleA2A({ message: { messageId: 'm' } });
    expect(res.success).toBe(false);
    expect(res.error?.message).toMatch(/delegation/i);
    expect(res.record).toBeUndefined();
  });

  it('rejects when delegation is a non-object', () => {
    const res = fromGoogleA2A({ delegation: 'nope' } as unknown as GoogleA2AEnvelope);
    expect(res.success).toBe(false);
  });

  it('rejects (never throws) a non-object envelope', () => {
    expect(() => fromGoogleA2A(42 as unknown as GoogleA2AEnvelope)).not.toThrow();
    expect(fromGoogleA2A(42 as unknown as GoogleA2AEnvelope).success).toBe(false);
    expect(fromGoogleA2A(null as unknown as GoogleA2AEnvelope).success).toBe(false);
  });

  it('rejects when issuer is missing', () => {
    const env = validEnvelope();
    delete env.delegation!.issuer;
    const res = fromGoogleA2A(env);
    expect(res.success).toBe(false);
    expect(res.error?.message).toMatch(/issuer/i);
  });

  it('rejects when subject is missing', () => {
    const env = validEnvelope();
    delete env.delegation!.subject;
    const res = fromGoogleA2A(env);
    expect(res.success).toBe(false);
    expect(res.error?.message).toMatch(/subject/i);
  });

  it('falls back to messageId then taskId for a stable id', () => {
    const fromMsg = fromGoogleA2A({
      message: { messageId: 'msg-9' },
      delegation: { issuer: 'did:web:i', subject: 'did:web:s' },
    });
    expect(fromMsg.success).toBe(true);
    expect(fromMsg.record!.id).toBe('msg-9');

    const fromTask = fromGoogleA2A({
      message: { taskId: 'task-9' },
      delegation: { issuer: 'did:web:i', subject: 'did:web:s' },
    });
    expect(fromTask.record!.id).toBe('task-9');
  });

  it('rejects when no stable id exists (no silent random id)', () => {
    const res = fromGoogleA2A({
      delegation: { issuer: 'did:web:i', subject: 'did:web:s' },
    });
    expect(res.success).toBe(false);
    expect(res.error?.message).toMatch(/id/i);
  });

  it('preserves a string audience', () => {
    const env = validEnvelope();
    env.delegation!.audience = 'did:web:resource.example';
    expect(fromGoogleA2A(env).record!.constraints.audience).toBe('did:web:resource.example');
  });

  it('preserves a string[] audience', () => {
    const env = validEnvelope();
    env.delegation!.audience = ['did:web:a', 'did:web:b'];
    expect(fromGoogleA2A(env).record!.constraints.audience).toEqual(['did:web:a', 'did:web:b']);
  });

  it('defaults scopes to an empty array when none are supplied', () => {
    const res = fromGoogleA2A({
      delegation: { id: 'd', issuer: 'did:web:i', subject: 'did:web:s' },
    });
    expect(res.record!.constraints.scopes).toEqual([]);
  });
});

describe('toGoogleA2A', () => {
  it('reconstructs the delegation block from a record', () => {
    const record = fromGoogleA2A(validEnvelope()).record!;
    const res = toGoogleA2A(record);
    expect(res.success).toBe(true);
    const del = res.envelope!.delegation!;
    expect(del.id).toBe('del-123');
    expect(del.issuer).toBe('did:web:issuer.example');
    expect(del.subject).toBe('did:web:agent.example');
    expect(del.scopes).toEqual(['calendar.read', 'calendar.write']);
  });

  it('reconstructs a minimal agentCard from metadata provenance', () => {
    const record = fromGoogleA2A(validEnvelope()).record!;
    const env = toGoogleA2A(record).envelope!;
    expect(env.agentCard?.name).toBe('Acme Planner');
  });

  it('rejects (never throws) a structurally-invalid record', () => {
    const res = toGoogleA2A({ id: '', issuerDid: '', subjectDid: '' } as never);
    expect(res.success).toBe(false);
    expect(res.envelope).toBeUndefined();
  });

  it('rejects (never throws) a non-object record', () => {
    expect(() => toGoogleA2A(42 as never)).not.toThrow();
    expect(toGoogleA2A(42 as never).success).toBe(false);
  });
});

describe('security: prototype pollution', () => {
  it('does not pollute Object.prototype and does not throw on __proto__-shaped input', () => {
    const malicious = JSON.parse(
      '{"delegation":{"id":"x","issuer":"did:web:i","subject":"did:web:s","__proto__":{"polluted":true}},"__proto__":{"polluted":true}}',
    ) as GoogleA2AEnvelope;
    expect(() => fromGoogleA2A(malicious)).not.toThrow();
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('does not pollute via a constructor-shaped key and does not throw', () => {
    const malicious = JSON.parse(
      '{"delegation":{"id":"x","issuer":"did:web:i","subject":"did:web:s","constructor":{"prototype":{"polluted":true}}}}',
    ) as GoogleA2AEnvelope;
    expect(() => fromGoogleA2A(malicious)).not.toThrow();
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});
