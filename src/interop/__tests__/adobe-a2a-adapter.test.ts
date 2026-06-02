import { fromAdobeA2A, toAdobeA2A } from '../adobe-a2a-adapter.js';
import { matchScope } from '../../delegation/scope-matcher.js';
import type { AdobeA2AEnvelope } from '../a2a-types.js';

function validEnvelope(): AdobeA2AEnvelope {
  return {
    protocol: 'adobe-a2a',
    version: '1.0',
    from: { did: 'did:web:issuer.example', org: 'Acme' },
    to: { did: 'did:web:agent.example', agentId: 'agent-7' },
    authorization: {
      delegationId: 'del-abc',
      grants: [{ resource: 'calendar.read', match: 'exact' }],
      audience: 'did:web:resource.example',
    },
    signature: 'opaque-sig',
  };
}

describe('fromAdobeA2A', () => {
  it('decodes a valid envelope, mapping from.did/to.did to issuer/subject', () => {
    const res = fromAdobeA2A(validEnvelope());
    expect(res.success).toBe(true);
    const record = res.record!;
    expect(record.id).toBe('del-abc');
    expect(record.issuerDid).toBe('did:web:issuer.example');
    expect(record.subjectDid).toBe('did:web:agent.example');
    expect(record.signature).toBe('opaque-sig');
    expect(record.status).toBe('active');
    expect(record.metadata?.sourceFormat).toBe('adobe-a2a');
  });

  it('maps parentId, audience, and validFrom/validUntil into the record', () => {
    const env = validEnvelope();
    env.authorization!.parentId = 'del-parent';
    env.authorization!.validFrom = 1000;
    env.authorization!.validUntil = 2000;
    const record = fromAdobeA2A(env).record!;
    expect(record.parentId).toBe('del-parent');
    expect(record.constraints.audience).toBe('did:web:resource.example');
    expect(record.constraints.notBefore).toBe(1000);
    expect(record.constraints.notAfter).toBe(2000);
  });

  it('maps an exact grant (or a match-less grant) into flat constraints.scopes', () => {
    const env = validEnvelope();
    env.authorization!.grants = [
      { resource: 'calendar.read', match: 'exact' },
      { resource: 'calendar.write' }, // absent match defaults to exact
    ];
    const res = fromAdobeA2A(env);
    expect(res.record!.constraints.scopes).toEqual(['calendar.read', 'calendar.write']);
    expect(res.record!.constraints.crisp).toBeUndefined();
    expect(res.warnings ?? []).toEqual([]);
  });

  it('maps a prefix grant into constraints.crisp.scopes with the matcher preserved + a warning', () => {
    const env = validEnvelope();
    env.authorization!.grants = [{ resource: 'files/', match: 'prefix' }];
    const res = fromAdobeA2A(env);
    expect(res.record!.constraints.scopes).toEqual([]);
    expect(res.record!.constraints.crisp!.scopes).toEqual([{ resource: 'files/', matcher: 'prefix' }]);
    expect(res.warnings?.length).toBeGreaterThan(0);
    expect(res.warnings!.join(' ')).toMatch(/non-exact|prefix/i);
  });

  it('maps a regex grant into constraints.crisp.scopes with the matcher preserved', () => {
    const env = validEnvelope();
    env.authorization!.grants = [{ resource: 'docs/.*', match: 'regex' }];
    const res = fromAdobeA2A(env);
    expect(res.record!.constraints.crisp!.scopes).toEqual([{ resource: 'docs/.*', matcher: 'regex' }]);
    expect(res.warnings?.length).toBeGreaterThan(0);
  });

  it('rejects (never throws) when authorization is missing', () => {
    const res = fromAdobeA2A({ from: { did: 'a' }, to: { did: 'b' } });
    expect(res.success).toBe(false);
    expect(res.error?.message).toMatch(/authorization/i);
  });

  it('rejects when from.did is missing', () => {
    const env = validEnvelope();
    delete env.from!.did;
    expect(fromAdobeA2A(env).success).toBe(false);
  });

  it('rejects when to.did is missing', () => {
    const env = validEnvelope();
    delete env.to!.did;
    expect(fromAdobeA2A(env).success).toBe(false);
  });

  it('rejects when delegationId is missing (no silent random id)', () => {
    const env = validEnvelope();
    delete env.authorization!.delegationId;
    const res = fromAdobeA2A(env);
    expect(res.success).toBe(false);
    expect(res.error?.message).toMatch(/id/i);
  });

  it('does not throw on a non-object envelope', () => {
    expect(() => fromAdobeA2A(42 as unknown as AdobeA2AEnvelope)).not.toThrow();
    expect(fromAdobeA2A(42 as unknown as AdobeA2AEnvelope).success).toBe(false);
  });
});

describe('security: ReDoS-adjacent', () => {
  it('carries a catastrophic-backtracking resource as data only — never executes it', () => {
    const env: AdobeA2AEnvelope = {
      from: { did: 'did:web:i' },
      to: { did: 'did:web:s' },
      authorization: {
        delegationId: 'd',
        grants: [{ resource: '(a+)+$', match: 'regex' }],
      },
    };
    const start = performance.now();
    const res = fromAdobeA2A(env);
    const elapsed = performance.now() - start;

    expect(res.success).toBe(true);
    expect(elapsed).toBeLessThan(50);

    const cs = res.record!.constraints.crisp!.scopes[0]!;
    expect(cs.resource).toBe('(a+)+$');
    expect(cs.matcher).toBe('regex');

    // The structured-scope contract: the produced CrispScope feeds matchScope
    // safely (the matcher rejects nested-quantifier shapes) — no hang, no throw.
    const t2 = performance.now();
    const matched = matchScope(cs.resource, cs.matcher, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!');
    expect(performance.now() - t2).toBeLessThan(50);
    expect(matched).toBe(false);
  });

  it('maps an unrecognized matcher to a flat exact scope (no widening, no crisp escalation)', () => {
    const env = {
      from: { did: 'did:web:i' },
      to: { did: 'did:web:s' },
      authorization: {
        delegationId: 'd',
        grants: [{ resource: 'safe.resource', match: 'glob-haxor' as unknown as 'exact' }],
      },
    } satisfies AdobeA2AEnvelope;
    const res = fromAdobeA2A(env);
    expect(res.success).toBe(true);
    expect(res.record!.constraints.scopes).toEqual(['safe.resource']);
    expect(res.record!.constraints.crisp).toBeUndefined();
    expect(res.warnings ?? []).toEqual([]);
  });

  it('does not pollute Object.prototype on __proto__-shaped grants', () => {
    const malicious = JSON.parse(
      '{"from":{"did":"a"},"to":{"did":"b"},"authorization":{"delegationId":"d","__proto__":{"polluted":true}}}',
    ) as AdobeA2AEnvelope;
    expect(() => fromAdobeA2A(malicious)).not.toThrow();
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});

describe('toAdobeA2A', () => {
  it('maps a flat scope back to an exact grant', () => {
    const record = fromAdobeA2A(validEnvelope()).record!;
    const res = toAdobeA2A(record);
    expect(res.success).toBe(true);
    expect(res.envelope!.authorization!.grants).toEqual([{ resource: 'calendar.read', match: 'exact' }]);
  });

  it('maps a crisp scope back to a grant preserving the matcher', () => {
    const env = validEnvelope();
    env.authorization!.grants = [{ resource: 'files/', match: 'prefix' }];
    const record = fromAdobeA2A(env).record!;
    const grants = toAdobeA2A(record).envelope!.authorization!.grants!;
    expect(grants).toContainEqual({ resource: 'files/', match: 'prefix' });
  });

  it('reconstructs from/to provenance from metadata', () => {
    const record = fromAdobeA2A(validEnvelope()).record!;
    const env = toAdobeA2A(record).envelope!;
    expect(env.from!.did).toBe('did:web:issuer.example');
    expect(env.to!.did).toBe('did:web:agent.example');
    expect(env.from!.org).toBe('Acme');
    expect(env.to!.agentId).toBe('agent-7');
  });

  it('rejects (never throws) a structurally-invalid record', () => {
    expect(() => toAdobeA2A({ id: '', issuerDid: '', subjectDid: '' } as never)).not.toThrow();
    expect(toAdobeA2A({ id: '', issuerDid: '', subjectDid: '' } as never).success).toBe(false);
  });

  it('rejects (never throws) a non-object record', () => {
    expect(() => toAdobeA2A(42 as never)).not.toThrow();
    expect(toAdobeA2A(42 as never).success).toBe(false);
  });

  it('skips a non-object or resource-less grant without throwing', () => {
    const env = validEnvelope();
    env.authorization!.grants = [
      null as unknown as { resource: string },
      { foo: 'bar' } as unknown as { resource: string },
      { resource: 'kept.scope', match: 'exact' },
    ];
    const res = fromAdobeA2A(env);
    expect(res.success).toBe(true);
    expect(res.record!.constraints.scopes).toEqual(['kept.scope']);
  });
});
