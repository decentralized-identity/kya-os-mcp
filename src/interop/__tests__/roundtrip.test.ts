import { fromGoogleA2A, toGoogleA2A } from '../google-a2a-adapter.js';
import { fromAdobeA2A, toAdobeA2A } from '../adobe-a2a-adapter.js';
import { wrapDelegationAsVC, validateDelegationCredential } from '../../types/protocol.js';
import type { GoogleA2ADelegation, GoogleA2AEnvelope, AdobeA2AEnvelope, AdobeA2AGrant } from '../a2a-types.js';

// ---------------------------------------------------------------------------
// Normalizers — collapse re-derivable defaults so deep-equal compares semantics
// ---------------------------------------------------------------------------

function normGoogleDelegation(d: GoogleA2ADelegation): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: d.id,
    issuer: d.issuer,
    subject: d.subject,
    scopes: d.scopes ?? [],
    signature: d.signature ?? '',
  };
  if (d.parent !== undefined) out['parent'] = d.parent;
  if (d.audience !== undefined) out['audience'] = d.audience;
  if (d.notBefore !== undefined) out['notBefore'] = d.notBefore;
  if (d.notAfter !== undefined) out['notAfter'] = d.notAfter;
  return out;
}

function normGrants(grants: AdobeA2AGrant[] | undefined): AdobeA2AGrant[] {
  return [...(grants ?? [])]
    .map((g) => ({ resource: g.resource, match: g.match ?? 'exact' }))
    .sort((a, b) => a.resource.localeCompare(b.resource));
}

// ---------------------------------------------------------------------------
// Representative Google envelopes
// ---------------------------------------------------------------------------

const googleTable: Array<{ label: string; env: GoogleA2AEnvelope }> = [
  { label: 'no scopes', env: { delegation: { id: 'g1', issuer: 'did:web:i', subject: 'did:web:s' } } },
  { label: 'flat scopes', env: { delegation: { id: 'g2', issuer: 'did:web:i', subject: 'did:web:s', scopes: ['a', 'b'] } } },
  { label: 'audience string', env: { delegation: { id: 'g3', issuer: 'did:web:i', subject: 'did:web:s', scopes: ['a'], audience: 'did:web:r' } } },
  { label: 'audience array', env: { delegation: { id: 'g4', issuer: 'did:web:i', subject: 'did:web:s', audience: ['did:web:a', 'did:web:b'] } } },
  { label: 'parent / chain', env: { delegation: { id: 'g5', issuer: 'did:web:i', subject: 'did:web:s', parent: 'g-parent', scopes: ['x'] } } },
  { label: 'with metadata', env: { agentCard: { name: 'Planner', url: 'https://acme.example' }, delegation: { id: 'g6', issuer: 'did:web:i', subject: 'did:web:s' } } },
  { label: 'signature + window', env: { delegation: { id: 'g7', issuer: 'did:web:i', subject: 'did:web:s', signature: 'sig', notBefore: 1, notAfter: 2 } } },
];

describe('Google round-trip fidelity', () => {
  it.each(googleTable)('preserves the delegation block: $label', ({ env }) => {
    const record = fromGoogleA2A(env).record!;
    const back = toGoogleA2A(record).envelope!;
    expect(normGoogleDelegation(back.delegation!)).toEqual(normGoogleDelegation(env.delegation!));
  });

  it('round-trips the agentCard provenance', () => {
    const env = googleTable.find((t) => t.label === 'with metadata')!.env;
    const back = toGoogleA2A(fromGoogleA2A(env).record!).envelope!;
    expect(back.agentCard?.name).toBe('Planner');
    expect(back.agentCard?.url).toBe('https://acme.example');
  });
});

// ---------------------------------------------------------------------------
// Representative Adobe envelopes
// ---------------------------------------------------------------------------

function adobeEnv(authorization: AdobeA2AEnvelope['authorization']): AdobeA2AEnvelope {
  return { protocol: 'adobe-a2a', from: { did: 'did:web:i', org: 'Acme' }, to: { did: 'did:web:s', agentId: 'agent-1' }, authorization };
}

const adobeTable: Array<{ label: string; env: AdobeA2AEnvelope }> = [
  { label: 'no grants', env: adobeEnv({ delegationId: 'a1' }) },
  { label: 'exact grants', env: adobeEnv({ delegationId: 'a2', grants: [{ resource: 'r1', match: 'exact' }, { resource: 'r2' }] }) },
  { label: 'prefix grant', env: adobeEnv({ delegationId: 'a3', grants: [{ resource: 'files/', match: 'prefix' }] }) },
  { label: 'regex grant', env: adobeEnv({ delegationId: 'a4', grants: [{ resource: 'docs/.*', match: 'regex' }] }) },
  { label: 'mixed matchers', env: adobeEnv({ delegationId: 'a5', grants: [{ resource: 'x', match: 'exact' }, { resource: 'p/', match: 'prefix' }, { resource: 'q.*', match: 'regex' }] }) },
  { label: 'audience + window + parent', env: adobeEnv({ delegationId: 'a6', parentId: 'a-parent', grants: [{ resource: 'r', match: 'exact' }], audience: ['did:web:a', 'did:web:b'], validFrom: 10, validUntil: 20 }) },
];

describe('Adobe round-trip fidelity', () => {
  it.each(adobeTable)('preserves grant→scope→grant fidelity: $label', ({ env }) => {
    const record = fromAdobeA2A(env).record!;
    const back = toAdobeA2A(record).envelope!;
    expect(normGrants(back.authorization!.grants)).toEqual(normGrants(env.authorization!.grants));
  });

  it('preserves parent, audience, and validity window', () => {
    const env = adobeTable.find((t) => t.label === 'audience + window + parent')!.env;
    const back = toAdobeA2A(fromAdobeA2A(env).record!).envelope!;
    expect(back.authorization!.parentId).toBe('a-parent');
    expect(back.authorization!.audience).toEqual(['did:web:a', 'did:web:b']);
    expect(back.authorization!.validFrom).toBe(10);
    expect(back.authorization!.validUntil).toBe(20);
  });
});

// ---------------------------------------------------------------------------
// Cross-format acceptance oracle — a normalized foreign envelope is a valid
// native delegation credential.
// ---------------------------------------------------------------------------

describe('cross-format acceptance oracle', () => {
  it.each(googleTable)('Google → wrapDelegationAsVC → validate: $label', ({ env }) => {
    const record = fromGoogleA2A(env).record!;
    expect(validateDelegationCredential(wrapDelegationAsVC(record)).success).toBe(true);
  });

  it.each(adobeTable)('Adobe → wrapDelegationAsVC → validate: $label', ({ env }) => {
    const record = fromAdobeA2A(env).record!;
    expect(validateDelegationCredential(wrapDelegationAsVC(record)).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Cross-vendor equivalence — same authority via either vendor → same record.
// ---------------------------------------------------------------------------

describe('cross-vendor equivalence', () => {
  it('produces identical issuer/subject/scopes/audience regardless of vendor', () => {
    const google = fromGoogleA2A({
      delegation: { id: 'shared', issuer: 'did:web:i', subject: 'did:web:s', scopes: ['a', 'b'], audience: 'did:web:r' },
    }).record!;
    const adobe = fromAdobeA2A(
      adobeEnv({ delegationId: 'shared', grants: [{ resource: 'a', match: 'exact' }, { resource: 'b', match: 'exact' }], audience: 'did:web:r' }),
    ).record!;

    expect(google.issuerDid).toBe(adobe.issuerDid);
    expect(google.subjectDid).toBe(adobe.subjectDid);
    expect(google.constraints.scopes).toEqual(adobe.constraints.scopes);
    expect(google.constraints.audience).toEqual(adobe.constraints.audience);
  });
});

// ---------------------------------------------------------------------------
// No-widening security invariant.
// ---------------------------------------------------------------------------

describe('no-widening security invariant', () => {
  it('never adds a scope, never escalates a matcher, never drops audience (Adobe)', () => {
    const env = adobeEnv({
      delegationId: 'nw',
      grants: [{ resource: 'x', match: 'exact' }, { resource: 'p/', match: 'prefix' }, { resource: 'q.*', match: 'regex' }],
      audience: 'did:web:r',
    });
    const record = fromAdobeA2A(env).record!;
    const flat = record.constraints.scopes ?? [];
    const crisp = record.constraints.crisp?.scopes ?? [];

    // No scope invented, none dropped.
    expect(flat.length + crisp.length).toBe(3);
    // Exact stays flat-exact; non-exact stays crisp with the same matcher (no escalation).
    expect(flat).toEqual(['x']);
    expect(crisp).toEqual([{ resource: 'p/', matcher: 'prefix' }, { resource: 'q.*', matcher: 'regex' }]);
    // Audience preserved.
    expect(record.constraints.audience).toBe('did:web:r');

    // A second round trip is stable — still 3 scopes, matchers + audience intact.
    const record2 = fromAdobeA2A(toAdobeA2A(record).envelope!).record!;
    expect((record2.constraints.scopes?.length ?? 0) + (record2.constraints.crisp?.scopes.length ?? 0)).toBe(3);
    expect(record2.constraints.crisp?.scopes).toEqual(crisp);
    expect(record2.constraints.audience).toBe('did:web:r');
  });

  it('never drops audience or invents scopes across a Google round trip', () => {
    const env: GoogleA2AEnvelope = {
      delegation: { id: 'gnw', issuer: 'did:web:i', subject: 'did:web:s', scopes: ['only'], audience: ['did:web:a'] },
    };
    const back = toGoogleA2A(fromGoogleA2A(env).record!).envelope!.delegation!;
    expect(back.scopes).toEqual(['only']);
    expect(back.audience).toEqual(['did:web:a']);
  });

  it('keeps a regex resource in crisp scopes — never promoted to a flat (exact) scope', () => {
    const record = fromAdobeA2A(adobeEnv({ delegationId: 'rx', grants: [{ resource: 'evil.*', match: 'regex' }] })).record!;
    expect(record.constraints.scopes).toEqual([]);
    expect(record.constraints.crisp?.scopes).toEqual([{ resource: 'evil.*', matcher: 'regex' }]);
  });
});
