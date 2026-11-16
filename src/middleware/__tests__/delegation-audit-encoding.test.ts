/**
 * What the delegation gate encodes of a delegation it verified. It takes the digest of one sent with
 * a Data Integrity proof over the credential's RFC 8785 bytes, so all of the credential must encode;
 * a VC-JWT's over the JWT, so only the members whose values it hands on, into its audit record, the
 * authorization context a tool and a policy gate receive, and its grant, must
 * (./with-kya-os.delegation-encoding.test.ts). It decides this whether or not an audit store is
 * configured, and refuses a delegation that fails as `delegation_invalid`, with a reason its response
 * proof signs. A session grant hands on values of the credential it holds too, so its credential
 * passes the same check, without being encoded, each time the grant authorizes a call, and a grant
 * bound before the check, whose credential fails it, authorizes none. A stand-in for
 * `canonicalizeJsonBytes` counts each credential the middleware encodes, and otherwise encodes as
 * the real one does. The issuer is a
 * did:key, which the gate resolves itself; its credentials travel with a Data Integrity proof and as
 * VC-JWTs.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const encoded: unknown[] = [];
vi.mock('../../utils/canonical-json.js', async (original) => {
  const actual = await original<typeof import('../../utils/canonical-json.js')>();
  return {
    ...actual,
    canonicalizeJsonBytes: (value: unknown): Uint8Array => {
      encoded.push(value);
      return actual.canonicalizeJsonBytes(value);
    },
  };
});

import { delegationGate } from './helpers/delegation-gate.js';
import { createRealCryptoProvider, createRealIdentity } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, signedCredential, signedJwt } from '../../__tests__/utils/delegation-credentials.js';
import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import type { AgentIdentity } from '../../providers/base.js';
import type { AuditTrailService } from '../../audit/service.js';
import { MemoryGrantStore } from '../../providers/grant-store.js';

const crypto = createRealCryptoProvider();
/** A refusal of a delegation holding a value the gate cannot encode, in a session: signed, reason included. */
const REFUSED = {
  outcome: 'delegation_invalid',
  reason: 'Delegation credential holds a value that cannot be encoded as RFC 8785 text',
  proved: true,
  verified: true,
};

/** How many delegation credentials the middleware has encoded so far. */
const credentialsEncoded = () =>
  encoded.filter((value) => typeof value === 'object' && value !== null && 'credentialSubject' in value).length;

/** How `issuer` signs a delegation to the agent, for a user, with its key named: a VC-JWT's JSON text as `edit` rewrites it. */
const signing = (issuer: AgentIdentity, edit?: (json: string) => string) => ({
  record: delegationRecord(issuer.did, { controller: 'did:web:user.example', createdAt: 1_750_000_000_000 }),
  kid: issuer.kid,
  edit,
});

/** Rewrite every occurrence of `from` in a payload's JSON text, which must hold it. */
const replacing = (from: string, to: string) => (json: string): string => {
  expect(json).toContain(from);
  return json.split(from).join(to);
};

/** An audit store that encodes each event in RFC 8785 form, as the audit trail service does. */
function encodingStore() {
  const events: string[] = [];
  const record: AuditTrailService['record'] = async (event) => {
    canonicalizeJsonBytes(event);
    events.push(event.eventType);
    return { status: 'pending', event: event as never };
  };
  return { events, record };
}

/** Rewrite the delegation's scopes, in both lists that hold them, to the JSON text `list`. */
const scopesAs = (list: string) => replacing('"scopes":["orders:place"]', `"scopes":${list}`);

beforeEach(() => {
  encoded.length = 0;
});

describe('the encoding of a delegation the gate verified', () => {
  it('encodes a credential with a Data Integrity proof once for the call it is sent with, and never through a session grant or as a VC-JWT', async () => {
    const issuer = await createRealIdentity(crypto);
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did] });
    for (const [delegation, encodings] of [[await signedCredential(issuer, signing(issuer)), 1], [await signedJwt(issuer, signing(issuer)), 0]] as const) {
      const session = await gate.session();
      const before = credentialsEncoded();
      expect(await gate.callIn(session, delegation)).toBe('ran');
      expect(credentialsEncoded() - before).toBe(encodings);
      expect(await gate.callIn(session)).toBe('ran');
      expect(await gate.callIn(session)).toBe('ran');
      expect(credentialsEncoded() - before).toBe(encodings);
    }
  });

  it.each([false, true])('refuses a credential with a Data Integrity proof that holds a member it cannot encode, audit store %s', async (audited) => {
    const issuer = await createRealIdentity(crypto);
    const store = encodingStore();
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did], record: audited ? store.record : undefined });
    const credential = await signedCredential(issuer, signing(issuer));
    for (const proof of [{ ...credential.proof!, extra: '\uD800' }, { ...credential.proof!, extra: 9_007_199_254_740_995 }]) {
      expect(await gate.inSession({ ...credential, proof })).toEqual(REFUSED);
    }
    expect(store.events.filter((event) => event.startsWith('delegation.'))).toEqual(audited ? ['delegation.rejected', 'delegation.rejected'] : []);
  });

  it.each([false, true])('runs a VC-JWT whose members it does not hand on hold what it cannot encode, and lets its session grant authorize the next call, audit store %s', async (audited) => {
    const issuer = await createRealIdentity(crypto);
    const store = encodingStore();
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did], record: audited ? store.record : undefined });
    const edits = [
      replacing('"createdAt":1750000000000', '"createdAt":9007199254740995'),
      replacing('"createdAt":1750000000000', '"createdAt":1e400'),
      replacing('"status":"active"', '"status":"active","metadata":{"note":"\\ud800"}'),
    ];
    for (const edit of edits) {
      const session = await gate.session();
      expect(await gate.callIn(session, await signedJwt(issuer, signing(issuer, edit)))).toBe('ran');
      // The grant hands on the same members of the same credential, so it refuses no more than the call did.
      expect(await gate.callIn(session)).toBe('ran');
    }
    expect(store.events.filter((event) => event === 'delegation.verified')).toHaveLength(audited ? 3 : 0);
  });

  it.each([false, true])('refuses a VC-JWT whose member it hands on holds what it cannot encode, audit store %s', async (audited) => {
    const issuer = await createRealIdentity(crypto);
    const store = encodingStore();
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did], record: audited ? store.record : undefined });
    const edits = [
      replacing('"id":"del-', '"id":"\\ud800del-'),
      replacing('"did:web:agent.example"', '"did:web:agent.example\\ud800"'),
      replacing('"controller":"did:web:user.example"', '"controller":"did:web:user.example\\udc00"'),
      replacing('"id":"urn:uuid:', '"id":"urn:uuid:\\ud800'),
    ];
    for (const edit of edits) expect(await gate.inSession(await signedJwt(issuer, signing(issuer, edit)))).toEqual(REFUSED);
    expect(store.events.filter((event) => event.startsWith('delegation.'))).toEqual(audited ? Array(4).fill('delegation.rejected') : []);
  });

  it.each([false, true])('refuses a VC-JWT whose scopes, which a tool and a policy gate receive, do not encode, and hands on scopes that do, audit store %s', async (audited) => {
    const issuer = await createRealIdentity(crypto);
    const store = encodingStore();
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did], record: audited ? store.record : undefined });
    expect(await gate.inSession(await signedJwt(issuer, signing(issuer, scopesAs('["orders:place","x\\ud800"]'))))).toEqual(REFUSED);
    expect(gate.contexts).toEqual([]);
    expect(await gate.callIn(await gate.session(), await signedJwt(issuer, signing(issuer, scopesAs('["orders:place","x\\ud83d\\ude00"]'))))).toBe('ran');
    expect(gate.contexts.map((context) => context?.principal?.delegatedScopes)).toEqual([['orders:place', 'x\u{1F600}']]);
    expect(store.events.filter((event) => event.startsWith('delegation.'))).toEqual(audited ? ['delegation.rejected', 'delegation.verified'] : []);
  });

  it('authorizes no call with a session grant whose credential holds scopes it cannot encode, as one bound before this check', async () => {
    const issuer = await createRealIdentity(crypto);
    const grantStore = new MemoryGrantStore();
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did], grantStore });
    const grantFor = async (sessionId: string, list: string) => grantStore.bind({
      id: `grant-${sessionId}`, agentDid: 'did:web:agent.example', userDid: 'did:web:user.example', scopes: ['orders:place'],
      sessionId, authorization: { type: 'delegation' }, credentialJwt: await signedJwt(issuer, signing(issuer, scopesAs(list))),
      issuedAt: Date.now(), status: 'active',
    });
    const unencodable = await gate.session();
    await grantFor(unencodable, '["orders:place","x\\ud800"]');
    expect(await gate.callIn(unencodable)).toBe('needs_authorization');
    const encodable = await gate.session();
    await grantFor(encodable, '["orders:place"]');
    expect(await gate.callIn(encodable)).toBe('ran');
    expect(gate.contexts.map((context) => context?.principal?.delegatedScopes)).toEqual([['orders:place']]);
  });

  it('authorizes no call with a session grant whose credential with a Data Integrity proof holds what it cannot encode anywhere', async () => {
    const issuer = await createRealIdentity(crypto);
    const grantStore = new MemoryGrantStore();
    const gate = await delegationGate({ trustedRootIssuers: [issuer.did], grantStore });
    const credential = await signedCredential(issuer, signing(issuer));
    const grantFor = async (sessionId: string, proof: object) => grantStore.bind({
      id: `grant-${sessionId}`, agentDid: 'did:web:agent.example', userDid: 'did:web:user.example', scopes: ['orders:place'],
      sessionId, authorization: { type: 'delegation' }, delegationCredential: { ...credential, proof } as typeof credential,
      issuedAt: Date.now(), status: 'active',
    });
    for (const extra of ['\uD800', 9_007_199_254_740_995]) {
      const unencodable = await gate.session();
      await grantFor(unencodable, { ...credential.proof!, extra });
      expect(await gate.callIn(unencodable)).toBe('needs_authorization');
    }
    const encodable = await gate.session();
    await grantFor(encodable, { ...credential.proof!, extra: 'x' });
    expect(await gate.callIn(encodable)).toBe('ran');
    expect(credentialsEncoded()).toBe(0);
  });
});
