/**
 * The delegation gate runs a tool only for a delegation its issuer signed with a key the issuer's
 * DID document lists under `assertionMethod`, whether the delegation arrives with a Data Integrity
 * proof or as a VC-JWT. Acme's did:web document lists `#login-1` under `authentication`, for
 * signing in, and `#assert-1` under `assertionMethod`, for issuing; the gate resolves it through
 * `delegation.didResolver`, or fetches it with the package's did:web resolver through
 * `delegation.fetchProvider`; a key that a custom resolver serves must still come from a conforming
 * method Acme controls. Large documents and long DIDs are exercised here; how the lookup's work
 * grows is tested beside it. In a session the
 * gate signs its refusal, reason included, as it signs any outcome, and the reason is well-formed
 * text whatever the delegation quotes. A delegation must name its issuer by a DID (VC Data Model
 * 2.0 §4.7), and the last test of the first block names it otherwise. The gate refuses a delegation
 * holding a value it cannot encode, and leaves a failure of its hash provider to its caller,
 * as it always has. Real Ed25519 keys sign everything.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { delegationGate, type GateOptions, type Resolution } from './helpers/delegation-gate.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { ACME, acmeDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import {
  credentialNaming,
  delegationRecord,
  jwtClaiming,
  keyOf,
  signedCredential,
  signedJwt,
} from '../../__tests__/utils/delegation-credentials.js';
import { didWebToUrl } from '../../delegation/did-web-resolver.js';
import type { DIDDocument, VerificationMethod } from '../../delegation/vc-verifier.js';
import type { FetchProvider } from '../../providers/base.js';
import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import type { AgentIdentity } from '../../providers/base.js';

/** Node's crypto, with a `hash` that fails, as a provider that is down fails, for the bytes it is told to refuse. */
class FailingHash extends NodeCryptoProvider {
  readonly failure = new Error('hash provider unavailable');
  private readonly refused = new Set<string>();

  refuse(bytes: Uint8Array): void {
    this.refused.add(Buffer.from(bytes).toString('base64'));
  }

  override async hash(data: Uint8Array): Promise<string> {
    if (this.refused.has(Buffer.from(data).toString('base64'))) throw this.failure;
    return super.hash(data);
  }
}

/** The bytes the gate takes a delegation's audit digest over: a VC-JWT as sent, or the credential in RFC 8785 form. */
const auditBytes = (delegation: unknown): Uint8Array =>
  typeof delegation === 'string' ? new TextEncoder().encode(delegation) : canonicalizeJsonBytes(delegation);

let login: AgentIdentity;
let assert: AgentIdentity;

beforeAll(async () => {
  login = await keyOf(ACME, 'login-1');
  assert = await keyOf(ACME, 'assert-1');
});

/** Resolves Acme's DID to `document` directly. */
const resolving = (document: DIDDocument) => ({
  didResolver: { resolve: async (requested: string) => (requested === ACME ? document : null) },
});

/** Serves `document` at its DID's did:web URL, for the gate's own did:web resolver to fetch. */
const serving = (document: DIDDocument) => {
  const url = didWebToUrl(document.id);
  const body = JSON.stringify(document);
  return {
    fetchProvider: {
      fetch: async (requested: string) =>
        requested === url
          ? new Response(body, { status: 200, headers: { 'content-type': 'application/json' } })
          : new Response('not found', { status: 404 }),
    } as unknown as FetchProvider,
  };
};

/** The delegation gate of a server that trusts Acme as a root issuer and resolves its DID by `resolution`. */
const acmeGate = (
  resolution: Resolution = resolving(acmeDocument(login, assert)),
  options: Omit<GateOptions, 'trustedRootIssuers' | 'resolution'> = {},
) => delegationGate({ trustedRootIssuers: [ACME], resolution, ...options });

describe('the delegation gate and the key that signed the delegation', () => {
  it('runs the tool for a delegation signed with the key Acme lists under assertionMethod', async () => {
    const gate = await acmeGate();
    expect(await gate.call(await signedCredential(assert))).toBe('ran');
    expect(await gate.call(await signedJwt(assert, { kid: assert.kid }))).toBe('ran');
    expect(await gate.call(await signedJwt(assert))).toBe('ran');
    expect(gate.runs()).toBe(3);
  });

  it('refuses a delegation signed with the key Acme lists only under authentication', async () => {
    const gate = await acmeGate();
    expect(await gate.call(await signedCredential(login))).toBe('delegation_invalid');
    expect(await gate.call(await signedJwt(login, { kid: login.kid }))).toBe('delegation_invalid');
    expect(await gate.call(await signedJwt(login))).toBe('delegation_invalid');
    expect(gate.runs()).toBe(0);
  });

  it('refuses a delegation signed with a key its own resolver serves without a type, or under another controller', async () => {
    // The package's did:web resolver refuses a document whose methods have no type; a resolver the
    // deployment configures may serve one, and the gate holds every key it retrieves to the method
    // shape, and to a controller that is the issuer's DID.
    const { type: _type, ...untyped } = methodOf(assert);
    for (const published of [untyped as VerificationMethod, { ...methodOf(assert), controller: 'did:web:other.example' }]) {
      const gate = await acmeGate(resolving({ ...acmeDocument(login, assert), verificationMethod: [methodOf(login), published] }));
      for (const delegation of [await signedCredential(assert), await signedJwt(assert, { kid: assert.kid }), await signedJwt(assert)]) {
        expect(await gate.call(delegation)).toBe('delegation_invalid');
      }
      expect(gate.runs()).toBe(0);
    }
  });

  it('finds an explicitly named key after 100,000 references, and refuses a dangling default', async () => {
    // End to end through the gate's own did:web resolver: 100,000 references to methods the document
    // does not define, listed under assertionMethod before the issuing key, which the document also
    // publishes first under an id no relationship lists. How the lookup's time grows is tested beside
    // it (src/delegation/__tests__/verification-relationship-scaling.test.ts).
    const large: DIDDocument = {
      ...acmeDocument(login, assert),
      verificationMethod: [{ ...methodOf(assert), id: `${ACME}#unlisted` }, methodOf(login), methodOf(assert)],
      assertionMethod: [...Array.from({ length: 100_000 }, (_, i) => `#absent-${i}`), assert.kid],
    };
    const gate = await acmeGate(serving(large));
    const delegations = [await signedCredential(assert), await signedJwt(assert, { kid: assert.kid }), await signedJwt(assert)];
    for (const delegation of delegations.slice(0, 2)) expect(await gate.call(delegation)).toBe('ran');
    expect(await gate.inSession(delegations[2])).toMatchObject({ outcome: 'delegation_invalid', proved: true, verified: true });
    expect(gate.runs()).toBe(2);
  }, 180_000);

  it('refuses a 400,000-character DID whose document lists 60,000 references, on either path', async () => {
    // 940,029 bytes of JSON, which whoever holds the DID's host serves: 60,000 references to methods
    // the document does not define, listed under assertionMethod. A lookup that builds the absolute
    // id of each reference compares, hashes or copies 400,000 characters for each, and holds the
    // event loop for seconds on every delegation that names the DID, signed or not.
    const did = `did:web:long.example:${'a'.repeat(400_000 - 'did:web:long.example:'.length)}`;
    const key = await keyOf(did, 'key-1');
    const references = Array.from({ length: 60_000 }, (_, i) => `#${String(i).padStart(5, '0')}`);
    const gate = await acmeGate(serving({ id: did, assertionMethod: references } as DIDDocument));
    const credential = await signedCredential(key);
    const quoted = `"${did.slice(0, 64)}"...`;
    const refusals: [unknown, string][] = [
      [
        credential,
        `Delegation ${credential.credentialSubject.delegation.id} invalid: Verification method ${quoted} not found under assertionMethod of ${quoted}`,
      ],
      [await signedJwt(key), `JWT kid is absent, and assertionMethod of ${quoted} has no usable first entry`],
    ];
    for (const [delegation, reason] of refusals) {
      expect(await gate.reasoned(delegation)).toEqual({ outcome: 'delegation_invalid', reason });
    }
  }, 180_000);

  it('signs its refusal when the reason cuts a long purpose or kid, wherever the cut falls', async () => {
    // The response proof signs the reason in RFC 8785 form, which refuses a lone surrogate, so a cut
    // inside a character outside the Basic Multilingual Plane would leave the refusal unproven.
    const emoji = '\u{1F600}';
    const credential = await signedCredential(assert);
    const purpose = `${'p'.repeat(63)}${emoji}${'q'.repeat(30)}`;
    const kid = `${ACME}#${'k'.repeat(63 - ACME.length - 1)}${emoji}${'q'.repeat(30)}`;
    const gate = await acmeGate();
    for (const delegation of [{ ...credential, proof: { ...credential.proof!, proofPurpose: purpose } }, await signedJwt(assert, { kid })]) {
      expect(await gate.inSession(delegation)).toMatchObject({ outcome: 'delegation_invalid', proved: true, verified: true });
    }
    expect(gate.runs()).toBe(0);
  });

  it('signs its refusal when the reason quotes a lone surrogate, or its 256-unit bound falls inside a pair', async () => {
    // After `Delegation <id> invalid: Proof purpose "`, a purpose outside the Basic Multilingual Plane
    // puts a surrogate pair across the bound when the id is 179 characters long, and ends one at the
    // bound when it is 180.
    const emoji = '\u{1F600}';
    const credentialStating = async (proofPurpose: string, id?: string) => {
      const credential = await signedCredential(assert, { record: delegationRecord(ACME, id === undefined ? {} : { id }) });
      return { ...credential, proof: { ...credential.proof!, proofPurpose } };
    };
    const refusals: [unknown, string][] = [];
    const lone = await credentialStating('x\uD800y');
    refusals.push([lone, `Delegation ${lone.credentialSubject.delegation.id} invalid: Proof purpose "x\\ud800y" is not assertionMethod`]);
    const signed = await credentialStating('x');
    const named = { ...signed, credentialSubject: { ...signed.credentialSubject, delegation: { ...signed.credentialSubject.delegation, id: 'd\uD800' } } };
    refusals.push([named, 'Delegation d\uFFFD invalid: Proof purpose "x" is not assertionMethod']);
    refusals.push([await signedJwt(assert, { kid: `${ACME}#\uDC00` }), `Verification method "${ACME}#\\udc00" not found under assertionMethod of "${ACME}"`]);
    for (const id of ['d'.repeat(179), 'd'.repeat(180)]) {
      refusals.push([await credentialStating(emoji.repeat(70), id), `Delegation ${id} invalid: Proof purpose "${emoji.repeat(20)}\u2026`]);
    }
    const gate = await acmeGate();
    for (const [delegation, reason] of refusals) {
      expect(await gate.inSession(delegation)).toEqual({ outcome: 'delegation_invalid', reason, proved: true, verified: true });
    }
    expect(gate.runs()).toBe(0);
  });

  it('refuses a delegation whose issuer is not a URL before it resolves any DID, and says why', async () => {
    // The resolver answers every DID with Acme's document, so a later stage would go as far as it can
    // with what it is given.
    const asked: unknown[] = [];
    const gate = await acmeGate({
      didResolver: {
        resolve: async (requested: string) => {
          asked.push(requested);
          return acmeDocument(login, assert);
        },
      },
    });
    const credential = await credentialNaming(assert, { id: JSON.parse('{"toString":"x"}') });
    expect(await gate.inSession(credential)).toEqual({
      outcome: 'delegation_invalid',
      reason: `Delegation ${credential.credentialSubject.delegation.id} invalid: Credential issuer id of type object is not a URL`,
      proved: true,
      verified: true,
    });
    expect(await gate.inSession(await jwtClaiming(assert, {}, {}, assert.kid))).toEqual({
      outcome: 'delegation_invalid',
      reason: 'Credential issuer id of type undefined is not a URL',
      proved: true,
      verified: true,
    });
    expect(await gate.inSession(await jwtClaiming(assert, { iss: 5 }, ACME, assert.kid))).toEqual({
      outcome: 'delegation_invalid',
      reason: 'JWT iss of type number is not a URL',
      proved: true,
      verified: true,
    });
    expect(asked).toEqual([]);
    expect(gate.runs()).toBe(0);
  });
});

describe('the delegation gate and the audit digest of a delegation', () => {
  it('returns a signed refusal for noncanonical data in unsigned proof extensions, and audits the credential', async () => {
    const rejected: string[] = [];
    const gate = await acmeGate(undefined, {
      record: async (event) => {
        if (event.details.family === 'delegation' && event.details.phase === 'rejected') rejected.push(event.details.delegationRef);
        return { status: 'pending', event: event as never };
      },
    });
    const credential = await signedCredential(assert);
    for (const extension of [{ extra: '\uD800' }, { '\uDC00': 'x' }, { nested: { extra: '\uDFFF' } }]) {
      const delegation = { ...credential, proof: { ...credential.proof!, ...extension } };
      expect(await gate.inSession(delegation)).toEqual({
        outcome: 'delegation_invalid', reason: 'Delegation credential holds a value that cannot be encoded as RFC 8785 text',
        proved: true, verified: true,
      });
    }
    expect(rejected).toEqual([credential.id, credential.id, credential.id]);
    // A well-formed extension is still accepted; the signer never covered it.
    expect(await gate.call({ ...credential, proof: { ...credential.proof!, extra: '\u{1F600}' } })).toBe('ran');
    expect(gate.runs()).toBe(1);
  });

  it('returns a signed refusal for a VC-JWT whose subject id its audit record cannot encode', async () => {
    // The audit record holds members of the credential, its subject's id among them, and is encoded
    // in RFC 8785 form, which refuses a lone surrogate, as the audit trail service encodes it.
    const recorded: { event: string; encodes: boolean }[] = [];
    const gate = await acmeGate(undefined, {
      record: async (event) => {
        let encodes = true;
        try {
          canonicalizeJsonBytes(event);
        } catch {
          encodes = false;
        }
        recorded.push({ event: event.eventType, encodes });
        return { status: 'pending', event: event as never };
      },
    });
    const record = delegationRecord(ACME, { subjectDid: 'did:web:agent.example\uD800' });
    const jwt = await signedJwt(assert, { kid: assert.kid, record });
    expect(await gate.inSession(jwt)).toEqual({
      outcome: 'delegation_invalid', reason: 'Delegation credential holds a value that cannot be encoded as RFC 8785 text',
      proved: true, verified: true,
    });
    expect(recorded.filter(({ event }) => event.startsWith('delegation.'))).toEqual([{ event: 'delegation.rejected', encodes: true }]);
    expect(recorded.every(({ encodes }) => encodes)).toBe(true);
    expect(gate.runs()).toBe(0);
  });

  it('leaves a failure of its hash provider to its caller, with no refusal and no run', async () => {
    const provider = new FailingHash();
    const gate = await acmeGate(undefined, { provider });
    for (const delegation of [await signedCredential(assert), await signedJwt(assert, { kid: assert.kid })]) {
      provider.refuse(auditBytes(delegation));
      await expect(gate.inSession(delegation)).rejects.toBe(provider.failure);
    }
    expect(gate.runs()).toBe(0);
  });

  it('signs a refusal it decides after verification even when its hash provider fails', async () => {
    const provider = new FailingHash();
    const gate = await acmeGate(undefined, { provider, scopeId: 'orders:cancel' });
    for (const delegation of [await signedCredential(assert), await signedJwt(assert, { kid: assert.kid })]) {
      provider.refuse(auditBytes(delegation));
      expect(await gate.inSession(delegation)).toEqual({
        outcome: 'insufficient_scope', reason: 'Required scope "orders:cancel" not in delegation scopes',
        proved: true, verified: true,
      });
    }
    expect(gate.runs()).toBe(0);
  });

  it('runs a call its session grant authorizes without hashing the credential again', async () => {
    const provider = new FailingHash();
    const gate = await acmeGate(undefined, { provider });
    for (const delegation of [await signedCredential(assert), await signedJwt(assert, { kid: assert.kid })]) {
      const session = await gate.session();
      expect(await gate.callIn(session, delegation)).toBe('ran');
      provider.refuse(auditBytes(delegation));
      expect(await gate.callIn(session)).toBe('ran');
    }
    expect(gate.runs()).toBe(4);
  });
});
