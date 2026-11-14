/**
 * An `eddsa-jcs-2022` proof verifies only with a key that the signer's DID document lists under the
 * verification relationship the proof's purpose names (W3C Controlled Identifiers v1.0 §3.3, which
 * the cryptosuite follows to retrieve its key; Data Integrity §5.10). Both shipped verifiers expect
 * `assertionMethod`. A key listed there by reference, absolute or relative, or embedded by value is
 * accepted; a key the document lists under another relationship, or under none, or whose controller
 * is another DID, is not. Every proof is made with a real Ed25519 key by the independent signer in
 * ./signed-chain-helpers, and every DID document is written out here.
 */

import { describe, it, expect } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { DIDDocument, DIDResolver } from '../../delegation/vc-verifier.types.js';
import { ACME, documentOf, methodOf, type PublishedKey } from '../../__tests__/utils/did-documents.js';
import { verifyEddsaJcs2022 } from '../data-integrity.js';
import type { DelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import {
  NOW_MS,
  RESOURCE,
  hop,
  identity,
  serve,
  signEddsaJcs2022,
  statusList,
  type TestIdentity,
} from './signed-chain-helpers.js';

/** An Ed25519 key of Acme's did:web identity, published as `#<fragment>`, and its raw public key, for `methodOf`. */
function acmeKey(fragment: string): TestIdentity & PublishedKey {
  const key = identity();
  const method = `${ACME}#${fragment}`;
  return { ...key, did: ACME, method, kid: method, publicKey: Buffer.from(key.publicJwk.x, 'base64url').toString('base64') };
}

/** Resolves Acme's DID to `document`, and a did:key DID as the did:key method does. */
function resolverWith(document: DIDDocument): DIDResolver {
  const didKey = createDidKeyResolver();
  return { resolve: async (did) => (did === ACME ? document : didKey.resolve(did)) };
}

const verifyList = (document: DIDDocument, list: Record<string, unknown>) =>
  createStatusListProofVerifier({ didResolver: resolverWith(document) })(list);

describe('the verification relationship of a status list key', () => {
  const key = acmeKey('assert-1');
  const list = statusList(key);

  it('accepts a key listed under assertionMethod by its absolute id', async () => {
    const document = documentOf({ verificationMethod: [methodOf(key)], assertionMethod: [key.method] });
    expect(await verifyList(document, list)).toBe(true);
  });

  it('accepts a key listed under assertionMethod by a relative #fragment', async () => {
    const document = documentOf({ verificationMethod: [methodOf(key, { id: '#assert-1' })], assertionMethod: ['#assert-1'] });
    expect(await verifyList(document, list)).toBe(true);
  });

  it('accepts a key embedded in assertionMethod with an absolute or a relative id, listed nowhere else', async () => {
    for (const id of [key.method, '#assert-1']) {
      expect(await verifyList(documentOf({ assertionMethod: [methodOf(key, { id })] }), list)).toBe(true);
    }
    expect(await verifyList(documentOf({ assertionMethod: ['#assert-1', methodOf(key)] }), list)).toBe(true);
  });

  it('rejects a key listed only under authentication, by reference or embedded', async () => {
    const byReference = documentOf({ verificationMethod: [methodOf(key)], authentication: [key.method] });
    const embedded = documentOf({ authentication: [methodOf(key)] });
    expect(await verifyList(byReference, list)).toBe(false);
    expect(await verifyList(embedded, list)).toBe(false);
  });

  it('rejects a key the document lists under no verification relationship', async () => {
    expect(await verifyList(documentOf({ verificationMethod: [methodOf(key)] }), list)).toBe(false);
  });

  it('rejects a key listed under assertionMethod that another DID controls, by reference or embedded', async () => {
    const foreign = { ...methodOf(key), controller: 'did:web:other.example' };
    expect(await verifyList(documentOf({ verificationMethod: [foreign], assertionMethod: [key.method] }), list)).toBe(false);
    expect(await verifyList(documentOf({ assertionMethod: [foreign] }), list)).toBe(false);
  });

  it("rejects a key when assertionMethod lists only the issuer's other keys", async () => {
    const other = acmeKey('assert-2');
    const document = documentOf({
      verificationMethod: [methodOf(key), methodOf(other)],
      assertionMethod: [other.method, '#assert-2', methodOf(acmeKey('assert-3'))],
    });
    expect(await verifyList(document, list)).toBe(false);
  });

  it('rejects a reference to a method the document does not define', async () => {
    expect(await verifyList(documentOf({ assertionMethod: [key.method] }), list)).toBe(false);
  });

  it('reads assertionMethod only as an array', async () => {
    const document = documentOf({ verificationMethod: [methodOf(key)], assertionMethod: key.method });
    expect(await verifyList(document, list)).toBe(false);
  });

  it('passes over assertionMethod entries that name no method or another one', async () => {
    const other = acmeKey('assert-2');
    const others = [42, null, { type: 'JsonWebKey' }, methodOf(other, { id: '#assert-0' }), other.method];
    const byReference = documentOf({
      verificationMethod: [methodOf(other), methodOf(key)],
      assertionMethod: [...others, key.method],
    });
    const embedded = documentOf({ verificationMethod: [methodOf(other)], assertionMethod: [...others, methodOf(key)] });
    expect(await verifyList(byReference, list)).toBe(true);
    expect(await verifyList(embedded, list)).toBe(true);
  });

  it('rejects a proof whose verification method is empty, though assertionMethod lists the signing key first', async () => {
    const document = documentOf({ verificationMethod: [methodOf(key)], assertionMethod: [key.method] });
    expect(await verifyList(document, statusList({ ...key, method: '' }))).toBe(false);
  });

  it("rejects a document that is not the signer DID's own", async () => {
    const document = documentOf(
      { verificationMethod: [methodOf(key)], assertionMethod: [key.method] },
      'did:web:other.example',
    );
    expect(await verifyList(document, list)).toBe(false);
  });
});

describe('verifyEddsaJcs2022 and the proof purpose it checks for', () => {
  const key = acmeKey('invoke-1');
  const invocation = signEddsaJcs2022(
    { '@context': ['https://www.w3.org/ns/credentials/v2'], issuer: ACME, action: 'orders.place' },
    key,
    { proofPurpose: 'capabilityInvocation' },
  );
  const listedUnder = (relationship: string) =>
    resolverWith(documentOf({ verificationMethod: [methodOf(key)], [relationship]: [key.method] }));

  it('reads the relationship that the purpose names', async () => {
    expect(await verifyEddsaJcs2022(invocation, listedUnder('capabilityInvocation'), 'capabilityInvocation')).toBe(true);
    expect(await verifyEddsaJcs2022(invocation, listedUnder('assertionMethod'), 'capabilityInvocation')).toBe(false);
  });

  it('resolves false, without throwing, when the DID resolves to no document', async () => {
    const nothing: DIDResolver = { resolve: async () => null };
    expect(await verifyEddsaJcs2022(invocation, nothing, 'capabilityInvocation')).toBe(false);
  });

  it('finds no key for an empty issuer, whatever document a resolver returns for it', async () => {
    const anyDid: DIDResolver = {
      resolve: async () => documentOf({ verificationMethod: [methodOf(key, { id: '#invoke-1' })], capabilityInvocation: ['#invoke-1'] }),
    };
    const unnamed = signEddsaJcs2022(
      { '@context': ['https://www.w3.org/ns/credentials/v2'], issuer: '', action: 'orders.place' },
      { ...key, method: '#invoke-1' },
      { proofPurpose: 'capabilityInvocation' },
    );
    expect(await verifyEddsaJcs2022(invocation, anyDid, 'capabilityInvocation')).toBe(true);
    expect(await verifyEddsaJcs2022(unnamed, anyDid, 'capabilityInvocation')).toBe(false);
  });
});

/**
 * Acme with two keys: #login-1 listed under authentication, for signing in to its own console, and
 * #assert-1 under assertionMethod, for its delegations and status lists.
 */
function acme() {
  const login = acmeKey('login-1');
  const assert = acmeKey('assert-1');
  const document = documentOf({
    verificationMethod: [methodOf(login), methodOf(assert)],
    authentication: [login.method],
    assertionMethod: [assert.method],
  });
  return { login, assert, didResolver: resolverWith(document) };
}

describe('the verification relationship of a delegation hop key', () => {
  it('accepts a hop Acme signed with its assertionMethod key, and rejects one signed with its login key', async () => {
    const { login, assert, didResolver } = acme();
    const grant = (signer: TestIdentity) =>
      hop({
        issuer: signer,
        invoker: identity().did,
        id: 'urn:zcap:acme-root',
        parentCapability: RESOURCE,
        allowedAction: ['orders.place'],
      });
    const verifyHop = createDelegationProofVerifier({ didResolver });
    expect(await verifyHop(grant(assert))).toBe(true);
    expect(await verifyHop(grant(login))).toBe(false);
  });

  it('rejects a hop signed with the key Acme lists under assertionMethod when another DID controls it', async () => {
    const assert = acmeKey('assert-1');
    const controlledBy = (controller: string) =>
      resolverWith(documentOf({ verificationMethod: [{ ...methodOf(assert), controller }], assertionMethod: [assert.method] }));
    const granted = hop({
      issuer: assert,
      invoker: identity().did,
      id: 'urn:zcap:acme-root',
      parentCapability: RESOURCE,
      allowedAction: ['orders.place'],
    });
    expect(await createDelegationProofVerifier({ didResolver: controlledBy(ACME) })(granted)).toBe(true);
    expect(await createDelegationProofVerifier({ didResolver: controlledBy('did:web:other.example') })(granted)).toBe(false);
  });
});

describe('a merchant verifying a carried chain against Acme', () => {
  const agent = identity();
  const root = (signer: TestIdentity) =>
    hop({
      issuer: signer,
      invoker: agent.did,
      id: 'urn:zcap:acme-root',
      parentCapability: RESOURCE,
      allowedAction: ['orders.place'],
      statusIndex: 3,
    });
  const verify = (didResolver: DIDResolver, chain: DelegationChain, list: Record<string, unknown>) =>
    verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: agent.did, action: 'orders.place' },
      {
        resource: RESOURCE,
        verifyHopProof: createDelegationProofVerifier({ didResolver }),
        checkRevocation: createRevocationChecker({
          fetch: serve(list),
          now: () => NOW_MS,
          verifyStatusList: createStatusListProofVerifier({ didResolver }),
        }),
        now: () => NOW_MS,
      },
    );

  it('accepts a root and a status list Acme signed with its assertionMethod key', async () => {
    const { assert, didResolver } = acme();
    expect(await verify(didResolver, [root(assert)], statusList(assert))).toMatchObject({
      ok: true,
      responsibleParty: ACME,
    });
  });

  it('rejects a root signed with the key Acme lists only under authentication', async () => {
    const { login, assert, didResolver } = acme();
    expect(await verify(didResolver, [root(login)], statusList(assert))).toEqual({
      ok: false,
      code: 'delegation_invalid',
      reasons: ['hop 0: proof did not verify'],
      source: 'carried',
    });
  });

  it('keeps a revocation when a list signed with that authentication key clears it', async () => {
    const { login, assert, didResolver } = acme();
    const granted = [root(assert)];
    expect(await verify(didResolver, granted, statusList(assert, [3]))).toMatchObject({ ok: false, code: 'delegation_revoked' });
    expect(await verify(didResolver, granted, statusList(login))).toMatchObject({ ok: false, code: 'delegation_revoked' });
  });
});
