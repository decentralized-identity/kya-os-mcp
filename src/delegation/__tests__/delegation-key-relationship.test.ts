/**
 * `DelegationCredentialVerifier` checks a delegation credential only with a key its issuer's DID
 * document lists under `assertionMethod` (W3C Controlled Identifiers v1.0 §3.3), on both of its
 * paths: the embedded Data Integrity proof and the VC-JWT envelope. Acme keeps two keys, `#login-1`
 * under `authentication` for signing in and `#assert-1` under `assertionMethod` for issuing, and a
 * credential signed with the login key is not Acme's delegation. Some tests add `#assert-2`, a second
 * key under `assertionMethod`, and some name a key or an issuer far longer than a refusal reason
 * quotes. A credential must name its issuer by a DID, as a string or as the id of an issuer object
 * (VC Data Model 2.0 §4.7); the last tests name it otherwise, or send a VC-JWT that carries no
 * credential. Every credential is signed with a real Ed25519 key, and every DID document is written
 * out here.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { DelegationCredentialVerifier, type DIDDocument } from '../vc-verifier.js';
import { createRealCryptoProvider, createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { ACME, OTHER, acmeDocument, anotherDidReason, documentOf, methodOf } from '../../__tests__/utils/did-documents.js';
import {
  credentialNaming,
  delegationRecord,
  envelope,
  jwtClaiming,
  keyOf,
  signedCredential,
  signedJwt,
} from '../../__tests__/utils/delegation-credentials.js';
import type { AgentIdentity } from '../../providers/base.js';

const crypto = createRealCryptoProvider();
const LONG_ISSUER = `${ACME}:${'a'.repeat(100_000)}`;
/** Acme's DID as a refusal reason quotes it. */
const QUOTED_ACME = `"${ACME}"`;
/**
 * Issuers that are URLs, each with how a refusal reason quotes it: cut, or with a quote mark and a
 * Hangul filler, which renders as nothing, escaped.
 */
const QUOTED_ISSUERS: [string, string][] = [
  [LONG_ISSUER, `"${LONG_ISSUER.slice(0, 64)}"...`],
  [`${ACME}"\u3164`, `"${ACME}\\"\\u3164"`],
];

let login: AgentIdentity;
let assert: AgentIdentity;
let second: AgentIdentity;
let outsider: AgentIdentity;

beforeAll(async () => {
  login = await keyOf(ACME, 'login-1');
  assert = await keyOf(ACME, 'assert-1');
  second = await keyOf(ACME, 'assert-2');
  outsider = await keyOf(OTHER, 'key-1');
});

/** A verifier whose resolver answers `document` for `did` (default: Acme's DID) and nothing else. */
const verifierFor = (document: DIDDocument, did: string = ACME) =>
  new DelegationCredentialVerifier({
    didResolver: { resolve: async (requested) => (requested === did ? document : null) },
    signatureVerifier: createRealSignatureVerifier(crypto),
  });

describe('the Data Integrity path', () => {
  const verify = async (document: DIDDocument, credential: Awaited<ReturnType<typeof signedCredential>>) =>
    verifierFor(document).verifyDelegationCredential(credential, { skipCache: true });

  it("verifies a credential signed with the key Acme lists under assertionMethod", async () => {
    expect(await verify(acmeDocument(login, assert), await signedCredential(assert))).toMatchObject({ valid: true });
  });

  it('rejects a credential signed with the key Acme lists only under authentication', async () => {
    const result = await verify(acmeDocument(login, assert), await signedCredential(login));
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe(`Verification method "${login.kid}" not found under assertionMethod of "${ACME}"`);
  });

  it('rejects a key Acme publishes under no verification relationship', async () => {
    const document = documentOf({ verificationMethod: [methodOf(assert)] });
    expect(await verify(document, await signedCredential(assert))).toMatchObject({ valid: false, stage: 'signature' });
  });

  it('verifies a key listed by a relative reference or embedded, named absolute or relative', async () => {
    const byReference = documentOf({ verificationMethod: [methodOf(assert, { id: '#assert-1' })], assertionMethod: ['#assert-1'] });
    const embedded = documentOf({ assertionMethod: [methodOf(assert, { id: '#assert-1' })] });
    for (const document of [byReference, embedded]) {
      for (const kid of [assert.kid, '#assert-1']) {
        expect(await verify(document, await signedCredential(assert, { kid }))).toMatchObject({ valid: true });
      }
    }
  });

  it("rejects a key of another DID, even one Acme's document lists under assertionMethod", async () => {
    const document = documentOf({ verificationMethod: [methodOf(outsider)], assertionMethod: [outsider.kid] });
    expect(await verify(document, await signedCredential(outsider, { record: delegationRecord(ACME) }))).toMatchObject({ valid: false, stage: 'signature' });
  });

  it('rejects a key Acme lists under assertionMethod that another DID controls, saying so, or that has no type', async () => {
    const { type: _type, ...untyped } = methodOf(assert);
    const published: [Record<string, unknown>, string][] = [
      [{ ...methodOf(assert), controller: OTHER }, anotherDidReason(assert.kid, 'controller')],
      [untyped, `Verification method "${assert.kid}" not found under assertionMethod of "${ACME}"`],
    ];
    for (const [method, reason] of published) {
      const referencing = documentOf({ verificationMethod: [method], assertionMethod: [assert.kid] });
      const embedding = documentOf({ assertionMethod: [method] });
      for (const document of [referencing, embedding]) {
        expect(await verify(document, await signedCredential(assert))).toMatchObject({ valid: false, stage: 'signature', reason });
      }
    }
  });

  it("refuses a proof that states another purpose before it resolves the issuer's DID", async () => {
    const asked: string[] = [];
    const verifier = new DelegationCredentialVerifier({
      didResolver: {
        resolve: async (requested) => {
          asked.push(requested);
          return acmeDocument(login, assert);
        },
      },
      signatureVerifier: createRealSignatureVerifier(crypto),
    });
    const credential = await signedCredential(assert);
    const restated = { ...credential, proof: { ...credential.proof!, proofPurpose: 'authentication' } };
    const result = await verifier.verifyDelegationCredential(restated, { skipCache: true });
    expect(result).toMatchObject({ valid: false, stage: 'signature', reason: 'Proof purpose "authentication" is not assertionMethod' });
    expect(asked).toEqual([]);
  });

  it("rejects a document that is not the issuer's own, whoever's keys it lists, saying so of a key it lists as Acme's", async () => {
    const listingAcme = documentOf({ verificationMethod: [methodOf(assert)], assertionMethod: [assert.kid] }, OTHER);
    expect(await verify(listingAcme, await signedCredential(assert)))
      .toMatchObject({ valid: false, stage: 'signature', reason: anotherDidReason(assert.kid, "document's id") });
    const othersOwn = documentOf({ verificationMethod: [methodOf(outsider)], assertionMethod: [outsider.kid] }, OTHER);
    expect(await verify(othersOwn, await signedCredential(outsider, { record: delegationRecord(ACME) }))).toMatchObject({
      valid: false,
      stage: 'signature',
      reason: `Verification method "${outsider.kid}" not found under assertionMethod of "${ACME}"`,
    });
  });

  it('rejects a proof that names no verification method as a non-empty string, quoting what it names instead', async () => {
    const credential = await signedCredential(assert);
    const named: [unknown, string][] = [
      [undefined, 'Proof missing verificationMethod'],
      ['', 'Proof verificationMethod "" is not a DID URL'],
      [7, 'Proof verificationMethod of type number is not a DID URL'],
      [null, 'Proof verificationMethod of type null is not a DID URL'],
      [{ id: assert.kid }, 'Proof verificationMethod of type object is not a DID URL'],
      [JSON.parse('{"toString":"#assert-1"}'), 'Proof verificationMethod of type object is not a DID URL'],
    ];
    for (const [verificationMethod, reason] of named) {
      const result = await verify(acmeDocument(login, assert), { ...credential, proof: { ...credential.proof!, verificationMethod } as never });
      expect(result).toMatchObject({ valid: false, stage: 'signature', reason });
    }
  });

  it('rejects a proof that states another purpose, and reads one that states none as an assertion', async () => {
    const credential = await signedCredential(assert);
    const restated = { ...credential, proof: { ...credential.proof!, proofPurpose: 'authentication' } };
    const result = await verify(acmeDocument(login, assert), restated);
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe('Proof purpose "authentication" is not assertionMethod');

    const { proofPurpose: _purpose, ...unstated } = credential.proof!;
    expect(await verify(acmeDocument(login, assert), { ...credential, proof: unstated })).toMatchObject({ valid: true });
  });

  it('names a stated purpose that is not a string by its JSON type, and quotes at most 64 characters of one', async () => {
    const credential = await signedCredential(assert);
    const stated: [unknown, string][] = [
      [['assertionMethod'], 'of type array'],
      [[], 'of type array'],
      [{ purpose: 'assertionMethod' }, 'of type object'],
      [JSON.parse('{"toString":"assertionMethod"}'), 'of type object'],
      ['x'.repeat(100_000), `"${'x'.repeat(64)}"...`],
      ['assertionMethod ', '"assertionMethod "'],
    ];
    for (const [proofPurpose, named] of stated) {
      const result = await verify(acmeDocument(login, assert), { ...credential, proof: { ...credential.proof!, proofPurpose } as never });
      expect(result).toMatchObject({ valid: false, stage: 'signature', reason: `Proof purpose ${named} is not assertionMethod` });
    }
  });

  it("rejects a key whose id Acme's document defines twice, whichever definition holds the signing key", async () => {
    const definitions = [methodOf(assert), methodOf(second, { id: assert.kid })];
    for (const verificationMethod of [definitions, [...definitions].reverse()]) {
      const result = await verify(documentOf({ verificationMethod, assertionMethod: [assert.kid] }), await signedCredential(assert));
      expect(result).toMatchObject({ valid: false, stage: 'signature' });
      expect(result.reason).toBe(`Verification method "${assert.kid}" not found under assertionMethod of "${ACME}"`);
    }
  });

  it('quotes at most 64 characters of the verification method a proof names', async () => {
    const credential = await signedCredential(assert);
    const verificationMethod = `${ACME}#${'k'.repeat(100_000)}`;
    const result = await verify(acmeDocument(login, assert), { ...credential, proof: { ...credential.proof!, verificationMethod } });
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe(`Verification method "${verificationMethod.slice(0, 64)}"... not found under assertionMethod of "${ACME}"`);
  });

  it('quotes an issuer DID it cannot resolve, and a proof.type it does not support, as it quotes any value', async () => {
    const credential = await signedCredential(assert);
    const verifier = verifierFor(acmeDocument(login, assert));
    const objectType = JSON.parse('{"toString":"DataIntegrityProof"}');
    for (const [value, quoted] of [...QUOTED_ISSUERS, [objectType, 'of type object']] as [unknown, string][]) {
      if (typeof value === 'string') {
        expect(await verifier.verifyDelegationCredential({ ...credential, issuer: value }, { skipCache: true }))
          .toMatchObject({ valid: false, stage: 'signature', reason: `Could not resolve issuer DID: ${quoted}` });
      }
      expect(await verifier.verifyDelegationCredential({ ...credential, proof: { ...credential.proof!, type: value } as never }, { skipCache: true }))
        .toMatchObject({ valid: false, stage: 'signature', reason: `Unsupported credential proof.type: ${quoted}` });
    }
  });

  it('quotes at most 64 characters of the issuer DID', async () => {
    const issuer = LONG_ISSUER;
    const document = documentOf({ verificationMethod: [methodOf(assert, { id: '#assert-1' })], authentication: ['#assert-1'] }, issuer);
    const credential = await signedCredential(assert, { kid: '#assert-1', record: delegationRecord(issuer) });
    const result = await verifierFor(document, issuer).verifyDelegationCredential(credential, { skipCache: true });
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe(`Verification method "#assert-1" not found under assertionMethod of "${issuer.slice(0, 64)}"...`);
  });
});

describe('the VC-JWT path', () => {
  const verify = async (document: DIDDocument, jwt: string) =>
    verifierFor(document).verifyDelegationJwt(jwt, { skipCache: true });
  // Only the first entry is tried without a kid, so the refusal names that entry, not the list.
  const noUsableFirstEntry = (quotedIssuer: string) => `JWT kid is absent, and assertionMethod of ${quotedIssuer} has no usable first entry`;

  it('verifies a VC-JWT whose kid names the assertionMethod key, absolute or relative', async () => {
    for (const kid of [assert.kid, '#assert-1']) {
      expect(await verify(acmeDocument(login, assert), await signedJwt(assert, { kid }))).toMatchObject({ valid: true });
    }
  });

  it('rejects a VC-JWT whose kid names the key Acme lists only under authentication', async () => {
    const result = await verify(acmeDocument(login, assert), await signedJwt(login, { kid: login.kid }));
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe(`Verification method "${login.kid}" not found under assertionMethod of "${ACME}"`);
  });

  it('with no kid, checks the first key listed under assertionMethod and never one listed elsewhere', async () => {
    expect(await verify(acmeDocument(login, assert), await signedJwt(assert))).toMatchObject({ valid: true });
    expect(await verify(acmeDocument(login, assert), await signedJwt(login))).toMatchObject({ valid: false, stage: 'signature' });
  });

  it('with no kid, checks only the first key listed under assertionMethod', async () => {
    // verificationMethod lists the keys in the other order, so the first of those is not the key.
    const document = documentOf({ verificationMethod: [methodOf(second), methodOf(assert)], assertionMethod: [assert.kid, second.kid] });
    expect(await verify(document, await signedJwt(assert))).toMatchObject({ valid: true });
    expect(await verify(document, await signedJwt(second))).toMatchObject({ valid: false, stage: 'signature' });
    expect(await verify(document, await signedJwt(second, { kid: second.kid }))).toMatchObject({ valid: true });
  });

  it('requires a kid when the first assertion entry is dangling, malformed or ambiguous', async () => {
    const good = methodOf(assert);
    for (const entry of ['#gone', 7, { id: '#bad' }, '#twice']) {
      const document = documentOf({ verificationMethod: [good, { ...good, id: '#twice' }, { ...good, id: '#twice' }],
        assertionMethod: [entry, assert.kid] });
      expect(await verify(document, await signedJwt(assert)))
        .toMatchObject({ valid: false, stage: 'signature', reason: noUsableFirstEntry(QUOTED_ACME) });
      expect(await verify(document, await signedJwt(assert, { kid: assert.kid }))).toMatchObject({ valid: true });
    }
  });

  it('refuses an empty kid as naming no key, even when the first assertionMethod entry is the key that signed', async () => {
    for (const key of [assert, login]) {
      expect(await verify(acmeDocument(login, assert), await signedJwt(key, { kid: '' })))
        .toMatchObject({ valid: false, stage: 'signature', reason: 'JWT kid "" is not a DID URL' });
    }
  });

  it("rejects a kid of another DID, even one Acme's document lists under assertionMethod", async () => {
    const document = documentOf({ verificationMethod: [methodOf(outsider)], assertionMethod: [outsider.kid] });
    expect(await verify(document, await signedJwt(outsider, { kid: outsider.kid, record: delegationRecord(ACME) }))).toMatchObject({ valid: false });
  });

  it('rejects a key Acme lists under assertionMethod that another DID controls, with a kid or without, saying so', async () => {
    const document = documentOf({ verificationMethod: [{ ...methodOf(assert), controller: OTHER }], assertionMethod: [assert.kid] });
    for (const kid of [assert.kid, undefined]) {
      expect(await verify(document, await signedJwt(assert, { kid })))
        .toMatchObject({ valid: false, stage: 'signature', reason: anotherDidReason(assert.kid, 'controller') });
    }
  });

  it("rejects a document that is not the issuer's own, whoever's keys it lists, saying so of a key it lists as Acme's", async () => {
    const othersOwn = documentOf({ verificationMethod: [methodOf(outsider)], assertionMethod: [outsider.kid] }, OTHER);
    for (const kid of [outsider.kid, undefined]) {
      expect(await verify(othersOwn, await signedJwt(outsider, { kid, record: delegationRecord(ACME) }))).toMatchObject({ valid: false, stage: 'signature' });
    }
    const listingAcme = documentOf({ verificationMethod: [methodOf(assert)], assertionMethod: [assert.kid] }, OTHER);
    for (const kid of [assert.kid, undefined]) {
      expect(await verify(listingAcme, await signedJwt(assert, { kid })))
        .toMatchObject({ valid: false, stage: 'signature', reason: anotherDidReason(assert.kid, "document's id") });
    }
  });

  it('rejects a VC-JWT with no kid when Acme lists nothing under assertionMethod', async () => {
    const document = documentOf({ verificationMethod: [methodOf(assert)], authentication: [assert.kid] });
    const result = await verify(document, await signedJwt(assert));
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe(noUsableFirstEntry(QUOTED_ACME));
  });

  it('quotes at most 64 characters of a kid, and refuses one that is not a string as a malformed VC-JWT', async () => {
    const kid = `${ACME}#${'k'.repeat(100_000)}`;
    const result = await verify(acmeDocument(login, assert), await signedJwt(assert, { kid }));
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(result.reason).toBe(`Verification method "${kid.slice(0, 64)}"... not found under assertionMethod of "${ACME}"`);

    const objectKid = await signedJwt(assert, { kid: JSON.parse(`{"toString":"${assert.kid}"}`) });
    expect(await verify(acmeDocument(login, assert), objectKid)).toMatchObject({
      valid: false,
      stage: 'basic',
      reason: 'Not a valid VC-JWT (parse failed)',
    });
  });

  it('quotes an issuer DID it cannot resolve as it quotes any value, whether the resolver answers nothing or throws', async () => {
    const throwing = new DelegationCredentialVerifier({
      didResolver: { resolve: async () => { throw new Error('offline'); } },
      signatureVerifier: createRealSignatureVerifier(crypto),
    });
    for (const [issuer, quoted] of QUOTED_ISSUERS) {
      const jwt = await signedJwt(assert, { kid: assert.kid, record: delegationRecord(issuer) });
      expect(await verify(acmeDocument(login, assert), jwt)).toMatchObject({ valid: false, stage: 'signature', reason: `Could not resolve issuer DID: ${quoted}` });
      expect(await throwing.verifyDelegationJwt(jwt, { skipCache: true }))
        .toMatchObject({ valid: false, stage: 'signature', reason: `Could not resolve issuer DID ${quoted}: offline` });
    }
  });

  it('quotes at most 64 characters of the issuer DID, with a kid or without', async () => {
    const issuer = LONG_ISSUER;
    const document = documentOf({ verificationMethod: [methodOf(assert, { id: '#assert-1' })], authentication: ['#assert-1'] }, issuer);
    const reasonFor = async (kid?: string) =>
      (await verifierFor(document, issuer).verifyDelegationJwt(await signedJwt(assert, { kid, record: delegationRecord(issuer) }), { skipCache: true })).reason;
    expect(await reasonFor('#assert-1')).toBe(`Verification method "#assert-1" not found under assertionMethod of "${issuer.slice(0, 64)}"...`);
    expect(await reasonFor()).toBe(noUsableFirstEntry(`"${issuer.slice(0, 64)}"...`));
  });
});

describe('a credential that names no issuer DID', () => {
  // VC Data Model 2.0 §4.7: the issuer is a URL, or an object whose id is a URL. The resolver answers
  // every DID with Acme's document, so a later stage would go as far as it can with what it is given.
  const answeringEveryDid = () => {
    const asked: unknown[] = [];
    const verifier = new DelegationCredentialVerifier({
      didResolver: {
        resolve: async (requested) => {
          asked.push(requested);
          return acmeDocument(login, assert);
        },
      },
      signatureVerifier: createRealSignatureVerifier(crypto),
    });
    return { verifier, asked };
  };
  const notURLs: [unknown, string][] = [
    ['acme', 'Credential issuer "acme" is not a URL'],
    [{ id: 'acme' }, 'Credential issuer id "acme" is not a URL'],
    [{ id: 5 }, 'Credential issuer id of type number is not a URL'],
    [{}, 'Credential issuer id of type undefined is not a URL'],
    [{ id: null }, 'Credential issuer id of type null is not a URL'],
    [{ id: JSON.parse('{"toString":"x"}') }, 'Credential issuer id of type object is not a URL'],
    [[ACME], 'Credential issuer of type array is not a URL'],
  ];

  it('refuses an embedded-proof credential at the basic stage, before resolving any DID', async () => {
    const { verifier, asked } = answeringEveryDid();
    for (const [issuer, reason] of notURLs) {
      for (const kid of [assert.kid, '#assert-1']) {
        const result = await verifier.verifyDelegationCredential(await credentialNaming(assert, issuer, kid), { skipCache: true });
        expect(result).toMatchObject({ valid: false, stage: 'basic', reason });
      }
    }
    expect(asked).toEqual([]);
  });

  it('refuses a VC-JWT at the basic stage, before resolving any DID, whose iss, or with no iss whose issuer, is not a string', async () => {
    const { verifier, asked } = answeringEveryDid();
    for (const [issuer, reason] of notURLs) {
      for (const kid of [assert.kid, '#assert-1', undefined]) {
        const result = await verifier.verifyDelegationJwt(await jwtClaiming(assert, {}, issuer, kid), { skipCache: true });
        expect(result).toMatchObject({ valid: false, stage: 'basic', reason });
      }
    }
    const notStrings: [unknown, string][] = [
      [JSON.parse(`{"toString":"${ACME}"}`), 'of type object'],
      [5, 'of type number'],
      [null, 'of type null'],
      [[ACME], 'of type array'],
    ];
    for (const [iss, type] of notStrings) {
      const result = await verifier.verifyDelegationJwt(await jwtClaiming(assert, { iss }, ACME, assert.kid), { skipCache: true });
      expect(result).toMatchObject({ valid: false, stage: 'basic', reason: `JWT iss ${type} is not a URL` });
    }
    expect(asked).toEqual([]);
  });

  it("refuses a VC-JWT whose iss is a string but not a URL, by the credential issuer's rule, whatever its issuer", async () => {
    const { verifier, asked } = answeringEveryDid();
    const notURLs: [string, string][] = [
      ['acme', '"acme"'],
      [` ${ACME}`, `" ${ACME}"`],
      [`${ACME}\u0085`, `"${ACME}\\u0085"`],
      [`${ACME}\u200b`, `"${ACME}\\u200b"`],
      [`${ACME}\ud800`, `"${ACME}\\ud800"`],
      ['did:web:acme\u202e.example', '"did:web:acme\\u202e.example"'],
    ];
    for (const [iss, quoted] of notURLs) {
      for (const issuer of [ACME, iss]) {
        const result = await verifier.verifyDelegationJwt(await jwtClaiming(assert, { iss }, issuer, assert.kid), { skipCache: true });
        expect(result).toMatchObject({ valid: false, stage: 'basic', reason: `JWT iss ${quoted} is not a URL` });
      }
    }
    expect(asked).toEqual([]);
  });

  it('reads the issuer only from a credential its schema check accepts, so a VC-JWT that carries none is refused', async () => {
    const { verifier, asked } = answeringEveryDid();
    const refused = { valid: false, stage: 'basic', reason: expect.stringMatching(/^Schema validation failed: /) };
    for (const vc of [undefined, null, ACME]) {
      const jwt = await envelope(assert, Buffer.from(JSON.stringify({ iss: ACME, vc })).toString('base64url'), assert.kid);
      expect(await verifier.verifyDelegationJwt(jwt, { skipCache: true })).toMatchObject(refused);
    }
    expect(asked).toEqual([]);
  });

  it('verifies the same credential once its issuer names Acme, as a string or as the id of an object', async () => {
    for (const issuer of [ACME, { id: ACME }, { id: ACME, name: 'Acme' }]) {
      const verifier = verifierFor(acmeDocument(login, assert));
      const credential = await credentialNaming(assert, issuer);
      const jwt = await jwtClaiming(assert, { iss: ACME }, issuer, assert.kid);
      expect(await verifier.verifyDelegationCredential(credential, { skipCache: true })).toMatchObject({ valid: true });
      expect(await verifier.verifyDelegationJwt(jwt, { skipCache: true })).toMatchObject({ valid: true });
    }
  });
});
