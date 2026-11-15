/**
 * What a verifier reads from a custom resolver's DID document is what the walk measured. The walk
 * measures own members, and a key lookup reads `verificationMethod`, `assertionMethod` and a
 * method's members by name, which would find a member the object inherits. So the walk admits an
 * object only when it can inherit no member under a name this realm's `Object.prototype` lacks: its
 * prototype is `null`, this realm's `Object.prototype`, or another realm's, told by a `constructor`
 * named `Object` that points back and by having no member name of its own beyond those. A prototype
 * built by hand to pass for one, carrying the document's keys as getters, is refused, and no getter
 * on it runs, during the walk or after it.
 */

import vm from 'node:vm';
import { beforeAll, describe, expect, it } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AgentIdentity } from '../../providers/base.js';
import { measureDidDocument } from '../did-document-walk.js';
import { DelegationCredentialVerifier, type DIDDocument } from '../vc-verifier.js';

const DID = 'did:web:root.example';
const NOT_PLAIN = { ok: false, reason: 'value is neither an array nor a plain object' };

/**
 * A prototype built by hand: no prototype of its own, a `constructor` function named `name` whose
 * `prototype` points back to it, and `members` beside that.
 */
function handBuiltPrototype(name: string, members: PropertyDescriptorMap = {}): object {
  const constructor = { [name]: function () {} }[name]!;
  const prototype: object = Object.create(null, { constructor: { value: constructor }, ...members });
  Object.defineProperty(constructor, 'prototype', { value: prototype });
  return prototype;
}

/** An object with `prototype` and the own members `own`. */
const inheriting = (prototype: object | null, own: Record<string, unknown>): Record<string, unknown> =>
  Object.assign(Object.create(prototype) as Record<string, unknown>, own);

let issuer: AgentIdentity;
beforeAll(async () => {
  issuer = await keyOf(DID, 'key');
});

describe('a document whose prototype is built by hand to pass for Object.prototype', () => {
  /** The issuer's real document, its keys moved to getters on a hand-built prototype that count their reads. */
  function disguised(counter: { reads: number }): DIDDocument {
    const real = issuerDidDocument(methodOf(issuer));
    const getter = (value: unknown): PropertyDescriptor => ({
      get() {
        counter.reads += 1;
        return value;
      },
    });
    const prototype = handBuiltPrototype('Object', {
      verificationMethod: getter(real.verificationMethod),
      assertionMethod: getter(real.assertionMethod),
    });
    return inheriting(prototype, { id: real.id, '@context': real['@context'] }) as unknown as DIDDocument;
  }

  it('is refused by the walk, which reads none of its getters', () => {
    const counter = { reads: 0 };
    expect(measureDidDocument(disguised(counter))).toEqual(NOT_PLAIN);
    expect(counter.reads).toBe(0);
  });

  it('verifies no credential, and no getter on it is read during the walk or after it', async () => {
    const counter = { reads: 0 };
    const document = disguised(counter);
    const verifier = new DelegationCredentialVerifier({
      didResolver: { resolve: async (did) => (did === issuer.did ? document : null) },
      signatureVerifier: createRealSignatureVerifier(new NodeCryptoProvider()),
    });
    const result = await verifier.verifyDelegationCredential(await signedCredential(issuer), { skipCache: true });
    expect(result).toMatchObject({ valid: false, stage: 'signature', reason: `Could not resolve issuer DID: "${DID}"` });
    expect(counter.reads).toBe(0);
  });

  it('is refused when the member it carries is plain data, a symbol, or not enumerable', () => {
    for (const members of [
      { service: { value: [], enumerable: true } },
      { verificationMethod: { value: [] } },
      { [Symbol('hidden')]: { value: 1 } },
    ] as PropertyDescriptorMap[]) {
      expect(measureDidDocument(inheriting(handBuiltPrototype('Object', members), { id: DID }))).toEqual(NOT_PLAIN);
    }
  });

  it('is refused on a nested object as on the document itself', () => {
    const method = inheriting(handBuiltPrototype('Object', { publicKeyJwk: { get: () => ({ x: 'a' }) } }), { id: '#key' });
    expect(measureDidDocument({ id: DID, verificationMethod: [method] })).toEqual(NOT_PLAIN);
  });
});

describe('a prototype that is not an Object.prototype', () => {
  it('is refused when its constructor is not named Object, though it points back and carries nothing else', () => {
    expect(measureDidDocument(inheriting(handBuiltPrototype('Thing'), { id: DID }))).toEqual(NOT_PLAIN);
    expect(measureDidDocument(inheriting(handBuiltPrototype(''), { id: DID }))).toEqual(NOT_PLAIN);
  });

  it('is refused when its constructor reports the name Object through a getter, which is not run', () => {
    const prototype = handBuiltPrototype('Thing');
    let reads = 0;
    Object.defineProperty((prototype as { constructor: object }).constructor, 'name', {
      get() {
        reads += 1;
        return 'Object';
      },
    });
    expect(measureDidDocument(inheriting(prototype, { id: DID }))).toEqual(NOT_PLAIN);
    expect(reads).toBe(0);
  });

  it('is refused when its constructor is not a function, or does not point back to it', () => {
    const noFunction: object = Object.create(null, { constructor: { value: { name: 'Object' } } });
    Object.defineProperty((noFunction as { constructor: object }).constructor, 'prototype', { value: noFunction });
    expect(measureDidDocument(inheriting(noFunction, { id: DID }))).toEqual(NOT_PLAIN);
    const pointsElsewhere: object = Object.create(null, { constructor: { value: function Object() {} } });
    expect(measureDidDocument(inheriting(pointsElsewhere, { id: DID }))).toEqual(NOT_PLAIN);
    expect(measureDidDocument(inheriting(Object.create(null) as object, { id: DID }))).toEqual(NOT_PLAIN);
  });
});

describe('a prototype the walk admits', () => {
  it('is null, this realm\'s Object.prototype, or the Object.prototype of another realm', () => {
    const bytes = JSON.stringify({ id: DID }).length;
    expect(measureDidDocument(inheriting(null, { id: DID }))).toEqual({ ok: true, bytes });
    expect(measureDidDocument({ id: DID })).toEqual({ ok: true, bytes });
    expect(measureDidDocument(vm.runInNewContext(`({ id: '${DID}' })`))).toEqual({ ok: true, bytes });
  });

  it('carries only member names this realm\'s Object.prototype has, so no key of a document is inherited', () => {
    const bytes = JSON.stringify({ id: DID }).length;
    const sameNames = handBuiltPrototype('Object', { toString: { value: () => 'x' }, hasOwnProperty: { value: () => true } });
    expect(measureDidDocument(inheriting(sameNames, { id: DID }))).toEqual({ ok: true, bytes });
    expect(measureDidDocument(inheriting(handBuiltPrototype('Object'), { id: DID }))).toEqual({ ok: true, bytes });
  });
});
