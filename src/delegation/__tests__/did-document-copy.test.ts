/**
 * A verifier reads exactly what the walk measured in a custom resolver's DID document, because it
 * reads the walk's own copy: plain objects and arrays of this realm, holding each own enumerable
 * data member and each array element as the walk read it, once. So nothing the resolver's object
 * can do after that read reaches a verifier: an array's own or inherited `Symbol.iterator`, a
 * replaced `find` or `some`, a getter on an index that answers differently the second time, a
 * `Proxy`, a member that is not enumerable, or a change made once the walk is over.
 *
 * Each document here lists the issuer's real key where the walk measures it and hands a reader an
 * attacker's key, under the issuer's key id, by one of those routes. The credential is signed by
 * the attacker's key, so it verifies only if a reader took the smuggled method.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { createRealSignatureVerifier } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { keyOf, resignedCredential, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { AgentIdentity, FetchProvider } from '../../providers/base.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { SystemClockProvider } from '../../providers/system-clock.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { measureDidDocument } from '../did-document-walk.js';
import { isAdmittedDidDocument, resolveBoundedDid } from '../did-resource-limits.js';
import { DelegationCredentialVerifier, type DIDDocument, type VerificationMethod } from '../vc-verifier.js';

const DID = 'did:web:root.example';
const crypto = new NodeCryptoProvider();

let issuer: AgentIdentity;
let attacker: AgentIdentity;
/** A credential that names the issuer and its key id, signed by the attacker's key. */
let forged: DelegationCredential;
/** A credential the issuer signed. */
let genuine: DelegationCredential;
beforeAll(async () => {
  issuer = await keyOf(DID, 'key');
  attacker = await keyOf('did:web:attacker.example', 'key');
  genuine = await signedCredential(issuer);
  forged = await resignedCredential(genuine, {}, attacker, issuer.kid);
});

/** The attacker's key as a method of the issuer under the issuer's key id, counting each time it is handed out. */
function smuggler() {
  const state = { reads: 0 };
  const method = (): VerificationMethod => {
    state.reads += 1;
    return methodOf(attacker, { id: issuer.kid, controller: DID });
  };
  return { state, method };
}

/** Every way a reader can take the elements of an array without indexing it, answered from `entries`. */
function replacedMethods(entries: () => unknown[]): PropertyDescriptorMap {
  const names = ['find', 'some', 'every', 'filter', 'map', 'forEach', 'includes', 'findIndex', 'reduce', 'entries', 'values', 'flatMap', 'slice', 'at'] as const;
  const descriptors: PropertyDescriptorMap = {
    [Symbol.iterator]: { value: () => entries()[Symbol.iterator]() },
  };
  for (const name of names) {
    descriptors[name] = { value: (...args: unknown[]) => (entries()[name] as (...a: unknown[]) => unknown)(...args) };
  }
  return descriptors;
}

/** Each route, as the issuer's document with its `verificationMethod` array built to hand out `smuggled`. */
const ROUTES: [string, (real: VerificationMethod, smuggled: () => VerificationMethod) => unknown][] = [
  ['an own Symbol.iterator', (real, smuggled) =>
    Object.defineProperty([real], Symbol.iterator, { value: () => [smuggled()][Symbol.iterator]() })],
  ['an iterator inherited from a subclass', (real, smuggled) => {
    class Listed extends Array<unknown> {
      override [Symbol.iterator](): ArrayIterator<unknown> {
        return [smuggled()][Symbol.iterator]();
      }
    }
    return Listed.from([real]);
  }],
  ['an iterator inherited from a prototype set by hand', (real, smuggled) =>
    Object.setPrototypeOf([real], Object.create(Array.prototype, replacedMethods(() => [smuggled()])) as object)],
  ['own find, some and the other methods replaced', (real, smuggled) =>
    Object.defineProperties([real], replacedMethods(() => [smuggled()]))],
  ['a getter on its index that answers the real method once and the smuggled one after', (real, smuggled) => {
    let asked = 0;
    return Object.defineProperty([] as unknown[], 0, { enumerable: true, get: () => (asked++ === 0 ? real : smuggled()) });
  }],
  ['a Proxy that answers the real method once and the smuggled one after', (real, smuggled) => {
    let asked = 0;
    return new Proxy([real], { get: (target, key, receiver) => (key === '0' && asked++ > 0 ? smuggled() : Reflect.get(target, key, receiver) as unknown) });
  }],
];

/** The issuer's document with `verificationMethod` as `listed`, and the issuer's key id under `assertionMethod`. */
const documentListing = (listed: unknown): DIDDocument =>
  ({ id: DID, verificationMethod: listed, assertionMethod: [issuer.kid] }) as unknown as DIDDocument;

const verifierOver = (document: DIDDocument) =>
  new DelegationCredentialVerifier({
    didResolver: { resolve: async (did) => (did === DID ? document : null) },
    signatureVerifier: createRealSignatureVerifier(crypto),
  });

const proofVerifierOver = (document: DIDDocument) =>
  new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new SystemClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: { resolveDID: async () => document } as unknown as FetchProvider,
  });

describe.each(ROUTES)('a verificationMethod array with %s', (_route, build) => {
  it('does not verify a credential under the smuggled key, which no reader is handed', async () => {
    const { state, method } = smuggler();
    const document = documentListing(build(methodOf(issuer), method));
    const result = await verifierOver(document).verifyDelegationCredential(forged, { skipCache: true });
    expect(result).toMatchObject({ valid: false, stage: 'signature' });
    expect(state.reads).toBe(0);
  });

  it('still verifies a credential the issuer signed, under the key the walk measured', async () => {
    const { state, method } = smuggler();
    const document = documentListing(build(methodOf(issuer), method));
    expect(await verifierOver(document).verifyDelegationCredential(genuine, { skipCache: true })).toMatchObject({ valid: true });
    expect(state.reads).toBe(0);
  });

  it('gives ProofVerifier the key the walk measured, and never the smuggled one', async () => {
    const measured = methodOf(issuer).publicKeyJwk as { x: string };
    for (const kid of [issuer.kid, undefined]) {
      const { state, method } = smuggler();
      const document = documentListing(build(methodOf(issuer), method));
      expect(await proofVerifierOver(document).fetchPublicKeyFromDID(DID, kid)).toMatchObject({ x: measured.x });
      expect(state.reads).toBe(0);
    }
  });
});

describe('a document that changes once the walk has measured it', () => {
  it('does not verify a credential under a key swapped in after its methods were measured', async () => {
    const document = issuerDidDocument(methodOf(issuer)) as DIDDocument & { service: unknown[] };
    let swaps = 0;
    // The walk reads `service` last, and its element's getter swaps the methods it has measured.
    document.service = Object.defineProperty([] as unknown[], 0, {
      enumerable: true,
      get() {
        swaps += 1;
        document.verificationMethod = [methodOf(attacker, { id: issuer.kid, controller: DID })];
        return 'swapped';
      },
    });
    expect(await verifierOver(document).verifyDelegationCredential(forged, { skipCache: true })).toMatchObject({ valid: false, stage: 'signature' });
    expect(swaps).toBe(1);
  });
});

describe('a member the walk does not measure', () => {
  it('is not in what a verifier reads when it is not enumerable, as JSON would not write it', async () => {
    const document = Object.defineProperty({ id: DID, assertionMethod: [issuer.kid] }, 'verificationMethod', {
      value: [methodOf(attacker, { id: issuer.kid, controller: DID })],
    }) as unknown as DIDDocument;
    expect(measureDidDocument(document)).toMatchObject({ ok: true, bytes: JSON.stringify(document).length });
    expect(await verifierOver(document).verifyDelegationCredential(forged, { skipCache: true })).toMatchObject({ valid: false, stage: 'signature' });
    expect(await resolveBoundedDid({ resolve: async () => document }, DID)).toEqual({ id: DID, assertionMethod: [issuer.kid] });
  });
});

describe('the copy a verifier reads', () => {
  it('holds the document as JSON would write it, in plain frozen objects and arrays of this realm', async () => {
    const real = issuerDidDocument(methodOf(issuer));
    const subclassed = Object.assign(Object.create(null) as Record<string, unknown>, real, {
      verificationMethod: class extends Array<unknown> {}.from(real.verificationMethod!),
      ['__proto__']: 'kept as a member',
    });
    const copy = (await resolveBoundedDid({ resolve: async () => subclassed as unknown as DIDDocument }, DID))!;
    expect(JSON.stringify(copy)).toBe(JSON.stringify(subclassed));
    expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(copy.verificationMethod)).toBe(Array.prototype);
    expect(Object.getOwnPropertyDescriptor(copy, '__proto__')?.value).toBe('kept as a member');
    for (const part of [copy, copy.verificationMethod, copy.verificationMethod![0], copy.verificationMethod![0]!.publicKeyJwk]) {
      expect(Object.isFrozen(part)).toBe(true);
    }
    expect(isAdmittedDidDocument(copy)).toBe(true);
  });

  it('leaves the resolver its own object, unfrozen and unbranded', async () => {
    const document = issuerDidDocument(methodOf(issuer));
    const copy = await resolveBoundedDid({ resolve: async () => document }, DID);
    expect(copy).toEqual(document);
    expect(copy).not.toBe(document);
    expect([Object.isFrozen(document), Object.isFrozen(document.verificationMethod), isAdmittedDidDocument(document)]).toEqual([false, false, false]);
  });

  it('is what RuntimeFetchProvider returns for a configured resolver, so a later verifier does not walk it again', async () => {
    const document = issuerDidDocument(methodOf(issuer));
    const provider = new RuntimeFetchProvider({ didResolvers: { web: { resolve: async () => document } } });
    const resolved = (await provider.resolveDID(DID))!;
    expect(resolved).toEqual(document);
    expect([resolved === document, Object.isFrozen(resolved), isAdmittedDidDocument(resolved)]).toEqual([false, true, true]);
    expect(await resolveBoundedDid({ resolve: async () => resolved }, DID)).toBe(resolved);
  });
});
