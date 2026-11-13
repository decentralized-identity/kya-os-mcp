/**
 * The `signed-proof/delegation-*` vectors (suite 1.5.0) that pin how a
 * credential is read (SPEC.md §7.8): a member its issuer named `__proto__`,
 * a number past those read exactly, how deep it nests, and a null where a
 * proof or a verifier gives one. Each turns on that reading and nothing else.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeJwt } from 'jose';
import { canonicalize } from 'json-canonicalize';
import { describe, it, expect } from 'vitest';
import { VECTORS_DIR } from '../loader.js';
import {
  DELEGATION_CREDENTIAL_DIGEST_DOMAIN,
  delegationChainDigest,
} from '../../src/delegation/chain-digest.js';
import { delegationCredentialId, delegationRefOf } from '../../src/delegation/delegation-ref.js';
import { NoSignedFormError, signedForm, signingInput } from '../../src/delegation/signed-form.js';
import type { SignedProofInput } from '../types.js';
import {
  type Credential,
  type Proof,
  byId,
  chainOf,
  crypto,
  digestOf,
  hash,
  inputOf,
  issuerSigned,
  keyOf,
  proofOf,
  verify,
} from './helpers/delegation-vectors.js';

describe('signed-proof/delegation-chain-proto-member', () => {
  it('binds a credential object whose issuer signed a member named __proto__, which its digest covers', async () => {
    const chain = chainOf('chain-proto-member');
    expect(chain).toHaveLength(1);
    const [credential] = chain as [Exclude<Credential, string>];
    expect(Object.getOwnPropertyNames(credential)).toContain('__proto__');
    expect(Object.getPrototypeOf(credential)).toBe(Object.prototype);
    expect(await issuerSigned(credential)).toBe(true);
    expect(JSON.stringify(signedForm(credential))).toContain('"__proto__":"signed by the issuer"');
    expect(proofOf('chain-proto-member').meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(byId('chain-proto-member').expected).toBe('pass');
    expect((await verify(inputOf('chain-proto-member'))).outcome).toBe('pass');

    // A copy made member by member with assignment loses the member, and
    // with it the digest: a verifier that copies so rejects this vector.
    const assigned: Record<string, unknown> = {};
    for (const key of Object.keys(credential)) assigned[key] = (credential as Record<string, unknown>)[key];
    expect(Object.getOwnPropertyNames(assigned)).not.toContain('__proto__');
    expect(await digestOf([assigned as Credential])).not.toBe(await digestOf(chain));
  });
});

describe('signed-proof/delegation-chain-number-read-as-binary64', () => {
  it('binds no credential object holding 9007199254740993.5, which reads as an integer above 2^53 - 1', async () => {
    const chain = chainOf('chain-number-read-as-binary64');
    expect(chain).toHaveLength(1);
    const [credential] = chain as [Exclude<Credential, string>];
    // The file holds the number as written, no integer, and it is read as
    // the binary64 value nearest it, an integer past those read exactly.
    const text = readFileSync(join(VECTORS_DIR, 'signed-proof.json'), 'utf8');
    expect(text.split('"ceiling": 9007199254740993.5')).toHaveLength(2);
    const ceiling = credential.credentialSubject.delegation.metadata?.['ceiling'];
    expect(ceiling).toBe(9007199254740994);
    expect(Number.isInteger(ceiling)).toBe(true);
    expect(Number.isSafeInteger(ceiling)).toBe(false);

    // Its issuer signed it as a canonicalizer that holds numbers to no rule
    // writes it, and the proof carries the digest that canonicalizer gives.
    expect(await issuerSignedUncounted(credential)).toBe(true);
    const { meta } = proofOf('chain-number-read-as-binary64');
    expect(meta.delegationChainDigest).toBe(await delegationChainDigest([await uncountedDigest(credential)], hash));
    expect(meta.delegationRef).toBe(credential.id);
    // The number is what there is to refuse: what its signature covers has
    // no canonical form, so no signature of it is checked and no digest taken.
    expect(() => signingInput(signedForm(credential))).toThrow(NoSignedFormError);
    expect(await issuerSigned(credential)).toBe(false);
    await expect(digestOf(chain)).rejects.toThrow(NoSignedFormError);
    // The largest integer read exactly in its place is signed content like any other.
    const { delegation } = credential.credentialSubject;
    const exact = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject, delegation: { ...delegation, metadata: { ceiling: 2 ** 53 - 1 } } },
    };
    await expect(digestOf([exact as Credential])).resolves.toMatch(/^sha256:[0-9a-f]{64}$/);

    const result = await verify(inputOf('chain-number-read-as-binary64'));
    expect(byId('chain-number-read-as-binary64').expected).toBe('fail');
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Delegation chain digest mismatch/);
    // Without the chain the same proof verifies: nothing else is wrong with it.
    const { delegationChain: _chain, ...rest } = inputOf('chain-number-read-as-binary64').expected!;
    expect((await verify({ ...inputOf('chain-number-read-as-binary64'), expected: rest })).outcome).toBe('pass');
  });
});

/**
 * The issuer's signature over RFC 8785 of the credential without its proof,
 * checked with another canonicalizer, which applies no bound and no rule to
 * numbers.
 */
async function issuerSignedUncounted(credential: Exclude<Credential, string>): Promise<boolean> {
  const { proof, ...unsigned } = credential;
  const issuer = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
  return crypto.verify(
    new TextEncoder().encode(canonicalize(unsigned as never)),
    Buffer.from(String(proof.proofValue), 'base64url'),
    Buffer.from(String(keyOf(issuer).x), 'base64url').toString('base64'),
  );
}

/** The credential digest of §7.8 taken by hand, with that canonicalizer. */
async function uncountedDigest(credential: Exclude<Credential, string>): Promise<string> {
  const { proof, ...unsigned } = credential;
  const signedFormJcs = canonicalize({ credential: unsigned, signature: proof.proofValue } as never);
  return crypto.hash(new TextEncoder().encode(`${DELEGATION_CREDENTIAL_DIGEST_DOMAIN}\0${signedFormJcs}`));
}

// SPEC §7.8: the arrays and objects of a credential nest at most 64 levels
// deep. Each of these vectors is a credential at the bound or one level past
// it, and differs from a credential any implementation accepts in that alone.
describe('signed-proof/delegation-*-nested-* vectors', () => {
  /** How deep the arrays and objects of a value nest, by a walk of its own. */
  const depthOf = (value: unknown): number =>
    typeof value !== 'object' || value === null ? 0 : 1 + Math.max(0, ...Object.values(value).map(depthOf));
  const payloadOf = (jwt: string) => decodeJwt<{ vc: { id: string } }>(jwt);

  it('chain-nested-at-bound: a credential object 64 levels deep, signed by its issuer, digested and bound', async () => {
    const chain = chainOf('chain-nested-at-bound');
    expect(chain).toHaveLength(1);
    const [credential] = chain as [Exclude<Credential, string>];
    expect(depthOf(credential)).toBe(64);
    expect(await issuerSigned(credential)).toBe(true);
    const { meta } = proofOf('chain-nested-at-bound');
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    // The bound changes no digest: taken by hand it is the same.
    expect(meta.delegationChainDigest).toBe(await delegationChainDigest([await uncountedDigest(credential)], hash));
    expect(meta.delegationRef).toBe(credential.id);
    expect(byId('chain-nested-at-bound').expected).toBe('pass');
    expect((await verify(inputOf('chain-nested-at-bound'))).outcome).toBe('pass');
  });

  it('chain-nested-past-bound: a credential object 65 levels deep, rejected for its depth alone', async () => {
    const chain = chainOf('chain-nested-past-bound');
    expect(chain).toHaveLength(1);
    const [credential] = chain as [Exclude<Credential, string>];
    expect(depthOf(credential)).toBe(65);
    // Its issuer did sign it, and the proof carries the digest §7.8 would
    // give it were there no bound: a verifier that counts nothing accepts.
    expect(await issuerSignedUncounted(credential)).toBe(true);
    const { meta } = proofOf('chain-nested-past-bound');
    expect(meta.delegationChainDigest).toBe(await delegationChainDigest([await uncountedDigest(credential)], hash));
    expect(meta.delegationRef).toBe(credential.id);
    // The depth is what there is to refuse: it has no signed form, so no
    // signature of it is checked and no digest of it is taken.
    expect(() => signedForm(credential)).toThrow(NoSignedFormError);
    expect(() => signedForm(credential)).toThrow('A credential object nests at most 64 levels deep');
    expect(await issuerSigned(credential)).toBe(false);
    await expect(digestOf(chain)).rejects.toThrow(NoSignedFormError);

    const result = await verify(inputOf('chain-nested-past-bound'));
    expect(byId('chain-nested-past-bound').expected).toBe('fail');
    expect(result.outcome).toBe('fail');
    expect(result.detail).toMatch(/Delegation chain digest mismatch/);
    // Without the chain the same proof verifies: nothing else is wrong with it.
    const { delegationChain: _chain, ...rest } = inputOf('chain-nested-past-bound').expected!;
    expect((await verify({ ...inputOf('chain-nested-past-bound'), expected: rest })).outcome).toBe('pass');
  });

  it('ref-jwt-nested-at-bound: a VC-JWT whose payload is 64 levels deep is read, and named by its id', async () => {
    const chain = chainOf('ref-jwt-nested-at-bound');
    expect(chain).toHaveLength(1);
    const [jwt] = chain as [string];
    expect(depthOf(payloadOf(jwt))).toBe(64);
    expect(await issuerSigned(jwt)).toBe(true);
    const { meta } = proofOf('ref-jwt-nested-at-bound');
    expect(meta.delegationRef).toBe(payloadOf(jwt).vc.id);
    expect(meta.delegationRef).toBe(await delegationRefOf(jwt, hash));
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(byId('ref-jwt-nested-at-bound').expected).toBe('pass');
    expect((await verify(inputOf('ref-jwt-nested-at-bound'))).outcome).toBe('pass');
  });

  it('ref-jwt-nested-past-bound: a VC-JWT whose payload is 65 levels deep is not read, so a refusal binds it and names none', async () => {
    const chain = chainOf('ref-jwt-nested-past-bound');
    expect(chain).toHaveLength(1);
    const [jwt] = chain as [string];
    // An authentic JWS whose payload a parser reads, and which carries an id
    // there: a verifier that counts nothing derives that id, and rejects.
    expect(depthOf(payloadOf(jwt))).toBe(65);
    expect(await issuerSigned(jwt)).toBe(true);
    expect(payloadOf(jwt).vc.id).toMatch(/^urn:uuid:/);
    expect(delegationCredentialId(jwt)).toBeUndefined();
    expect(await delegationRefOf(jwt, hash)).toBeUndefined();

    const { meta } = proofOf('ref-jwt-nested-past-bound');
    expect(meta.outcome).toBe('denied');
    expect(meta.responseHash).toBeUndefined();
    expect(meta).not.toHaveProperty('delegationRef');
    // Its segments are digested as they were received, which takes no reading of them.
    expect(meta.delegationChainDigest).toBe(await digestOf(chain));
    expect(inputOf('ref-jwt-nested-past-bound').expected!.outcome).toBe('denied');
    expect(byId('ref-jwt-nested-past-bound').expected).toBe('pass');
    expect((await verify(inputOf('ref-jwt-nested-past-bound'))).outcome).toBe('pass');
  });

  it('are the same credentials but for the one level: each pair differs in its depth and its id', () => {
    const [atBound] = chainOf('chain-nested-at-bound') as [Exclude<Credential, string>];
    const [pastBound] = chainOf('chain-nested-past-bound') as [Exclude<Credential, string>];
    expect(Object.keys(pastBound)).toEqual(Object.keys(atBound));
    expect(pastBound.issuer).toEqual(atBound.issuer);
    expect(pastBound.credentialSubject.id).toBe(atBound.credentialSubject.id);
    const [atBoundJwt] = chainOf('ref-jwt-nested-at-bound') as [string];
    const [pastBoundJwt] = chainOf('ref-jwt-nested-past-bound') as [string];
    expect(pastBoundJwt.split('.')[0]).toBe(atBoundJwt.split('.')[0]);
    expect(Object.keys(payloadOf(pastBoundJwt))).toEqual(Object.keys(payloadOf(atBoundJwt)));
  });
});

// The same readings conformance/verify.py holds itself to, so that a vector
// with a null in it gets one verdict from both implementations.
describe('a null in the signed-proof/delegation-* vectors', () => {
  /** The vector `id` with `members` stated in its `expected`, or in its proof's `meta`. */
  const restated = (id: string, part: 'expected' | 'meta', members: Record<string, unknown>): SignedProofInput => {
    const input = structuredClone(inputOf(id));
    Object.assign(part === 'meta' ? (input.proof as Proof).meta : input.expected!, members);
    return input;
  };

  it('is no chain where the verifier gives one: the chain is compared with nothing, and no outcome is asked for', async () => {
    expect((await verify(restated('chain-binding', 'expected', { delegationChain: null }))).outcome).toBe('pass');
    expect((await verify(restated('chain-refused', 'expected', { delegationChain: null }))).outcome).toBe('pass');
    expect((await verify(restated('chain-refused', 'expected', { delegationChain: null, outcome: null }))).outcome)
      .toBe('pass');
    const outcomeNull = await verify(restated('chain-refused', 'expected', { outcome: null }));
    expect(outcomeNull.outcome).toBe('fail');
    expect(outcomeNull.detail).toMatch(/Outcome mismatch/);
  });

  // Each claim is one the signed payload of that vector leaves out, so it is
  // its form alone that makes no proof of it.
  it.each([
    ['chain-unbound', 'delegationChainDigest', null],
    ['chain-unbound', 'delegationChainDigest', ''],
    ['ref-jwt-nested-past-bound', 'delegationRef', null],
    ['chain-unbound', 'outcome', null],
    ['chain-unbound', 'outcome', ''],
  ])('makes no proof of %s where meta gives %s as %j', async (id, claim, value) => {
    const { [claim]: signed } = decodeJwt(proofOf(id).jws);
    expect(signed).toBeUndefined();
    const result = await verify(restated(id, 'meta', { [claim]: value }));
    expect(result.outcome).toBe('fail');
    expect(result.detail).toBe('Invalid proof structure');
  });

  // An empty string is no null: a claim meta gives as one is one the
  // signature does not cover, and an outcome asked for as one is asked for.
  it('is not what an empty string is, in meta or in what the verifier asks', async () => {
    expect((await verify(restated('ref-jwt-nested-past-bound', 'meta', { delegationRef: '' }))).outcome).toBe('pass');
    const outcomeEmpty = await verify(restated('chain-binding', 'expected', { outcome: '' }));
    expect(outcomeEmpty.outcome).toBe('fail');
    expect(outcomeEmpty.detail).toMatch(/Outcome mismatch/);
  });
});
