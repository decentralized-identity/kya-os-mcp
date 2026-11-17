/**
 * `eddsa-jcs-2022` hashes the proof options and the document in their RFC 8785 form, in which a
 * member named `toJSON` is data like any other and every object's members are sorted. A signature
 * over plain JSON is the one it was before, byte for byte, and a document with no JSON form is
 * refused rather than signed or read as some other document.
 */

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { describe, expect, it } from 'vitest';
import { createStatusListProofVerifier, signStatusListCredential } from '../status-list-proof.js';
import { ed25519SignerFromJwk } from '../proof/signer.js';
import type { Ed25519PrivateJwk } from '../proof/types.js';
import { base58Encode } from '../../utils/base58.js';
import type { DIDDocument } from '../../delegation/vc-verifier.types.js';

const ISSUER = 'did:web:status.example';
const METHOD = `${ISSUER}#status-1`;
const CREATED = '2026-01-01T00:00:00Z';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const publicJwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
const privateJwk = privateKey.export({ format: 'jwk' }) as Ed25519PrivateJwk;
const didDocument: DIDDocument = {
  id: ISSUER,
  verificationMethod: [{ id: METHOD, type: 'JsonWebKey2020', controller: ISSUER, publicKeyJwk: publicJwk } as never],
  assertionMethod: [METHOD],
};
const verify = createStatusListProofVerifier({ didResolver: { resolve: async (did) => (did === ISSUER ? didDocument : null) } });
const signer = () => ed25519SignerFromJwk({ did: ISSUER, kid: METHOD, privateJwk });

/** A list credential whose subject is `subject`, its members in the order written. */
const listWith = (subject: Record<string, unknown>): Record<string, unknown> => ({
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'https://status.example/lists/1',
  type: ['VerifiableCredential', 'BitstringStatusListCredential'],
  issuer: ISSUER,
  validFrom: CREATED,
  credentialSubject: subject,
});

/** The same JSON value with every object's members in the reverse order. */
function reversed(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reversed);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).reverse().map(([key, member]) => [key, reversed(member)]));
}

/** RFC 8785 for the plain values these tests use, written apart from the module under test. */
function jcs(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${jcs((value as Record<string, unknown>)[key])}`).join(',')}}`;
}

/** An `eddsa-jcs-2022` proof made apart from the module under test, hashing with `canonical`. */
function signedApart(document: Record<string, unknown>, canonical: (value: unknown) => string): Record<string, unknown> {
  const proof = { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: CREATED, verificationMethod: METHOD, proofPurpose: 'assertionMethod' };
  const hash = (value: unknown) => createHash('sha256').update(canonical(value)).digest();
  const signature = sign(null, Buffer.concat([hash({ ...proof, '@context': document['@context'] }), hash(document)]), privateKey);
  return { ...document, proof: { ...proof, proofValue: `z${base58Encode(new Uint8Array(signature))}` } };
}

describe('eddsa-jcs-2022 over RFC 8785', () => {
  const subject = { type: 'BitstringStatusList', id: 'https://status.example/lists/1#list', toJSON: 'a member like any other', encodedList: 'uH4sIAAAAAAAAA' };

  it('reads a member named toJSON as data, so the same JSON value verifies in any member order', async () => {
    const signed = await signStatusListCredential(listWith(subject), await signer(), { created: CREATED });
    expect(await verify(signed)).toBe(true);
    expect(await verify(reversed(signed) as Record<string, unknown>)).toBe(true);
  });

  it('verifies a proof another implementation made over the RFC 8785 form of a document with a toJSON member', async () => {
    expect(await verify(signedApart(listWith(subject), jcs))).toBe(true);
  });

  it('signs plain JSON byte for byte as before', async () => {
    const plain = listWith({ type: 'BitstringStatusList', id: 'https://status.example/lists/1#list', encodedList: 'uH4sIAAAAAAAAA' });
    const signed = await signStatusListCredential(plain, await signer(), { created: CREATED });
    expect(signed).toEqual(signedApart(plain, (value) => canonicalize(value as Parameters<typeof canonicalize>[0])));
  });

  it('refuses to sign a document with no JSON form, and reads none as verified', async () => {
    const unset = listWith({ ...subject, statusMessage: undefined });
    await expect(signStatusListCredential(unset, await signer(), { created: CREATED })).rejects.toThrow(
      'Cannot canonicalize undefined at $.credentialSubject.statusMessage',
    );
    const signed = signedApart(listWith(subject), jcs);
    expect(await verify({ ...signed, credentialSubject: { ...subject, statusMessage: undefined } })).toBe(false);
  });
});
