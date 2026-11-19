/**
 * W3C vc-di-eddsa (Recommendation, May 2025) has an `eddsa-jcs-2022` issuer state the document's
 * `@context` in the proof and sign it there (§3.3.1 step 2), and a verifier put `@context` in the
 * proof configuration only when the proof states one, which the document's `@context` must start
 * with (§3.3.2 step 4). From 1.22.0 to 1.25.0 the library's issuers signed the document's
 * `@context` without stating it in the proof, so a standard verifier refused every hop and status
 * list they signed, and the library's verifier refused a standard proof made without step 2.
 * These tests hold the issuers and the verifier to the Recommendation, and the verifier also to the
 * shape 1.22.0 to 1.25.0 issued, until 2.0.0 (DEPRECATIONS.md).
 */

import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { base58Decode } from '../../utils/base58.js';
import { eddsaJcs2022Verifies } from '../data-integrity.js';
import { DELEGATION_CONTEXT_V2 } from '../delegation.js';
import { createDelegationProofVerifier, signDelegationCredential } from '../delegation-proof.js';
import { ed25519SignerFromJwk } from '../proof/signer.js';
import { createStatusListProofVerifier, signStatusListCredential } from '../status-list-proof.js';
import { parties, signEddsaJcs2022, statusList, twoHopChain, type TestIdentity } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const verifyHop = createDelegationProofVerifier({ didResolver });
const verifyList = createStatusListProofVerifier({ didResolver });

const CREATED = '2026-11-01T00:00:00Z';
const OTHER_CONTEXT = 'https://example.com/other/v1';

/** W3C vc-di-eddsa Appendix B.3, Example 29: the public key of the pair that signs Example 39. */
const W3C_PUBLIC_KEY_MULTIBASE = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2';

/** W3C vc-di-eddsa Appendix B.3, Example 39: the signed credential, verbatim. */
const W3C_SIGNED_CREDENTIAL = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2',
  ],
  id: 'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',
  type: [
    'VerifiableCredential',
    'AlumniCredential',
  ],
  name: 'Alumni Credential',
  description: 'A minimum viable example of an Alumni Credential.',
  issuer: 'https://vc.example/issuers/5678',
  validFrom: '2023-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:example:abcdefgh',
    alumniOf: 'The School of Examples',
  },
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2023-02-24T23:36:38Z',
    verificationMethod: 'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2',
    proofPurpose: 'assertionMethod',
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2',
    ],
    proofValue: 'z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX',
  },
};

/** A Multikey Ed25519 public key as a JWK: base58btc, the multicodec prefix 0xed 0x01, then the key. */
function multikeyJwk(multibase: string): { kty: string; crv: string; x: string } {
  const bytes = base58Decode(multibase.slice(1));
  expect([...bytes.slice(0, 2)]).toEqual([0xed, 0x01]);
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(bytes.slice(2)).toString('base64url') };
}

/** The library's cryptosuite step over `document` with the key `jwk`, as both verifiers take it. */
function cryptosuiteVerifies(document: Record<string, unknown>, jwk: { kty: string; crv: string; x: string }): Promise<boolean> {
  const proof = document.proof as Record<string, unknown>;
  return eddsaJcs2022Verifies(document, proof, base58Decode(String(proof.proofValue).slice(1)), jwk);
}

/**
 * W3C vc-di-eddsa §3.3.2 written apart from the module under test and without the prefix rule of
 * step 4.1, so a test can show a signature holds where that rule alone refuses it: a `@context` the
 * proof states replaces the document's and is in the configuration, and one it does not state is in
 * neither. A standard verifier reads a proof so.
 */
function signedAsStated(document: Record<string, unknown>, signer: TestIdentity): boolean {
  const { proof, ...unsecured } = document as { proof: Record<string, unknown> } & Record<string, unknown>;
  const { proofValue, ...options } = proof;
  if (options['@context'] !== undefined) unsecured['@context'] = options['@context'];
  const hash = (value: unknown) => createHash('sha256').update(canonicalize(value)).digest();
  const signature = Buffer.from(base58Decode(String(proofValue).slice(1)));
  return verify(null, Buffer.concat([hash(options), hash(unsecured)]), createPublicKey(signer.privateKey), signature);
}

/** `signed` without its proof. */
function unsigned(signed: Record<string, unknown>): Record<string, unknown> {
  const { proof: _proof, ...rest } = signed;
  return rest;
}

/** A hop and a status list Acme issues, unsigned, and Acme. */
function acmeDocuments(): { acme: TestIdentity; hop: Record<string, unknown>; list: Record<string, unknown> } {
  const p = parties();
  return { acme: p.acme, hop: unsigned(twoHopChain(p)[0]), list: unsigned(statusList(p.acme)) };
}

describe('the W3C vc-di-eddsa eddsa-jcs-2022 example (Appendix B.3), verbatim', () => {
  const jwk = multikeyJwk(W3C_PUBLIC_KEY_MULTIBASE);

  it('verifies at the cryptosuite step both library verifiers take', async () => {
    expect(await cryptosuiteVerifies(W3C_SIGNED_CREDENTIAL, jwk)).toBe(true);
  });

  it('verifies without its proof @context, the shape 1.22.0 to 1.25.0 gave the same signature, until 2.0.0', async () => {
    const { '@context': _context, ...legacyProof } = W3C_SIGNED_CREDENTIAL.proof;
    expect(await cryptosuiteVerifies({ ...W3C_SIGNED_CREDENTIAL, proof: legacyProof }, jwk)).toBe(true);
  });

  it('is refused once a member it signs changes, in the document or in the proof @context', async () => {
    const renamed = { ...W3C_SIGNED_CREDENTIAL, name: 'Another Credential' };
    const proof = { ...W3C_SIGNED_CREDENTIAL.proof, '@context': ['https://www.w3.org/ns/credentials/v2'] };
    expect(await cryptosuiteVerifies(renamed, jwk)).toBe(false);
    expect(await cryptosuiteVerifies({ ...W3C_SIGNED_CREDENTIAL, proof }, jwk)).toBe(false);
  });

  it('goes no further in either library verifier, which take a key of the document issuer only (SPEC.md §6.10)', async () => {
    // The example's issuer is an https URL and its key a did:key, so neither verifier can apply it.
    expect(await verifyHop(W3C_SIGNED_CREDENTIAL)).toBe(false);
    expect(await verifyList(W3C_SIGNED_CREDENTIAL)).toBe(false);
  });
});

describe('a hop and a status list the library signs', () => {
  const signerOf = (party: TestIdentity) => ed25519SignerFromJwk({ did: party.did, kid: party.method, privateJwk: party.privateJwk });

  async function signedByLibrary(): Promise<{ acme: TestIdentity; hop: Record<string, unknown>; list: Record<string, unknown> }> {
    const { acme, hop, list } = acmeDocuments();
    return {
      acme,
      hop: await signDelegationCredential(hop as Parameters<typeof signDelegationCredential>[0], await signerOf(acme), { created: CREATED }),
      list: await signStatusListCredential(list, await signerOf(acme), { created: CREATED }),
    };
  }

  it('state the document @context in the proof, and the signature covers exactly that', async () => {
    const { acme, hop, list } = await signedByLibrary();
    for (const signed of [hop, list]) {
      expect((signed.proof as Record<string, unknown>)['@context']).toEqual(signed['@context']);
      expect(signedAsStated(signed, acme)).toBe(true);
    }
    expect(await verifyHop(hop)).toBe(true);
    expect(await verifyList(list)).toBe(true);
  });

  it('carry the signature 1.25.0 wrote, so a verifier of 1.20.0 to 1.25.0 accepts them', async () => {
    const { acme, hop, list } = await signedByLibrary();
    for (const signed of [hop, list]) {
      const { '@context': _context, ...legacyProof } = signed.proof as Record<string, unknown>;
      expect({ ...signed, proof: legacyProof }).toEqual(signEddsaJcs2022(unsigned(signed), acme, {}, 'legacy'));
    }
  });
});

describe('verifying an eddsa-jcs-2022 proof by where it states @context', () => {
  it('accepts a hop and a list whose issuer skipped §3.3.1 step 2 and signed no @context', async () => {
    const { acme, hop, list } = acmeDocuments();
    const signedHop = signEddsaJcs2022(hop, acme, {}, 'unstated');
    const signedList = signEddsaJcs2022(list, acme, {}, 'unstated');
    expect(signedHop.proof['@context']).toBeUndefined();
    expect(await verifyHop(signedHop)).toBe(true);
    expect(await verifyList(signedList)).toBe(true);
  });

  it('accepts a hop and a list as 1.22.0 to 1.25.0 signed them, and refuses either once changed', async () => {
    const { acme, hop, list } = acmeDocuments();
    const signedHop = signEddsaJcs2022(hop, acme, {}, 'legacy');
    const signedList = signEddsaJcs2022(list, acme, {}, 'legacy');
    expect(signedAsStated(signedHop, acme)).toBe(false);
    expect(await verifyHop(signedHop)).toBe(true);
    expect(await verifyList(signedList)).toBe(true);
    expect(await verifyHop({ ...signedHop, validUntil: '2028-01-01T00:00:00Z' })).toBe(false);
    expect(await verifyList({ ...signedList, validFrom: '2026-02-01T00:00:00Z' })).toBe(false);
  });

  it('refuses a proof whose @context the document does not start with, though its signature holds over the one it states', async () => {
    const { acme, list } = acmeDocuments();
    const signed = signEddsaJcs2022({ ...list, '@context': [DELEGATION_CONTEXT_V2, OTHER_CONTEXT] }, acme);
    const presented = { ...signed, '@context': list['@context'] };
    expect(signedAsStated(presented, acme)).toBe(true);
    expect(await verifyList(presented)).toBe(false);
    // A document that starts with the proof's @context is read with that @context (§3.3.2 step 4.2).
    const extended = { ...signed, '@context': [DELEGATION_CONTEXT_V2, OTHER_CONTEXT, 'https://example.com/later/v1'] };
    expect(await verifyList(extended)).toBe(true);
  });

  it('refuses a proof whose stated @context was changed after signing, to a prefix of the document @context or another', async () => {
    const { acme, hop } = acmeDocuments();
    const signed = signEddsaJcs2022(hop, acme);
    const restated = (context: unknown) => ({ ...signed, proof: { ...signed.proof, '@context': context } });
    expect(await verifyHop(signed)).toBe(true);
    expect(await verifyHop(restated([DELEGATION_CONTEXT_V2]))).toBe(false);
    expect(await verifyHop(restated([OTHER_CONTEXT]))).toBe(false);
  });
});
