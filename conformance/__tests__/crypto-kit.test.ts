/**
 * The conformance kit signs credentials as the package checks them: the
 * vectors are minted with `signVC` and checked by the package's own
 * `embeddedSignatureVerifier`, which reads a credential through its signed
 * form (SPEC.md §7.8). A kit that signed another way would ship vectors that
 * hold another reading than the one the spec gives. It signs a proof's JWS as
 * a JWS library signs one, and under a header no library signs under where a
 * vector needs one.
 */

import { createPrivateKey } from 'node:crypto';
import { CompactSign } from 'jose';
import { canonicalize } from 'json-canonicalize';
import { describe, it, expect } from 'vitest';
import { signProofMeta, signVC } from '../crypto-kit.js';
import { ed25519Signer } from '../../src/__tests__/utils/ed25519-signer.js';
import { embeddedSignatureVerifier } from '../../src/delegation/embedded-signature.js';
import { ED25519_KEY_SIZE, ED25519_PKCS8_DER_HEADER } from '../../src/utils/ed25519-constants.js';
import { buildProofJwsPayload, type DelegationCredential } from '../../src/index.js';
import { crypto } from './helpers/delegation-vectors.js';

const UNSIGNED = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  id: 'urn:uuid:kit-credential',
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:user.example.com',
  credentialSubject: { id: 'did:web:agent.example.com' },
};

describe('signVC', () => {
  it('signs what the package verifies, and not a credential changed since', async () => {
    const { privateKey, jwk } = await ed25519Signer();
    const proof = await signVC(crypto, UNSIGNED, privateKey, 'did:web:user.example.com#key-1');
    const credential = { ...UNSIGNED, proof } as unknown as DelegationCredential;
    const verify = embeddedSignatureVerifier(crypto);

    expect(await verify(credential, jwk)).toEqual({ valid: true, reason: undefined });
    const changed = { ...credential, issuer: 'did:web:someone.else' } as DelegationCredential;
    expect(await verify(changed, jwk)).toEqual({ valid: false, reason: 'Signature verification failed' });
  });

  // A vector may need a credential signed as another canonicalizer writes it:
  // one that holds a number to no rule the package's does, say.
  it('signs what the canonicalizer it is given writes, the credential without its proof', async () => {
    const { publicKey, privateKey } = await ed25519Signer();
    const written: Array<Record<string, unknown>> = [];
    const canonicalize = (unsigned: Record<string, unknown>) => {
      written.push(unsigned);
      return `issuer's form of ${JSON.stringify(unsigned)}`;
    };
    const credential = { ...UNSIGNED, issuedAt: 2 ** 53, proof: { proofValue: 'replaced' } };

    const proof = await signVC(crypto, credential, privateKey, 'did:web:user.example.com#key-1', canonicalize);

    expect(written).toEqual([{ ...UNSIGNED, issuedAt: 2 ** 53 }]);
    const bytes = new TextEncoder().encode(`issuer's form of ${JSON.stringify(written[0])}`);
    const signature = new Uint8Array(Buffer.from(proof.proofValue!, 'base64url'));
    expect(await crypto.verify(bytes, signature, publicKey)).toBe(true);
  });
});

describe('signProofMeta', () => {
  const META = {
    did: 'did:web:server.example.com',
    kid: 'did:web:server.example.com#key-1',
    ts: 1_700_000_000,
    nonce: 'nonce-1',
    audience: 'did:web:client.example.com',
    sessionId: 'kyaos_1',
    requestHash: `sha256:${'0'.repeat(64)}`,
  };
  const signedPayload = () => canonicalize(buildProofJwsPayload(META));

  it('signs the JWS a JWS library signs over the proof payload, under the producer header', async () => {
    const { privateKey } = await ed25519Signer();
    const seed = Buffer.from(privateKey, 'base64').subarray(0, ED25519_KEY_SIZE);
    const key = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_DER_HEADER, seed]), format: 'der', type: 'pkcs8' });
    const jws = await new CompactSign(new TextEncoder().encode(signedPayload()))
      .setProtectedHeader({ alg: 'EdDSA', kid: META.kid })
      .sign(key);

    expect(await signProofMeta({ kid: META.kid, privateKey }, META)).toEqual({ jws, meta: META });
  });

  it('signs under the header it is given, as it is written, which no JWS library signs under', async () => {
    const { publicKey, privateKey } = await ed25519Signer();
    const header = { kid: META.kid, alg: 'HS256', typ: 'x' };

    const { jws, meta } = await signProofMeta({ kid: META.kid, privateKey }, META, header);

    const [writtenHeader, writtenPayload, signature] = jws.split('.') as [string, string, string];
    expect(meta).toBe(META);
    expect(Buffer.from(writtenHeader, 'base64url').toString('utf8')).toBe(JSON.stringify(header));
    expect(Buffer.from(writtenPayload, 'base64url').toString('utf8')).toBe(signedPayload());
    const signingInput = new TextEncoder().encode(`${writtenHeader}.${writtenPayload}`);
    expect(await crypto.verify(signingInput, new Uint8Array(Buffer.from(signature, 'base64url')), publicKey)).toBe(true);
  });
});
