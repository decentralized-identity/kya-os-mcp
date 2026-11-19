/**
 * Under a small-order Ed25519 public key one signature verifies every message:
 * with A the identity point, R = identity and S = 0 satisfy [S]B = R + [k]A
 * whatever k is. `jose`, WebCrypto and OpenSSL all accept such a key, so each
 * verification path that imports a key itself must refuse it. The providers
 * are covered in providers/__tests__/web-crypto.test.ts; these are the paths
 * that hand a JWK straight to `jose` or WebCrypto.
 */
import { describe, it, expect } from 'vitest';
import { exportJWK, generateKeyPair, importJWK } from 'jose';

import { CompactJwsAuditSignatureVerifier } from '../audit/crypto.js';
import { buildCardProof, verifyCardProof, verifyHttpSignature, type ProofSigner } from '../card/index.js';
import { verifyVcJwtSignature } from '../delegation/vc-jwt-verify.js';
import type { DIDResolver } from '../delegation/vc-verifier.js';
import { issuerDidDocument, methodOf } from './utils/did-documents.js';
import { base64url } from './utils/encodings.js';
import { forgedJws, IDENTITY, IDENTITY_SIGNED, UNIVERSAL_SIGNATURE } from './utils/small-order.js';
import { generateDidKeyFromBytes } from '../utils/did-helpers.js';
import { AUD, NONCE, PROOF_KEY, REQ, clock, deps, keypair } from '../card/__tests__/proof-helpers.js';

const encoder = new TextEncoder();

const okp = (key: Uint8Array) => ({ kty: 'OKP', crv: 'Ed25519', x: base64url(key) });

describe.each([
  ['the identity point', IDENTITY],
  ['the identity point with the sign bit set', IDENTITY_SIGNED],
])('a small-order key (%s)', (_label, smallOrderKey) => {
  it('VC-JWT: an issuer publishing it cannot sign any payload', async () => {
    const did = generateDidKeyFromBytes(smallOrderKey);
    const kid = `${did}#key-1`;
    const resolver: DIDResolver = {
      resolve: async () => issuerDidDocument(methodOf({ did, kid, publicKey: Buffer.from(smallOrderKey).toString('base64') })),
    };
    const jwt = forgedJws(
      { alg: 'EdDSA', kid },
      JSON.stringify({ iss: did, vc: { credentialSubject: { scopes: ['admin:*'] } } }),
    );
    const result = await verifyVcJwtSignature(jwt, did, kid, resolver);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/small-order/);
  });

  it('VC-JWT: also when the key is published as publicKeyMultibase', async () => {
    const did = generateDidKeyFromBytes(smallOrderKey);
    const kid = `${did}#key-1`;
    const resolver: DIDResolver = {
      resolve: async () =>
        issuerDidDocument(methodOf({ did, kid, publicKey: Buffer.from(smallOrderKey).toString('base64') }, { form: 'multibase' })),
    };
    const result = await verifyVcJwtSignature(forgedJws({ alg: 'EdDSA', kid }, '{}'), did, kid, resolver);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/small-order/);
  });

  it('card proof: a detached JWS under it is an invalid signature', async () => {
    const { signer } = await keypair();
    // No cnf, so nothing but the signature ties the proof to a key.
    const noCnf: ProofSigner = { did: signer.did, kid: signer.kid, sign: signer.sign };
    const env = await buildCardProof(REQ, noCnf, { audience: AUD, nonce: NONCE, now: clock });
    const proof = env[PROOF_KEY];
    const [protectedHeader] = proof.jws.split('.');
    const forged = { ...proof, jws: `${protectedHeader}..${base64url(UNIVERSAL_SIGNATURE)}` };
    const key = { ...okp(smallOrderKey), kid: signer.kid } as Parameters<typeof deps>[0];

    const result = await verifyCardProof(forged, REQ, deps(key));
    expect(result.ok).toBe(false);
    expect(result.reasons).toEqual(['invalid_signature']);
  });

  it('card proof: an RFC 9421 HTTP signature under it does not verify', async () => {
    const { signer } = await keypair();
    const env = await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock });
    const forged = { ...env[PROOF_KEY], httpSig: base64url(UNIVERSAL_SIGNATURE) };
    const key = { ...okp(smallOrderKey), kid: signer.kid } as Parameters<typeof verifyHttpSignature>[1];
    expect(await verifyHttpSignature(forged, key)).toBe(false);
  });

  it.each([
    ['a JWK', async (key: Uint8Array) => okp(key)],
    ['an imported CryptoKey', async (key: Uint8Array) => importJWK(okp(key), 'EdDSA')],
  ])('audit: a compact JWS under it, resolved as %s, does not verify', async (_form, resolveAs) => {
    const signerRef = { did: 'did:key:zAuditSigner', kid: 'did:key:zAuditSigner#key-1', alg: 'EdDSA' as const };
    const payload = 'canonical audit receipt';
    const resolved = await resolveAs(smallOrderKey);
    const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => resolved as never });
    const jws = forgedJws({ alg: 'EdDSA', kid: signerRef.kid }, payload);
    await expect(verifier.verify(encoder.encode(payload), jws, signerRef)).resolves.toBe(false);
  });
});

describe('audit verification still accepts ordinary keys in every form', () => {
  const signerRef = { did: 'did:key:zAuditSigner', kid: 'did:key:zAuditSigner#key-1', alg: 'EdDSA' as const };

  it('verifies under a JWK the resolver returns', async () => {
    const { CompactJwsAuditSigner } = await import('../audit/crypto.js');
    const { privateKey, publicKey } = await generateKeyPair('Ed25519', { extractable: true });
    const payload = encoder.encode('canonical audit receipt');
    const jws = await new CompactJwsAuditSigner(signerRef, privateKey).sign(payload);
    const jwk = await exportJWK(publicKey);
    const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => jwk });
    await expect(verifier.verify(payload, jws, signerRef)).resolves.toBe(true);
  });

  it('fails closed on a raw secret where an Ed25519 key belongs', async () => {
    const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => new Uint8Array(32) });
    const jws = forgedJws({ alg: 'EdDSA', kid: signerRef.kid }, 'x');
    await expect(verifier.verify(encoder.encode('x'), jws, signerRef)).resolves.toBe(false);
  });
});
