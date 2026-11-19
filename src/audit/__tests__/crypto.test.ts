import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { base64url } from '../../__tests__/utils/encodings.js';
import { forgedJws, IDENTITY, IDENTITY_SIGNED } from '../../__tests__/utils/small-order.js';
import {
  CompactJwsAuditSignatureVerifier,
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
} from '../crypto.js';

const signerRef = {
  did: 'did:key:zAuditSigner',
  kid: 'did:key:zAuditSigner#key-1',
  alg: 'EdDSA' as const,
};

describe('audit cryptography adapters', () => {
  it('round-trips a compact JWS and binds payload, algorithm, KID, and DID', async () => {
    const { privateKey, publicKey } = await generateKeyPair('Ed25519');
    const signer = new CompactJwsAuditSigner(signerRef, privateKey);
    const payload = new TextEncoder().encode('canonical audit receipt');
    const jws = await signer.sign(payload);
    const verifier = new CompactJwsAuditSignatureVerifier({
      resolve: async ({ kid }) => kid === signerRef.kid ? publicKey : null,
    });

    await expect(verifier.verify(payload, jws, signerRef)).resolves.toBe(true);
    await expect(verifier.verify(new TextEncoder().encode('tampered'), jws, signerRef))
      .resolves.toBe(false);
    await expect(verifier.verify(payload, jws, {
      ...signerRef, did: 'did:key:zWrongController',
    })).resolves.toBe(false);
    await expect(verifier.verify(payload, jws, {
      ...signerRef, kid: `${signerRef.did}#unknown`,
    })).resolves.toBe(false);
    await expect(verifier.verify(payload, 'not-a-jws', signerRef)).resolves.toBe(false);
  });

  it('rejects a hash provider that violates the protocol digest format', async () => {
    class InvalidDigestCryptoProvider extends NodeCryptoProvider {
      override async hash(): Promise<string> {
        return 'SHA256:NOT-CANONICAL';
      }
    }
    const hasher = new CryptoProviderAuditHasher(new InvalidDigestCryptoProvider());
    await expect(hasher.sha256(new Uint8Array())).rejects.toThrow(/lowercase-hex/);
  });

  describe('a key handed over as a JWK', () => {
    const encoder = new TextEncoder();
    const forged = (payload: string): string => forgedJws({ alg: 'EdDSA', kid: signerRef.kid }, payload);

    it.each([
      ['says nothing of extractability', {}],
      ['says it is extractable', { ext: true }],
      ['says it is not extractable', { ext: false }],
    ])('refuses a small-order key whose JWK %s', async (_case, extractability) => {
      const jwk = { kty: 'OKP', crv: 'Ed25519', x: base64url(IDENTITY), ...extractability };
      const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => jwk });
      const payload = '{"sequence":"7"}';

      await expect(verifier.verify(encoder.encode(payload), forged(payload), signerRef)).resolves.toBe(false);
    });

    it('verifies under a sound key whose JWK says it is not extractable', async () => {
      const { privateKey, publicKey } = await generateKeyPair('Ed25519', { extractable: true });
      const jwk = { ...(await exportJWK(publicKey)), ext: false };
      const payload = encoder.encode('canonical audit receipt');
      const jws = await new CompactJwsAuditSigner(signerRef, privateKey).sign(payload);
      const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => jwk });

      await expect(verifier.verify(payload, jws, signerRef)).resolves.toBe(true);
    });
  });

  describe('a key the resolver imported non-extractable', () => {
    const encoder = new TextEncoder();
    const forged = (payload: string): string => forgedJws({ alg: 'EdDSA', kid: signerRef.kid }, payload);

    it.each([
      ['the identity', IDENTITY],
      ['the identity with the sign bit set', IDENTITY_SIGNED],
    ])('refuses a small-order key, %s, that cannot be read back', async (_case, point) => {
      const key = await crypto.subtle.importKey('raw', point, { name: 'Ed25519' }, false, ['verify']);
      const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => key });
      const payload = 'any payload at all';

      await expect(verifier.verify(encoder.encode(payload), forged(payload), signerRef)).resolves.toBe(false);
    });

    it('verifies under a sound key that cannot be read back', async () => {
      const { privateKey, publicKey } = await generateKeyPair('Ed25519', { extractable: true });
      const raw = await crypto.subtle.exportKey('raw', publicKey as CryptoKey);
      const hidden = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
      const payload = encoder.encode('canonical audit receipt');
      const jws = await new CompactJwsAuditSigner(signerRef, privateKey).sign(payload);
      const verifier = new CompactJwsAuditSignatureVerifier({ resolve: async () => hidden });

      await expect(verifier.verify(payload, jws, signerRef)).resolves.toBe(true);
    });
  });
});
