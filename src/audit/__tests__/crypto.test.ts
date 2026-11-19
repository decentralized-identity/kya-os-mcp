import { exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
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
    const b64url = (value: string | Uint8Array): string =>
      base64urlEncodeFromBytes(typeof value === 'string' ? encoder.encode(value) : value);
    /** The identity point: a public key of order one. */
    const identity = Uint8Array.from({ length: 32 }, (_, index) => (index === 0 ? 1 : 0));
    /** R = identity, S = 0: fits every message under such a key. */
    const anySignature = Uint8Array.from({ length: 64 }, (_, index) => (index === 0 ? 1 : 0));
    const forged = (payload: string): string =>
      `${b64url(JSON.stringify({ alg: 'EdDSA', kid: signerRef.kid }))}.${b64url(payload)}.${b64url(anySignature)}`;

    it.each([
      ['says nothing of extractability', {}],
      ['says it is extractable', { ext: true }],
      ['says it is not extractable', { ext: false }],
    ])('refuses a small-order key whose JWK %s', async (_case, extractability) => {
      const jwk = { kty: 'OKP', crv: 'Ed25519', x: b64url(identity), ...extractability };
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
});
