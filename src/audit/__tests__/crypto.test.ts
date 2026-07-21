import { generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
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
});
