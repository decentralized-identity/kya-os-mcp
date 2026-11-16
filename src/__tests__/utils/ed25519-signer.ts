/**
 * Test helper: a fresh Ed25519 key, and what a test signs and verifies with it.
 */
import { base64url } from './encodings.js';
import { nodeCrypto } from './node-crypto-provider.js';

/** A fresh Ed25519 key as a test holds it. */
export interface Ed25519Signer {
  /** The raw public key in base64, as a `CryptoProvider` takes one. */
  publicKey: string;
  /** The raw private key in base64, as a `CryptoProvider` takes one. */
  privateKey: string;
  /** The public key as a JWK. */
  jwk: { kty: 'OKP'; crv: 'Ed25519'; x: string };
  /** The key's signature over `data`, text as its UTF-8. */
  sign: (data: Uint8Array | string) => Promise<Uint8Array>;
}

export async function ed25519Signer(): Promise<Ed25519Signer> {
  const { publicKey, privateKey } = await nodeCrypto.generateKeyPair();
  return {
    publicKey,
    privateKey,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: base64url(Buffer.from(publicKey, 'base64')) },
    sign: (data) => nodeCrypto.sign(typeof data === 'string' ? new TextEncoder().encode(data) : data, privateKey),
  };
}
