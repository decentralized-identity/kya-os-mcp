/**
 * Key-format shims between the demo's identities (raw Ed25519 seed/public key
 * in base64, the SDK's `Identity` convention) and what the audit protocol wants
 * (a WebCrypto `CryptoKey` for signing, an OKP JWK for verification).
 */
import { publicKeyToJwk } from '@kya-os/mcp';
import type { KeyedIdentity } from './wiring.js';

const ED25519_PKCS8_HEADER = Buffer.from('302e020100300506032b657004220420', 'hex');

/** An Ed25519 seed (base64) as a non-extractable WebCrypto signing handle. */
export async function signingKeyFor(identity: Pick<KeyedIdentity, 'privateKeyBase64'>): Promise<CryptoKey> {
  const seed = Buffer.from(identity.privateKeyBase64, 'base64').subarray(0, 32);
  const pkcs8 = Buffer.concat([ED25519_PKCS8_HEADER, seed]);
  return globalThis.crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
}

/** OKP/Ed25519 JWK (with kid) from a standard-base64 public key. */
export function jwkFor(publicKeyBase64: string, kid: string): Record<string, unknown> {
  return { ...publicKeyToJwk(new Uint8Array(Buffer.from(publicKeyBase64, 'base64'))), kid };
}
