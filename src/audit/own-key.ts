/**
 * The public half of an audit signer's private key, so the recorder and the
 * checkpoint builder can verify what their own key signed without being
 * handed a verifier.
 */
import { exportJWK, type JWK, type KeyObject } from 'jose';
import type { AuditVerificationKeyResolver } from './crypto.js';
import { sameSigner } from './recorder-authority.js';
import type { SignerRef } from './types.js';

/** A private key an audit signer signs with: a CryptoKey, a Node.js KeyObject or a private JWK. */
export type AuditSigningKey = CryptoKey | KeyObject | JWK;

/** The members of a public key of each key type the audit algorithms use (EdDSA, ES256). */
const PUBLIC_MEMBERS = {
  OKP: ['crv', 'x'],
  EC: ['crv', 'x', 'y'],
} as const satisfies Record<string, readonly string[]>;

function isJwk(key: AuditSigningKey): key is JWK {
  return 'kty' in key;
}

function isCryptoKey(key: CryptoKey | KeyObject): key is CryptoKey {
  return 'extractable' in key;
}

/** `key` as a JWK, when it is a private key whose members can be read. */
async function privateJwkOf(key: AuditSigningKey): Promise<JWK | undefined> {
  if (isJwk(key)) return key;
  if (key.type !== 'private') return undefined;
  if (isCryptoKey(key) && !key.extractable) return undefined;
  return exportJWK(key);
}

/**
 * The public key of the private signing key `key`, as a JWK of its public
 * members alone, or undefined when `key` does not yield it: a CryptoKey
 * created non-extractable, a public or secret key, or a key type no audit
 * algorithm uses.
 */
export async function publicJwkOf(key: AuditSigningKey): Promise<JWK | undefined> {
  const jwk = await privateJwkOf(key);
  if (jwk === undefined || typeof jwk.d !== 'string') return undefined;
  const kty = jwk.kty === 'OKP' ? 'OKP' : jwk.kty === 'EC' ? 'EC' : undefined;
  if (kty === undefined) return undefined;
  const members: Readonly<Record<string, unknown>> = jwk;
  const publicKey: Record<string, string> = { kty };
  for (const member of PUBLIC_MEMBERS[kty]) {
    const value = members[member];
    if (typeof value !== 'string') return undefined;
    publicKey[member] = value;
  }
  return publicKey as JWK;
}

/** A resolver that knows one key: `publicKey`, for the signer `ref` alone. */
export function ownKeyResolver(ref: SignerRef, publicKey: JWK): AuditVerificationKeyResolver {
  return { resolve: async (signer) => (sameSigner(signer, ref) ? publicKey : null) };
}
