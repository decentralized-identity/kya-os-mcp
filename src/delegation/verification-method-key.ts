/**
 * Verification-method key extraction — one place that answers "what Ed25519
 * public key does this verification method publish?".
 *
 * The `VerificationMethod` type has always declared `publicKeyMultibase` and
 * `publicKeyBase58` alongside `publicKeyJwk`, but both signature paths read
 * only the JWK — so a did:cheqd issuer (which publishes multibase keys) could
 * never verify end-to-end. This helper converts at the point of use; resolvers
 * keep reporting DID documents exactly as published.
 *
 * FAIL-CLOSED: anything that is not provably a 32-byte Ed25519 key —
 * non-`z` multibase, wrong multicodec, wrong length, malformed base58 —
 * returns `undefined`, and the caller denies with its usual reason.
 */
import { base58Decode } from '../utils/base58.js';
import {
  publicKeyToJwk,
  ED25519_MULTICODEC_PREFIX,
  ED25519_PUBLIC_KEY_LENGTH,
} from './did-key-resolver.js';
import type { VerificationMethod } from './vc-verifier.types.js';

/** Multibase prefix for base58btc. */
const MULTIBASE_BASE58BTC = 'z';

/**
 * The verification method's public key as an Ed25519 OKP JWK: an existing
 * `publicKeyJwk` is returned untouched (byte-for-byte — zero behavior change
 * for documents that already publish JWKs); otherwise one is synthesized from
 * `publicKeyMultibase` (base58btc, with or without the 0xed01 multicodec
 * prefix) or legacy `publicKeyBase58`. `undefined` when no usable Ed25519 key
 * is present (fail-closed).
 */
export function verificationMethodJwk(
  method: VerificationMethod,
): { kty: string; crv: string; x: string } | undefined {
  if (method.publicKeyJwk) {
    return method.publicKeyJwk as { kty: string; crv: string; x: string };
  }

  const raw = rawEd25519Key(method);
  return raw ? publicKeyToJwk(raw) : undefined;
}

/** Decode multibase/base58 key material to raw bytes; `undefined` unless it is exactly a 32-byte Ed25519 key. */
function rawEd25519Key(method: VerificationMethod): Uint8Array | undefined {
  try {
    if (method.publicKeyMultibase?.startsWith(MULTIBASE_BASE58BTC)) {
      const decoded = base58Decode(method.publicKeyMultibase.slice(1));
      const stripped =
        decoded.length === ED25519_PUBLIC_KEY_LENGTH + ED25519_MULTICODEC_PREFIX.length &&
        decoded[0] === ED25519_MULTICODEC_PREFIX[0] &&
        decoded[1] === ED25519_MULTICODEC_PREFIX[1]
          ? decoded.slice(ED25519_MULTICODEC_PREFIX.length)
          : decoded;
      return stripped.length === ED25519_PUBLIC_KEY_LENGTH ? stripped : undefined;
    }
    if (method.publicKeyBase58) {
      const decoded = base58Decode(method.publicKeyBase58);
      return decoded.length === ED25519_PUBLIC_KEY_LENGTH ? decoded : undefined;
    }
  } catch {
    return undefined; // malformed base58 → fail-closed
  }
  return undefined;
}
