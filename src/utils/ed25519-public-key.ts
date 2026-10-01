/**
 * Strict decoding of the base64 Ed25519 public keys the CryptoProviders verify
 * against, and the small-order check every Ed25519 verification path applies.
 *
 * Node's base64 decoder skips characters it does not recognise and accepts any
 * length, so `NodeCryptoProvider` used to verify against keys that
 * `WebCryptoProvider` rejected (a 64-byte "key", a key with junk appended).
 * Both providers now decode through here: exactly 32 bytes, nothing but ASCII
 * whitespace besides the key, and never a small-order point.
 */

import { base64ToBytes } from './base64.js';
import { ED25519_KEY_SIZE } from './ed25519-constants.js';

/** 32 bytes as base64 or base64url: 43 characters, optionally one `=` of padding. */
const ED25519_PUBLIC_KEY_BASE64 = /^[A-Za-z0-9+/_-]{43}=?$/;

/**
 * ASCII whitespace, which both base64 decoders the providers used before
 * (Node's Buffer, and `atob`) skip: a key read from a file keeps its newline.
 */
const ASCII_WHITESPACE = /[\t\n\f\r ]/g;

/**
 * Encodings of the points of order 1, 2, 4 and 8, as libsodium blocks them
 * (`ge25519_has_small_order`), including the non-canonical `p` and `p + 1`
 * forms. Under such a key, the signature R = identity, S = 0 satisfies the
 * verification equation for every message, so anyone could sign as it.
 * Compared with the sign bit (top bit of the last byte) masked off.
 */
const SMALL_ORDER_ENCODINGS: readonly Uint8Array[] = [
  // 0 (order 4)
  new Uint8Array(32),
  // 1 (order 1): the identity
  Uint8Array.from([1, ...new Array<number>(31).fill(0)]),
  // order 8
  Uint8Array.from([
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
  ]),
  // order 8
  Uint8Array.from([
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
  ]),
  // p - 1 (order 2)
  Uint8Array.from([0xec, ...new Array<number>(30).fill(0xff), 0x7f]),
  // p, a non-canonical 0 (order 4)
  Uint8Array.from([0xed, ...new Array<number>(30).fill(0xff), 0x7f]),
  // p + 1, a non-canonical 1 (order 1)
  Uint8Array.from([0xee, ...new Array<number>(30).fill(0xff), 0x7f]),
];

/** True if `key` (32 bytes) encodes a point of small order, under either sign bit. */
export function isSmallOrderEd25519Key(key: Uint8Array): boolean {
  return SMALL_ORDER_ENCODINGS.some((blocked) =>
    blocked.every((byte, i) => (i === 31 ? (key[i]! & 0x7f) === byte : key[i] === byte)),
  );
}

/**
 * Decode a base64 (or base64url) Ed25519 public key, or `null` unless it is
 * exactly 32 bytes with nothing but ASCII whitespace besides it in the string,
 * and is not a small-order point.
 */
export function decodeEd25519PublicKey(publicKeyBase64: string): Uint8Array | null {
  const compact = publicKeyBase64.replace(ASCII_WHITESPACE, '');
  if (!ED25519_PUBLIC_KEY_BASE64.test(compact)) {
    return null;
  }
  const key = base64ToBytes(compact);
  if (key.length !== ED25519_KEY_SIZE || isSmallOrderEd25519Key(key)) {
    return null;
  }
  return key;
}

/**
 * True if `key` is an Ed25519 public CryptoKey on a small-order point. Paths
 * that import a JWK through `jose` or WebCrypto check the imported key, not
 * the JWK string: neither refuses a small-order point, and Node's JWK import
 * decodes `x` leniently (padding, junk, non-zero trailing bits), so a check on
 * the string can be sidestepped. A key that is not an extractable Ed25519
 * public key cannot be read back and is left to the verifier.
 */
export async function isSmallOrderEd25519CryptoKey(key: object): Promise<boolean> {
  // Typed as `object` so callers holding an opaque key handle (or the
  // Uint8Array secret jose returns for `oct` keys) need no casts.
  const { type, algorithm, extractable } = key as Partial<CryptoKey>;
  if (type !== 'public' || (algorithm as { name: string }).name !== 'Ed25519' || extractable !== true) {
    return false;
  }
  return isSmallOrderEd25519Key(new Uint8Array(await crypto.subtle.exportKey('raw', key as CryptoKey)));
}
