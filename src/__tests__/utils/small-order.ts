/**
 * Test helper: a small-order Ed25519 public key, and the one signature that verifies every message
 * under it. With A the identity point, R = identity and S = 0 satisfy [S]B = R + [k]A whatever k
 * is, so each verification path that imports a key itself must refuse such a key.
 */

import { base64url } from './encodings.js';

/** The identity point: a public key of order one. */
export const IDENTITY = Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0));

/** The identity point with the sign bit set, a second encoding of it. */
export const IDENTITY_SIGNED = Uint8Array.from(IDENTITY, (byte, i) => (i === 31 ? byte | 0x80 : byte));

/** R = identity, S = 0: valid for every message under a small-order key. */
export const UNIVERSAL_SIGNATURE = Uint8Array.from({ length: 64 }, (_, i) => (i === 0 ? 1 : 0));

/** A compact JWS under `header` over `payload`, carrying {@link UNIVERSAL_SIGNATURE}. */
export function forgedJws(header: Record<string, unknown>, payload: string): string {
  return `${base64url(JSON.stringify(header))}.${base64url(payload)}.${base64url(UNIVERSAL_SIGNATURE)}`;
}
