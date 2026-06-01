import { base64url } from 'jose';

/**
 * PKCE (RFC 7636), S256 only.
 *
 * KYA-OS mandates the S256 challenge method — `plain` is never accepted. These
 * helpers are runtime-neutral and dependency-free beyond jose's base64url and
 * the Web Crypto API (available in Node 20+, edge runtimes, and browsers). No
 * Node-specific import, matching the package's runtime-neutral convention.
 */

export type S256 = 'S256';

/** True only for the S256 challenge method. */
export function isS256ChallengeMethod(method: string): method is S256 {
  return method === 'S256';
}

/** Compute the S256 code challenge for a verifier: BASE64URL(SHA-256(verifier)). */
export async function computeS256Challenge(codeVerifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return base64url.encode(new Uint8Array(digest));
}

/**
 * Verify a code verifier against its S256 challenge. Returns false on any
 * mismatch; never throws. The compare is length-checked and constant-time over
 * the challenge string.
 */
export async function verifyS256Challenge(
  codeVerifier: string,
  codeChallenge: string,
): Promise<boolean> {
  const expected = await computeS256Challenge(codeVerifier);
  return timingSafeEqual(expected, codeChallenge);
}

/** Length-checked constant-time string compare. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
