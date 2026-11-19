/**
 * Changing a signature so that it no longer verifies, for the vectors a verifier must refuse.
 *
 * Each changes the FIRST character of a base64url signature, whose bits are all significant, so the
 * signature bytes are certain to change. Changing the LAST character is not a reliable tamper: the
 * 86 characters of a 64-byte Ed25519 signature carry only 2 significant bits in the last one, and a
 * decoder that ignores the 4 spare bits reads an 'A' put for a 'B' there as the same signature.
 */

/** `value`, a base64url signature, with its first character changed. */
export function flipB64url(value: string): string {
  const swap = value[0] === 'A' ? 'B' : 'A';
  return swap + value.slice(1);
}

/** `jws`, compact or detached, with the first character of its signature segment changed. */
export function flipSignatureChar(jws: string): string {
  const [header, payload, signature] = jws.split('.');
  return `${header}.${payload}.${flipB64url(signature!)}`;
}
