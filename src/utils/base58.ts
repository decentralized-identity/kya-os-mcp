/**
 * Base58 Utilities (Bitcoin alphabet)
 *
 * Encoding and decoding utilities for Base58 (Bitcoin alphabet).
 * Used for did:key multibase encoding (with 'z' prefix for base58btc).
 *
 * The Bitcoin alphabet excludes ambiguous characters (0, O, I, l).
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_MAP = new Map<string, number>();

// Build reverse lookup map
for (let i = 0; i < ALPHABET.length; i++) {
  const char = ALPHABET[i];
  if (char !== undefined) {
    ALPHABET_MAP.set(char, i);
  }
}

/**
 * Encode bytes to Base58 (Bitcoin alphabet)
 *
 * @param bytes - Bytes to encode
 * @returns Base58-encoded string
 */
export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Convert bytes to big integer
  let num = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      num = num * BigInt(256) + BigInt(byte);
    }
  }

  // Convert to base58
  let result = '';
  while (num > 0) {
    result = ALPHABET[Number(num % BigInt(58))] + result;
    num = num / BigInt(58);
  }

  // Add leading zeros (encoded as '1' in base58)
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result = '1' + result;
  }

  return result;
}

/**
 * A `maxLength` for {@link base58Decode} on untrusted key material, in
 * characters. Decoding cost grows quadratically with input length, and key
 * material (did:key, `publicKeyMultibase`, `publicKeyBase58`) is read from
 * counterparty-controlled DIDs and DID documents; the package's own decoders
 * of it pass this bound or a tighter one. 1024 characters (~750 bytes) holds
 * any public key a DID publishes, RSA-4096 included, and decodes in well
 * under a millisecond.
 */
export const MAX_BASE58_DECODE_LENGTH = 1024;

/**
 * Decode Base58 (Bitcoin alphabet) to bytes
 *
 * @param encoded - Base58-encoded string
 * @param maxLength - Longest input accepted, in characters, checked before any
 *   decoding work. Unbounded when omitted; pass
 *   {@link MAX_BASE58_DECODE_LENGTH} (or tighter) for untrusted input.
 * @returns Decoded bytes
 * @throws Error if input contains invalid characters or exceeds `maxLength`
 * @throws RangeError if `maxLength` is given but is not a non-negative integer
 */
export function base58Decode(encoded: string, maxLength?: number): Uint8Array {
  // A NaN bound compares false and would silently mean "unbounded"; a
  // negative or fractional one is a caller bug either way.
  if (maxLength !== undefined && (!Number.isInteger(maxLength) || maxLength < 0)) {
    throw new RangeError(`base58Decode maxLength must be a non-negative integer, got ${maxLength}`);
  }
  if (maxLength !== undefined && encoded.length > maxLength) {
    throw new Error(`Base58 input exceeds ${maxLength} characters`);
  }
  if (encoded.length === 0) return new Uint8Array(0);

  // Convert base58 to big integer
  let num = BigInt(0);
  for (const char of encoded) {
    const value = ALPHABET_MAP.get(char);
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    num = num * BigInt(58) + BigInt(value);
  }

  // Convert big integer to bytes. Hex is a power-of-two radix, so toString(16)
  // is linear; repeated `% 256` / `/ 256` (and `unshift`) would be quadratic.
  let hex = num === BigInt(0) ? '' : num.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;

  // Count leading zeros in input (encoded as '1')
  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === '1') {
      leadingZeros++;
    } else {
      break;
    }
  }

  // Leading zero bytes are already 0 in a fresh Uint8Array
  const result = new Uint8Array(leadingZeros + hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[leadingZeros + i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return result;
}

/**
 * Validate a Base58 string
 *
 * @param encoded - String to validate
 * @returns true if valid Base58, false otherwise
 */
export function isValidBase58(encoded: string): boolean {
  if (encoded.length === 0) return true;

  for (const char of encoded) {
    if (!ALPHABET_MAP.has(char)) {
      return false;
    }
  }

  return true;
}
