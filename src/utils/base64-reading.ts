/**
 * Base64 text read to bytes by the protocol's own rules: a segment of a
 * response proof's JWS, and the `x` of the key it is checked with, exactly as
 * RFC 7515 §2 writes base64url (SPEC.md §7.4); a segment of a VC-JWT, as the
 * JWS libraries that verify one read it (SPEC.md §7.8); and a credential's
 * `proofValue`, which is read more loosely still because the decoders that
 * read one differ. No runtime decoder is used, so a string reads the same on
 * every runtime.
 *
 * `./base64.ts` decodes through the runtime, for the values SPEC.md states no
 * reading for. What it accepts is no reading of this module: it reads `+`,
 * `/` and padding one `=` short of a group, which only the `proofValue`
 * reading passes, it refuses a last group of one character, and white space
 * that changes the length a string is padded to, which that reading passes,
 * and it differs between runtimes. A value whose reading SPEC.md states is
 * read here.
 *
 * Each reading gives the bytes, or undefined for a string outside it, and
 * leaves it to the caller to say what such a string is.
 */

/** The six-bit value of each base64url character (RFC 4648 §5). */
const BASE64URL = new Map<string, number>(
  [...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'].map(
    (character, value): [string, number] => [character, value],
  ),
);

/** The same, with the characters base64 (RFC 4648 §4) writes for 62 and 63. */
const BASE64_EITHER = new Map(BASE64URL).set('+', 62).set('/', 63);

/** ASCII whitespace: passed over wherever it stands in an encoded string. */
const WHITESPACE = new Set([' ', '\t', '\n', '\r', '\f']);

/** What {@link readSixBits} read of a string. */
interface SixBitRead {
  /** The whole bytes its characters give. */
  bytes: Uint8Array;
  /** How many characters of the alphabet it holds. */
  characters: number;
  /** How many `=` follow the last of them. */
  padding: number;
}

/**
 * The characters of `alphabet` in `encoded`, in order, six bits each, as
 * whole bytes. ASCII whitespace is passed over, `=` may only follow the last
 * character of the alphabet, and bits short of a byte are dropped.
 * Undefined for any other character, or one of the alphabet after a `=`.
 */
function readSixBits(encoded: string, alphabet: ReadonlyMap<string, number>): SixBitRead | undefined {
  const bytes = new Uint8Array(Math.floor((encoded.length * 6) / 8));
  let length = 0;
  let buffer = 0;
  let bits = 0;
  let characters = 0;
  let padding = 0;
  for (const character of encoded) {
    if (WHITESPACE.has(character)) continue;
    if (character === '=') {
      padding += 1;
      continue;
    }
    const value = padding > 0 ? undefined : alphabet.get(character);
    if (value === undefined) return undefined;
    characters += 1;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[length++] = (buffer >> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }
  return { bytes: bytes.subarray(0, length), characters, padding };
}

/**
 * The bytes a `proofValue` carries (SPEC §7.8): its base64 or base64url
 * characters in order, six bits each, as whole bytes. ASCII whitespace is
 * passed over, `=` may only follow the last of those characters, as padding,
 * and bits short of a byte are dropped.
 *
 * It reads a little more than RFC 4648 §5 writes on purpose. Padding, the
 * other alphabet, a line break and the spare bits of a last character all
 * occur in strings that decoders in use accept, and each gives another string
 * for one signature. Reading them to the same bytes is what makes the
 * signature one value. A JWS segment is not read this way: see
 * {@link jwsSegmentBytes}.
 */
export function base64EitherBytes(encoded: string): Uint8Array | undefined {
  return readSixBits(encoded, BASE64_EITHER)?.bytes;
}

/** A string of base64url characters alone: no white space, no `=`. */
const BASE64URL_ONLY = /^[A-Za-z0-9_-]*$/;

/**
 * The bytes base64url carries as RFC 7515 §2 writes it (SPEC §7.4): the
 * characters of the base64url alphabet alone, with no white space and no
 * `=`. A last group of one character starts a byte and gives none of it, and
 * is refused. Bits short of a byte are dropped.
 *
 * A response proof's JWS segments, and the `x` of the Ed25519 key it is
 * checked with, are read this way and no other: a proof has one string, so a
 * verifier that reads it as this one does reaches the same verdict.
 */
export function strictBase64urlBytes(encoded: string): Uint8Array | undefined {
  if (!BASE64URL_ONLY.test(encoded) || encoded.length % 4 === 1) return undefined;
  return readSixBits(encoded, BASE64URL)?.bytes;
}

/**
 * The bytes a segment of a VC-JWT carries (SPEC §7.8): base64url as RFC 7515
 * §2 has it, read no more loosely than the JWS libraries that verify a VC-JWT
 * read it, so that a credential that verifies has a digest. Its characters
 * are of the base64url alphabet alone. ASCII whitespace is passed over. `=`
 * may only complete the last group of four characters: two after a group of
 * two, one after a group of three, and none otherwise. A last group of one
 * character starts a byte and gives none of it, and is refused. Bits short of
 * a byte are dropped.
 *
 * This is the set of strings jose, the JWS library that verifies a VC-JWT
 * here, reads on both of its decoding paths, and the bytes it reads them to.
 * `+` and `/` are not base64url, and a JWS written with them was never one.
 * A response proof is not read this way: see {@link strictBase64urlBytes}.
 */
export function jwsSegmentBytes(encoded: string): Uint8Array | undefined {
  const read = readSixBits(encoded, BASE64URL);
  if (read === undefined) return undefined;
  const lastGroup = read.characters % 4;
  const completed = lastGroup !== 0 && read.padding === 4 - lastGroup;
  return lastGroup === 1 || (read.padding > 0 && !completed) ? undefined : read.bytes;
}

// `ignoreBOM` keeps a byte order mark in the text, where JSON refuses it.
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** `bytes` as UTF-8 that is well formed, a byte order mark kept in the text, or undefined. */
function utf8Text(bytes: Uint8Array | undefined): string | undefined {
  if (bytes === undefined) return undefined;
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return undefined;
  }
}

/**
 * The text a segment of a VC-JWT carries: its {@link jwsSegmentBytes} as
 * UTF-8 that is well formed, a byte order mark kept in the text. Undefined
 * for a segment that is not one, or whose bytes are not UTF-8.
 */
export function jwsSegmentText(encoded: string): string | undefined {
  return utf8Text(jwsSegmentBytes(encoded));
}

/**
 * The text a segment of a response proof's JWS carries: its
 * {@link strictBase64urlBytes} as UTF-8 that is well formed. Undefined for a
 * segment that is not so written, or whose bytes are not UTF-8.
 */
export function strictBase64urlText(encoded: string): string | undefined {
  return utf8Text(strictBase64urlBytes(encoded));
}
