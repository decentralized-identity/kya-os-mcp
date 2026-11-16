/**
 * Base64 and base64url, encoded and decoded by the runtime: `Buffer` where there is one, `atob`,
 * `btoa` and `TextDecoder` otherwise, so that the helpers work in Node.js and in Cloudflare Workers.
 *
 * The decoders read what the runtime's decoder reads. That is none of the protocol's readings
 * (`./base64-reading.ts`), and it is not the same on every runtime:
 *
 * - `base64urlDecodeToString`, with `Buffer`: characters of either alphabet and no white space;
 *   `=` only where it completes the last group of four or falls one short of completing it; a last
 *   group of one character refused. The bytes are read as UTF-8, a byte that is not UTF-8 as
 *   U+FFFD, and a byte order mark stays in the text. Without `Buffer` it reads as the byte
 *   decoders do, and a byte order mark is dropped.
 * - `base64urlDecodeToBytes` and `base64ToBytes`, with `atob`: characters of either alphabet; `=`
 *   as above; ASCII white space passed over, but counted when the string is padded to a multiple
 *   of four, so a string with white space is read only when its length is the length its
 *   characters alone would be padded to. Without `atob`, `Buffer` reads every string: it passes
 *   over what is outside the alphabets and stops at the first `=`.
 *
 * These decoders remain, beside the protocol's readings, for the values SPEC.md states no reading
 * of its own for: among them a key a host configures, a card proof's signatures, audit evidence,
 * a status list's bits, and the segments of a VC-JWT as `parseVCJWT` reads them for verification.
 * None of the protocol's readings accepts exactly the strings these accept, so a caller moved from
 * one to the other would reach another verdict on the strings that differ.
 * `__tests__/base64.runtime-decoders.test.ts` holds what each accepts, string by string.
 */

export function base64urlDecodeToString(input: string): string {
  const padded = addPadding(input);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

  if (typeof Buffer !== 'undefined') {
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(base64)) {
      throw new Error('Invalid base64url string: contains invalid characters');
    }
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  if (typeof atob !== 'undefined') {
    const binaryString = atob(base64);
    if (typeof TextDecoder !== 'undefined') {
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return new TextDecoder().decode(bytes);
    }
    return binaryString;
  }

  throw new Error('Neither Buffer nor atob is available');
}

export function base64urlDecodeToBytes(input: string): Uint8Array {
  const padded = addPadding(input);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

  if (typeof atob !== 'undefined') {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  return new Uint8Array(Buffer.from(base64, 'base64'));
}

export function base64urlEncodeFromString(input: string): string {
  if (typeof Buffer !== 'undefined') {
    const base64 = Buffer.from(input, 'utf-8').toString('base64');
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  if (typeof btoa !== 'undefined') {
    const utf8Bytes = new TextEncoder().encode(input);
    const binaryString = Array.from(utf8Bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  throw new Error('Neither Buffer nor btoa is available');
}

export function base64urlEncodeFromBytes(bytes: Uint8Array): string {
  if (typeof btoa !== 'undefined') {
    const binaryString = Array.from(bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    const base64 = btoa(binaryString);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof btoa !== 'undefined') {
    const binaryString = Array.from(bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    return btoa(binaryString);
  }

  return Buffer.from(bytes).toString('base64');
}

/** Standard base64 or base64url to bytes: the reading of {@link base64urlDecodeToBytes}. */
export function base64ToBytes(base64: string): Uint8Array {
  return base64urlDecodeToBytes(base64);
}

function addPadding(input: string): string {
  const remainder = input.length % 4;
  if (remainder === 0) {
    return input;
  }
  return input + '='.repeat((4 - remainder) % 4);
}
