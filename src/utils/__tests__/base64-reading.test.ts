/**
 * Base64 text read to bytes by the protocol's own rules: a response proof's
 * JWS segments and its key's `x` as RFC 7515 §2 writes base64url (SPEC.md
 * §7.4), a VC-JWT's segments in the base64url alphabet of RFC 4648 §5 alone
 * (SPEC.md §7.8), and a proofValue in that alphabet or the base64 one of §4.
 * A character of none of them is refused, whatever it is.
 */
import { describe, expect, it } from 'vitest';
import { base64EitherBytes, jwsSegmentBytes, strictBase64urlBytes } from '../base64-reading.js';

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
/** What both readings pass over, or read as padding. */
const SET_ASIDE = ' \t\n\r\f=';
const ASCII = Array.from({ length: 128 }, (_, code) => String.fromCharCode(code));
const outside = (alphabet: string): string[] =>
  ASCII.filter((character) => !alphabet.includes(character) && !SET_ASIDE.includes(character));
const bytes = (text: string): Uint8Array => new Uint8Array(Buffer.from(text));

describe('the readings of base64 text', () => {
  // RFC 4648 §10, in the base64url alphabet and without padding.
  it.each([
    ['', ''],
    ['Zg', 'f'],
    ['Zm8', 'fo'],
    ['Zm9v', 'foo'],
    ['Zm9vYg', 'foob'],
    ['Zm9vYmE', 'fooba'],
    ['Zm9vYmFy', 'foobar'],
  ])('read %j as RFC 4648 §10 gives it', (encoded, decoded) => {
    expect(strictBase64urlBytes(encoded)).toEqual(bytes(decoded));
    expect(jwsSegmentBytes(encoded)).toEqual(bytes(decoded));
    expect(base64EitherBytes(encoded)).toEqual(bytes(decoded));
  });

  it('refuse in a proof segment every ASCII character outside the base64url alphabet, white space and = included', () => {
    for (const character of ASCII.filter((character) => !BASE64URL.includes(character))) {
      expect(strictBase64urlBytes(`Zm9v${character}Zm9v`)).toBeUndefined();
      expect(strictBase64urlBytes(`Zm9vZm9v${character}`)).toBeUndefined();
      expect(strictBase64urlBytes(`${character}Zm9vZm9v`)).toBeUndefined();
    }
  });

  it.each([
    ['the padding that completes a group of two', 'Zg=='],
    ['the padding that completes a group of three', 'Zm8='],
    ['a line break', 'Zm9v\nYmFy'],
    ['white space at either end', ' Zm9vYmFy\t'],
    ['a last group of one character, which gives no byte', 'Zm9vY'],
    ['a character outside ASCII', 'Zm9vé'],
  ])('refuse in a proof segment %s', (_name, encoded) => {
    expect(strictBase64urlBytes(encoded)).toBeUndefined();
  });

  it('refuse in a JWS segment every ASCII character outside the base64url alphabet', () => {
    for (const character of outside(BASE64URL)) {
      expect(jwsSegmentBytes(`Zm9v${character}Zm9v`)).toBeUndefined();
    }
  });

  it('refuse in a proofValue every ASCII character outside both alphabets', () => {
    for (const character of outside(`${BASE64URL}+/`)) {
      expect(base64EitherBytes(`Zm9v${character}Zm9v`)).toBeUndefined();
    }
  });
});
