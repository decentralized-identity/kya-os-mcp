import { describe, it, expect } from 'vitest';
import { importJWK } from 'jose';
import {
  decodeEd25519PublicKey,
  isSmallOrderEd25519CryptoKey,
  isSmallOrderEd25519Key,
} from '../ed25519-public-key.js';
import { base64urlEncodeFromBytes, bytesToBase64 } from '../base64.js';

const hex = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));

/** The small-order encodings libsodium blocks, before the sign bit is applied. */
const SMALL_ORDER = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

describe('isSmallOrderEd25519Key', () => {
  it.each(SMALL_ORDER)('blocks %s under either sign bit', (encoding) => {
    const key = hex(encoding);
    expect(isSmallOrderEd25519Key(key)).toBe(true);
    key[31] = key[31]! ^ 0x80;
    expect(isSmallOrderEd25519Key(key)).toBe(true);
  });

  it('passes ordinary keys', () => {
    for (let i = 0; i < 100; i++) {
      const key = crypto.getRandomValues(new Uint8Array(32));
      expect(isSmallOrderEd25519Key(key)).toBe(false);
    }
  });
});

describe('decodeEd25519PublicKey', () => {
  const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

  it('decodes 32 bytes as padded base64, unpadded base64, or base64url', () => {
    const padded = bytesToBase64(key);
    expect(decodeEd25519PublicKey(padded)).toEqual(key);
    expect(decodeEd25519PublicKey(padded.replace(/=$/, ''))).toEqual(key);
    expect(decodeEd25519PublicKey(base64urlEncodeFromBytes(key))).toEqual(key);
  });

  it.each([
    ['empty', ''],
    ['31 bytes', bytesToBase64(key.subarray(0, 31))],
    ['64 bytes', bytesToBase64(new Uint8Array([...key, ...key]))],
    ['junk after the key', `${bytesToBase64(key)}!!!!`],
    ['a non-whitespace character inside', `${bytesToBase64(key).slice(0, 10)}.${bytesToBase64(key).slice(10)}`],
    ['a small-order point', bytesToBase64(hex(SMALL_ORDER[1]!))],
    ['a small-order point with a trailing newline', `${bytesToBase64(hex(SMALL_ORDER[1]!))}\n`],
    ['whitespace around 31 bytes', ` ${bytesToBase64(key.subarray(0, 31))}\n`],
  ])('rejects %s', (_label, input) => {
    expect(decodeEd25519PublicKey(input)).toBeNull();
  });

  it.each([
    ['a trailing newline (a key read from a file)', `${bytesToBase64(key)}\n`],
    ['CRLF and a leading space', ` ${bytesToBase64(key)}\r\n`],
    ['a line break inside (wrapped base64)', `${bytesToBase64(key).slice(0, 20)}\n${bytesToBase64(key).slice(20)}`],
    ['tabs and form feeds', `\t${base64urlEncodeFromBytes(key)}\f`],
  ])('ignores ASCII whitespace, as Node and atob do: %s', (_label, input) => {
    expect(decodeEd25519PublicKey(input)).toEqual(key);
  });
});

describe('isSmallOrderEd25519CryptoKey', () => {
  const okp = (bytes: Uint8Array) => ({ kty: 'OKP', crv: 'Ed25519', x: base64urlEncodeFromBytes(bytes) });

  it.each(SMALL_ORDER)('flags an imported %s under either sign bit', async (encoding) => {
    const bytes = hex(encoding);
    expect(await isSmallOrderEd25519CryptoKey(await importJWK(okp(bytes), 'EdDSA'))).toBe(true);
    bytes[31] = bytes[31]! ^ 0x80;
    expect(await isSmallOrderEd25519CryptoKey(await importJWK(okp(bytes), 'EdDSA'))).toBe(true);
  });

  it('reads the imported key, not the JWK string: a lenient x still decodes to the point', async () => {
    // Node's JWK import skips junk in `x`, so a check on the string alone could be sidestepped.
    const lenient = { ...okp(hex(SMALL_ORDER[1]!)), x: `${okp(hex(SMALL_ORDER[1]!)).x}!!` };
    expect(await isSmallOrderEd25519CryptoKey(await importJWK(lenient, 'EdDSA'))).toBe(true);
  });

  it('passes an ordinary Ed25519 public key', async () => {
    const { publicKey } = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
    expect(await isSmallOrderEd25519CryptoKey(publicKey)).toBe(false);
  });

  it('leaves alone what it cannot read back as an Ed25519 public key', async () => {
    const ed = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const hidden = await crypto.subtle.importKey('jwk', okp(hex(SMALL_ORDER[1]!)), { name: 'Ed25519' }, false, ['verify']);
    expect(await isSmallOrderEd25519CryptoKey(ed.privateKey)).toBe(false);
    expect(await isSmallOrderEd25519CryptoKey(ec.publicKey)).toBe(false);
    expect(await isSmallOrderEd25519CryptoKey(hidden)).toBe(false);
    expect(await isSmallOrderEd25519CryptoKey(new Uint8Array(32))).toBe(false);
  });
});
