import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, it, expect, vi } from 'vitest';
import { importJWK } from 'jose';
import {
  decodeEd25519PublicKey,
  isSmallOrderEd25519CryptoKey,
  isSmallOrderEd25519Key,
} from '../ed25519-public-key.js';
import { SMALL_ORDER_PROBE_MESSAGE, SMALL_ORDER_PROBE_SIGNATURE } from '../ed25519-small-order-probe.js';
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

/** The order of the group Ed25519 signs in. */
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const littleEndian = (bytes: Uint8Array) => bytes.reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
const toLittleEndian = (value: bigint) => Uint8Array.from({ length: 32 }, (_, i) => Number((value >> BigInt(8 * i)) & 0xffn));

/**
 * Whether the runtime verifies a forgery under `key`, whose bytes are `raw`, a point of small order A.
 * The forgery holds by the equation [S]B = R + [k]A without the cofactor, and with an R of large
 * order, so it is no probe: R = [a]B for a fresh key's scalar a, S = a mod L, and a message whose
 * challenge k is a multiple of 8, the order of every small-order point, so [k]A is the identity. A
 * runtime that refuses every signature under a small-order key verifies none.
 */
async function verifiesForgeryUnder(key: CryptoKey, raw: Uint8Array): Promise<boolean> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const seed = Buffer.from(privateKey.export({ format: 'jwk' }).d!, 'base64url');
  const r = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url');
  const expanded = createHash('sha512').update(seed).digest();
  expanded[0]! &= 248;
  expanded[31]! &= 127;
  expanded[31]! |= 64;
  const s = toLittleEndian(littleEndian(expanded.subarray(0, 32)) % L);
  for (let n = 0; ; n++) {
    const message = Buffer.from(`forgery:${n}`);
    if ((littleEndian(createHash('sha512').update(r).update(raw).update(message).digest()) % L) % 8n !== 0n) continue;
    return crypto.subtle.verify({ name: 'Ed25519' }, key, new Uint8Array([...r, ...s]), message);
  }
}

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

  it('leaves alone what is not an Ed25519 public key', async () => {
    const ed = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const ec = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    expect(await isSmallOrderEd25519CryptoKey(ed.privateKey)).toBe(false);
    expect(await isSmallOrderEd25519CryptoKey(ec.publicKey)).toBe(false);
    expect(await isSmallOrderEd25519CryptoKey(new Uint8Array(32))).toBe(false);
  });

  // Node 24.22.3, as the Secure Curves draft asks, verifies nothing under a small-order key, so
  // there is nothing to flag; Node 22 verifies under one, and every such key must be flagged. The
  // CI matrix runs both.
  it.each(SMALL_ORDER)('flags %s imported non-extractable, under either sign bit, exactly where the runtime would verify a forgery under it', async (encoding) => {
    const bytes = hex(encoding);
    for (const flip of [0, 0x80]) {
      const raw = Uint8Array.from(bytes, (byte, i) => (i === 31 ? byte | flip : byte));
      const hidden = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
      expect(hidden.extractable).toBe(false);
      expect(await isSmallOrderEd25519CryptoKey(hidden)).toBe(await verifiesForgeryUnder(hidden, raw));
    }
  });

  it('passes an ordinary Ed25519 public key imported non-extractable', async () => {
    for (let i = 0; i < 32; i++) {
      const { publicKey } = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
      const raw = await crypto.subtle.exportKey('raw', publicKey);
      const hidden = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
      expect(await isSmallOrderEd25519CryptoKey(hidden)).toBe(false);
    }
  });

  it('passes a non-extractable key that may not verify, which no verifier can use', async () => {
    const raw = hex(SMALL_ORDER[1]!);
    const unusable = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, []);
    expect(await isSmallOrderEd25519CryptoKey(unusable)).toBe(false);
  });

  it('asks WebCrypto once per key', async () => {
    const hidden = await crypto.subtle.importKey('raw', hex(SMALL_ORDER[2]!), { name: 'Ed25519' }, false, ['verify']);
    const verify = vi.spyOn(crypto.subtle, 'verify');
    try {
      const first = await isSmallOrderEd25519CryptoKey(hidden);
      expect(await isSmallOrderEd25519CryptoKey(hidden)).toBe(first);
      expect(verify).toHaveBeenCalledTimes(1);
    } finally {
      verify.mockRestore();
    }
  });
});

describe('the small-order probe', () => {
  const ORDER = [4, 1, 8, 8, 2, 4, 1];

  it('is a message whose challenge is a multiple of the order of every small-order encoding, under either sign bit', async () => {
    const message = new TextEncoder().encode(SMALL_ORDER_PROBE_MESSAGE);
    const identity = SMALL_ORDER_PROBE_SIGNATURE.slice(0, 32);
    expect(SMALL_ORDER_PROBE_SIGNATURE.slice(32).every((byte) => byte === 0)).toBe(true);
    for (const [index, encoding] of SMALL_ORDER.entries()) {
      for (const flip of [0, 0x80]) {
        const key = Uint8Array.from(hex(encoding), (byte, i) => (i === 31 ? byte | flip : byte));
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', new Uint8Array([...identity, ...key, ...message])));
        expect((littleEndian(digest) % L) % BigInt(ORDER[index]!)).toBe(0n);
      }
    }
  });
});
