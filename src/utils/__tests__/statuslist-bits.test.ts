import { describe, it, expect } from 'vitest';
import {
  MAX_STATUS_LIST_BYTES,
  MULTIBASE_BASE64URL,
  parseStatusListIndex,
  decodeStatusListPayload,
  readStatusBit,
} from '../statuslist-bits.js';
import { base64urlEncodeFromBytes } from '../base64.js';

/** Identity "decompressor" — the payload IS the bitstring (mechanics tests need no gzip). */
const identity = (bytes: Uint8Array): Uint8Array => bytes;

describe('parseStatusListIndex', () => {
  it('parses a canonical non-negative decimal', () => {
    expect(parseStatusListIndex('0')).toBe(0);
    expect(parseStatusListIndex('94')).toBe(94);
    expect(parseStatusListIndex('131071')).toBe(131071);
  });

  it.each(['0x2A', ' 42', '42 ', '+42', '-1', '1e1', '4.2', '', 'abc'])(
    'rejects non-canonical input %j (fail-closed)',
    (raw) => {
      expect(() => parseStatusListIndex(raw)).toThrow(
        /canonical non-negative decimal/,
      );
    },
  );

  it('rejects values beyond the safe integer range', () => {
    expect(() => parseStatusListIndex('9007199254740992')).toThrow(
      /safe integer range/,
    );
  });
});

describe('decodeStatusListPayload', () => {
  const raw = new Uint8Array([0b10100000, 0b00000001]);

  it('decodes with the multibase u prefix', async () => {
    const encoded = MULTIBASE_BASE64URL + base64urlEncodeFromBytes(raw);
    expect(await decodeStatusListPayload(encoded, identity)).toEqual(raw);
  });

  it('decodes without the prefix (issuer interop)', async () => {
    const encoded = base64urlEncodeFromBytes(raw);
    expect(await decodeStatusListPayload(encoded, identity)).toEqual(raw);
  });

  it('supports an async decompressor', async () => {
    const encoded = base64urlEncodeFromBytes(raw);
    const asyncIdentity = async (bytes: Uint8Array) => bytes;
    expect(await decodeStatusListPayload(encoded, asyncIdentity)).toEqual(raw);
  });

  it('fail-closes on an inflated payload above the cap', async () => {
    const bomb = () => new Uint8Array(MAX_STATUS_LIST_BYTES + 1);
    const encoded = base64urlEncodeFromBytes(new Uint8Array([1]));
    await expect(decodeStatusListPayload(encoded, bomb)).rejects.toThrow(
      /too large/,
    );
  });
});

describe('readStatusBit', () => {
  const bits = new Uint8Array([0b10100000, 0b00000001]);

  it('reads MSB-first within each byte (W3C order)', () => {
    expect(readStatusBit(bits, 0)).toBe(true);
    expect(readStatusBit(bits, 1)).toBe(false);
    expect(readStatusBit(bits, 2)).toBe(true);
    expect(readStatusBit(bits, 15)).toBe(true);
    expect(readStatusBit(bits, 14)).toBe(false);
  });

  it.each([NaN, -1, 16, 2 ** 32 + 5, 0.5])(
    'fail-closes (throws "out of range") on unreadable index %p',
    (index) => {
      expect(() => readStatusBit(bits, index)).toThrow(/out of range/);
    },
  );
});
