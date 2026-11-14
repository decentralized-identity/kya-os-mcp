import { describe, it, expect } from 'vitest';
import {
  MAX_STATUS_LIST_BYTES,
  MULTIBASE_BASE64URL,
  parseStatusListIndex,
  encodeStatusListPayload,
  decodeStatusListPayload,
  readStatusBit,
  assertAnchorableStatusListCredential,
} from '../statuslist-bits.js';
import { base64urlEncodeFromBytes } from '../base64.js';
import { statusListGzipCodec } from '../statuslist-gzip.js';

const { compress: gzip, decompress: gunzip } = statusListGzipCodec;

/** A pass-through "decompressor": hands back the GZIP payload as if it were the bitstring. */
const passThrough = (bytes: Uint8Array): Uint8Array => bytes;

describe('parseStatusListIndex', () => {
  it('parses a canonical non-negative decimal', () => {
    expect(parseStatusListIndex('0')).toBe(0);
    expect(parseStatusListIndex('94')).toBe(94);
    expect(parseStatusListIndex('131071')).toBe(131071);
  });

  it('reads leading zeros, however many, as naming no other bit', () => {
    expect(parseStatusListIndex('0005')).toBe(5);
    expect(parseStatusListIndex(`${'0'.repeat(4300)}7`)).toBe(7);
    expect(() => parseStatusListIndex(`${'0'.repeat(4300)}9007199254740992`)).toThrow(/exceeds the safe integer range$/);
  });

  it.each(['0x2A', ' 42', '42 ', '+42', '-1', '1e1', '4.2', '', 'abc'])(
    'rejects non-canonical input %j (fail-closed)',
    (raw) => {
      expect(() => parseStatusListIndex(raw)).toThrow(
        /must be a non-negative decimal string/,
      );
    },
  );

  it.each([
    [7, 'number'],
    [0, 'number'],
    [['7'], 'array'],
    [null, 'null'],
    [undefined, 'undefined'],
    [true, 'boolean'],
    [{ toString: () => '7' }, 'object'],
    [{ toString: '7' }, 'object'],
  ])('refuses %j, which is not a string, without converting it', (raw, type) => {
    expect(() => parseStatusListIndex(raw)).toThrow(
      `Invalid statusListIndex of type ${type}: must be a non-negative decimal string`,
    );
  });

  it('rejects values beyond the safe integer range', () => {
    expect(() => parseStatusListIndex('9007199254740992')).toThrow(
      /safe integer range/,
    );
  });

  it('takes a non-negative safe integer number only when the caller accepts one, as a writer of its own records does', () => {
    const lenient = { acceptNumber: true };
    for (const index of [0, 7, Number.MAX_SAFE_INTEGER]) {
      expect(parseStatusListIndex(index, lenient)).toBe(index);
      expect(parseStatusListIndex(String(index), lenient)).toBe(index);
      expect(() => parseStatusListIndex(index)).toThrow(
        new Error('Invalid statusListIndex of type number: must be a non-negative decimal string'),
      );
    }
    const refused = [-1, 7.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, ['7'], '7x'];
    for (const index of refused) {
      expect(() => parseStatusListIndex(index, lenient)).toThrow(
        /^Invalid statusListIndex .*: must be a non-negative safe integer or a non-negative decimal string$/,
      );
    }
    expect(() => parseStatusListIndex('9007199254740992', lenient)).toThrow(/safe integer range/);
  });

  // Whoever signed the entry wrote its index, so a refusal quotes it as any value the other party chose.
  it('quotes a string index it refuses as a JSON string of at most 64 characters, so the reason is bounded and well-formed', () => {
    const refusals: [string, string][] = [
      [
        `${'7'.repeat(10)}x${'\u{1F600}'.repeat(5000)}\uD800`,
        `Invalid statusListIndex "${'7'.repeat(10)}x${'\u{1F600}'.repeat(53)}"...: must be a non-negative decimal string`,
      ],
      ['7\n\uDE00', 'Invalid statusListIndex "7\\n\\ude00": must be a non-negative decimal string'],
      ['9'.repeat(20_000), `statusListIndex "${'9'.repeat(64)}"... exceeds the safe integer range`],
    ];
    for (const [raw, refusal] of refusals) {
      expect(() => parseStatusListIndex(raw)).toThrow(new Error(refusal));
    }
  });
});

describe('encodeStatusListPayload', () => {
  const raw = new Uint8Array([0b10100000, 0b00000001]);

  it('GZIPs the bitstring under the multibase u prefix', async () => {
    const encoded = await encodeStatusListPayload(raw, gzip);
    expect(encoded.startsWith(MULTIBASE_BASE64URL)).toBe(true);
    expect(await decodeStatusListPayload(encoded, gunzip)).toEqual(raw);
  });

  it('refuses to publish when the compressor does not GZIP', async () => {
    await expect(encodeStatusListPayload(raw, passThrough)).rejects.toThrow(/not GZIP/);
  });
});

describe('decodeStatusListPayload', () => {
  const raw = new Uint8Array([0b10100000, 0b00000001]);

  it('decodes with the multibase u prefix', async () => {
    const encoded = MULTIBASE_BASE64URL + base64urlEncodeFromBytes(await gzip(raw));
    expect(await decodeStatusListPayload(encoded, gunzip)).toEqual(raw);
  });

  it('decodes without the prefix (issuer interop)', async () => {
    const encoded = base64urlEncodeFromBytes(await gzip(raw));
    expect(await decodeStatusListPayload(encoded, gunzip)).toEqual(raw);
  });

  it('supports a sync decompressor', async () => {
    const encoded = base64urlEncodeFromBytes(await gzip(raw));
    expect(await decodeStatusListPayload(encoded, () => raw)).toEqual(raw);
  });

  it('fail-closes on an inflated payload above the cap', async () => {
    const bomb = () => new Uint8Array(MAX_STATUS_LIST_BYTES + 1);
    const encoded = base64urlEncodeFromBytes(await gzip(new Uint8Array([1])));
    await expect(decodeStatusListPayload(encoded, bomb)).rejects.toThrow(
      /too large/,
    );
  });

  it('fail-closes on a payload that is not GZIP', async () => {
    const encoded = MULTIBASE_BASE64URL + base64urlEncodeFromBytes(raw);
    await expect(decodeStatusListPayload(encoded, () => raw)).rejects.toThrow(/not GZIP/);
  });

  it('fail-closes on a pass-through decompressor, which would read the GZIP header as bits', async () => {
    const encoded = base64urlEncodeFromBytes(await gzip(raw));
    await expect(decodeStatusListPayload(encoded, passThrough)).rejects.toThrow(
      /input unchanged/,
    );
    const copying = (bytes: Uint8Array): Uint8Array => bytes.slice();
    await expect(decodeStatusListPayload(encoded, copying)).rejects.toThrow(/input unchanged/);
  });

  it('reads a bitstring that itself begins with the GZIP magic', async () => {
    const magic = new Uint8Array([0x1f, 0x8b, 0x00]);
    const encoded = await encodeStatusListPayload(magic, gzip);
    expect(await decodeStatusListPayload(encoded, gunzip)).toEqual(magic);
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

describe('assertAnchorableStatusListCredential', () => {
  const anchorable = {
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    credentialSubject: { statusPurpose: 'revocation', encodedList: 'uH4sIAAAAAAAA' },
    proof: { type: 'Ed25519Signature2020', proofValue: 'zsig' },
  };

  it('accepts a signed credential with a bitstring', () => {
    expect(() => assertAnchorableStatusListCredential(anchorable)).not.toThrow();
  });

  it('refuses an unsigned credential (fail-closed for every future holder)', () => {
    const { proof: _proof, ...unsigned } = anchorable;
    expect(() => assertAnchorableStatusListCredential(unsigned)).toThrow(/UNSIGNED/);
  });

  it('refuses a missing or empty encodedList', () => {
    expect(() =>
      assertAnchorableStatusListCredential({ ...anchorable, credentialSubject: {} }),
    ).toThrow(/encodedList/);
    expect(() =>
      assertAnchorableStatusListCredential({
        ...anchorable,
        credentialSubject: { encodedList: '' },
      }),
    ).toThrow(/encodedList/);
  });

  it('refuses non-object content', () => {
    expect(() => assertAnchorableStatusListCredential(null)).toThrow(/must be an object/);
    expect(() => assertAnchorableStatusListCredential('vc')).toThrow(/must be an object/);
  });
});
