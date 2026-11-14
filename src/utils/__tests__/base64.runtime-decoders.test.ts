/**
 * What the decoders of `../base64.ts` accept and return, input by input.
 *
 * They decode through the runtime (`Buffer`, `atob`), so what they read is
 * the runtime's reading and not one of the protocol's (`../base64-reading.ts`).
 * The first table is the reading where `Buffer` and `atob` both exist, which
 * is Node.js. The second is what the same calls give where one of the two is
 * missing, and the third sets both beside the protocol's readings.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { base64ToBytes, base64urlDecodeToBytes, base64urlDecodeToString } from '../base64.js';
import { base64EitherBytes, jwsSegmentBytes, strictBase64urlBytes } from '../base64-reading.js';

/** A call's outcome: what it returned, or that it threw. */
const REFUSED = Symbol('refused');
type Outcome<T> = T | typeof REFUSED;

function outcome<T>(call: () => T): Outcome<T> {
  try {
    return call();
  } catch {
    return REFUSED;
  }
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const textOf = (encoded: string): Outcome<string> => outcome(() => base64urlDecodeToString(encoded));
const bytesOf = (encoded: string): Outcome<string> => outcome(() => hex(base64urlDecodeToBytes(encoded)));
const standardBytesOf = (encoded: string): Outcome<string> => outcome(() => hex(base64ToBytes(encoded)));

/** `input`, the text `base64urlDecodeToString` gives, and the bytes both byte decoders give, in hex. */
type Row = readonly [input: string, text: Outcome<string>, bytes: Outcome<string>];

const REPLACED = '\ufffd';

const WITH_BUFFER_AND_ATOB: readonly Row[] = [
  // Empty input is no bytes.
  ['', '', ''],

  // Whole groups, and a last group of two or three characters without padding.
  ['SGkh', 'Hi!', '486921'],
  ['SGkhSGkh', 'Hi!Hi!', '486921486921'],
  ['SGk', 'Hi', '4869'],
  ['SA', 'H', '48'],
  ['SGkhSA', 'Hi!H', '48692148'],

  // Bits short of a byte are dropped, whatever they are.
  ['SR', 'I', '49'],
  ['SH', 'H', '48'],

  // Padding that completes the last group, or falls one short of completing it.
  ['SGk=', 'Hi', '4869'],
  ['SA==', 'H', '48'],
  ['SA=', 'H', '48'],
  ['SGkhSA=', 'Hi!H', '48692148'],
  ['SGkhSGk=', 'Hi!Hi', '4869214869'],

  // Padding past the end of the last group, after a whole group, or alone.
  ['SGk==', REFUSED, REFUSED],
  ['SGk===', REFUSED, REFUSED],
  ['SA===', REFUSED, REFUSED],
  ['SGkh=', REFUSED, REFUSED],
  ['SGkh==', REFUSED, REFUSED],
  ['SGkh====', REFUSED, REFUSED],
  ['=', REFUSED, REFUSED],
  ['====', REFUSED, REFUSED],

  // Padding ahead of a character.
  ['SG=k', REFUSED, REFUSED],
  ['S=Gk', REFUSED, REFUSED],

  // A last group of one character, padded or not.
  ['S', REFUSED, REFUSED],
  ['S=', REFUSED, REFUSED],
  ['S===', REFUSED, REFUSED],
  ['SGkhS', REFUSED, REFUSED],

  // Either alphabet, and the two in one string.
  ['-_-_', REPLACED.repeat(3), 'fbffbf'],
  ['+/+/', REPLACED.repeat(3), 'fbffbf'],
  ['-/+_', REPLACED.repeat(3), 'fbffbf'],

  // White space: the text decoder refuses all of it. The byte decoders pass
  // over it, but count it when they pad, so a string is read only when its
  // length with the white space is the length its characters alone would
  // need.
  [' SGk', REFUSED, '4869'],
  ['SGk ', REFUSED, '4869'],
  ['SG\tk', REFUSED, '4869'],
  ['SGk\f', REFUSED, '4869'],
  ['SG kh', REFUSED, REFUSED],
  ['SG\nkh', REFUSED, REFUSED],
  ['SGkh\n', REFUSED, REFUSED],
  ['S G k', REFUSED, REFUSED],
  ['SGk= ', REFUSED, REFUSED],
  ['SA==\n', REFUSED, REFUSED],
  ['SA= =', REFUSED, REFUSED],
  ['SGk\n=', REFUSED, REFUSED],

  // Characters outside both alphabets, a vertical tab and a no-break space included.
  ['SGk*', REFUSED, REFUSED],
  ['SG.k', REFUSED, REFUSED],
  ['SGk\u00e9', REFUSED, REFUSED],
  ['SG\u{1f600}', REFUSED, REFUSED],
  ['SG\u000bkh', REFUSED, REFUSED],
  ['SG\u00a0kh', REFUSED, REFUSED],

  // Bytes that are not UTF-8 are read as U+FFFD, and a byte order mark stays in the text.
  ['_w', REPLACED, 'ff'],
  ['wyg', `${REPLACED}(`, 'c328'],
  ['7aCA', REPLACED.repeat(3), 'eda080'],
  ['77u_eA', '\ufeffx', 'efbbbf78'],
];

describe('the runtime decoders of base64.ts, where Buffer and atob both exist', () => {
  it.each(WITH_BUFFER_AND_ATOB)('%j', (input, text, bytes) => {
    expect(textOf(input)).toBe(text);
    expect(bytesOf(input)).toBe(bytes);
    expect(standardBytesOf(input)).toBe(bytes);
  });

  it('refuse with an error of their own for text, and with the runtime decoder error for bytes', () => {
    expect(() => base64urlDecodeToString('SGk*')).toThrow(
      new Error('Invalid base64url string: contains invalid characters'),
    );
    for (const decode of [base64urlDecodeToBytes, base64ToBytes]) {
      expect(outcome(() => decode('SGk*'))).toBe(REFUSED);
      expect(() => decode('SGk*')).toThrow(expect.objectContaining({ name: 'InvalidCharacterError' }));
    }
  });
});

/** The outcome of `call` on a runtime that has no global `name`. */
function without<T>(name: 'Buffer' | 'atob', call: () => T): T {
  vi.stubGlobal(name, undefined);
  try {
    return call();
  } finally {
    vi.unstubAllGlobals();
  }
}

describe('the runtime decoders of base64.ts, where Buffer or atob is missing', () => {
  afterEach(() => vi.unstubAllGlobals());

  // Without Buffer the text is read through atob and TextDecoder: white space
  // is passed over as the byte decoders pass over it, and a byte order mark
  // is dropped.
  it.each<readonly [string, Outcome<string>, Outcome<string>]>([
    ['SGk', 'Hi', 'Hi'],
    ['SA=', 'H', 'H'],
    ['SGk==', REFUSED, REFUSED],
    ['S', REFUSED, REFUSED],
    ['_w', REPLACED, REPLACED],
    [' SGk', REFUSED, 'Hi'],
    ['SG\tk', REFUSED, 'Hi'],
    ['SGk\f', REFUSED, 'Hi'],
    ['77u_eA', '\ufeffx', 'x'],
  ])('text of %j without Buffer', (input, withBuffer, withoutBuffer) => {
    expect(textOf(input)).toBe(withBuffer);
    expect(without('Buffer', () => textOf(input))).toBe(withoutBuffer);
  });

  // Without atob the bytes are read through Buffer, which refuses nothing: it
  // passes over what is outside the alphabets and stops at the first `=`.
  it.each<readonly [string, Outcome<string>, Outcome<string>]>([
    ['SGk', '4869', '4869'],
    ['SA==', '48', '48'],
    ['SGk==', REFUSED, '4869'],
    ['SGkh====', REFUSED, '486921'],
    ['S', REFUSED, ''],
    ['====', REFUSED, ''],
    ['SG=k', REFUSED, '48'],
    ['SG kh', REFUSED, '486921'],
    ['SGk*', REFUSED, '4869'],
    ['SG\u000bkh', REFUSED, '486921'],
  ])('bytes of %j without atob', (input, withAtob, withoutAtob) => {
    expect(bytesOf(input)).toBe(withAtob);
    expect(without('atob', () => bytesOf(input))).toBe(withoutAtob);
    expect(without('atob', () => standardBytesOf(input))).toBe(withoutAtob);
  });
});

describe('the runtime decoders of base64.ts beside the protocol readings', () => {
  const reading = (bytes: Uint8Array | undefined): Outcome<string> => (bytes === undefined ? REFUSED : hex(bytes));

  // Where each reading parts from the runtime's bytes: [input, runtime,
  // base64EitherBytes, jwsSegmentBytes, strictBase64urlBytes].
  it.each<readonly [string, Outcome<string>, Outcome<string>, Outcome<string>, Outcome<string>]>([
    ['SGk', '4869', '4869', '4869', '4869'],
    ['SGk=', '4869', '4869', '4869', REFUSED],
    ['SA=', '48', '48', REFUSED, REFUSED],
    ['SGkhSA=', '48692148', '48692148', REFUSED, REFUSED],
    ['+/+/', 'fbffbf', 'fbffbf', REFUSED, REFUSED],
    ['SGk==', REFUSED, '4869', REFUSED, REFUSED],
    ['SGkh=', REFUSED, '486921', REFUSED, REFUSED],
    ['====', REFUSED, '', REFUSED, REFUSED],
    ['S', REFUSED, '', REFUSED, REFUSED],
    [' SGk', '4869', '4869', '4869', REFUSED],
    ['SG kh', REFUSED, '486921', '486921', REFUSED],
    ['SGkh\n', REFUSED, '486921', '486921', REFUSED],
    ['SA==\n', REFUSED, '48', '48', REFUSED],
    ['SGk*', REFUSED, REFUSED, REFUSED, REFUSED],
  ])('%j', (input, runtime, either, jwsSegment, strict) => {
    expect(bytesOf(input)).toBe(runtime);
    expect(reading(base64EitherBytes(input))).toBe(either);
    expect(reading(jwsSegmentBytes(input))).toBe(jwsSegment);
    expect(reading(strictBase64urlBytes(input))).toBe(strict);
  });
});
