/**
 * `describeValue`, the form in which a refusal reason names a value the other party chose. The
 * verifiers that quote one are tested beside them; these are the values it is given.
 */

import { describe, it, expect } from 'vitest';
import { describeValue } from '../describe-value.js';

const EMOJI = '\u{1F600}';
const LONE_HIGH = '\uD83D';
const LONE_LOW = '\uDE00';

/** No control character, C0, DEL or C1, survives into a quote. */
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;
/** A lone surrogate: in a regular expression with the `u` flag, a surrogate pair reads as one character. */
const LONE_SURROGATE = /\p{Cs}/u;

describe('describeValue', () => {
  it('quotes a string of at most 64 characters as a JSON string', () => {
    for (const value of ['a', ' ', 'assertionMethod', 'did:web:acme.example#key-1', 'x'.repeat(64)]) {
      expect(describeValue(value)).toBe(`"${value}"`);
    }
  });

  it('quotes the empty string as "", so a reason shows that the value was empty', () => {
    expect(describeValue('')).toBe('""');
  });

  it('cuts a longer string after its first 64 characters, and marks the cut after the closing quote', () => {
    expect(describeValue('y'.repeat(65))).toBe(`"${'y'.repeat(64)}"...`);
    expect(describeValue('z'.repeat(100_000))).toBe(`"${'z'.repeat(64)}"...`);
  });

  it('counts a character outside the Basic Multilingual Plane as one, so the cut never splits it', () => {
    expect(describeValue(EMOJI.repeat(64))).toBe(`"${EMOJI.repeat(64)}"`);
    expect(describeValue(EMOJI.repeat(65))).toBe(`"${EMOJI.repeat(64)}"...`);
    expect(describeValue(`${'p'.repeat(63)}${EMOJI}q`)).toBe(`"${'p'.repeat(63)}${EMOJI}"...`);
  });

  it('escapes a lone surrogate, so the quote is well-formed text', () => {
    expect(describeValue(`a${LONE_HIGH}b`)).toBe('"a\\ud83db"');
    expect(describeValue(`a${LONE_LOW}b`)).toBe('"a\\ude00b"');
    expect(describeValue(`${LONE_LOW}${LONE_HIGH}`)).toBe('"\\ude00\\ud83d"');
    expect(describeValue(`${LONE_HIGH}${EMOJI}${LONE_LOW}`)).toBe(`"\\ud83d${EMOJI}\\ude00"`);
    for (const code of [0xd800, 0xdbff, 0xdc00, 0xdfff]) {
      expect(describeValue(`a${String.fromCharCode(code)}b`)).toBe(`"a\\u${code.toString(16)}b"`);
    }
    const besideTheSurrogates = String.fromCharCode(0xd7ff, 0xe000);
    expect(describeValue(besideTheSurrogates)).toBe(`"${besideTheSurrogates}"`);
  });

  it('counts a lone surrogate as one character, on either side of the cut', () => {
    expect(describeValue(`${'p'.repeat(63)}${LONE_HIGH}`)).toBe(`"${'p'.repeat(63)}\\ud83d"`);
    expect(describeValue(`${'p'.repeat(63)}${LONE_LOW}q`)).toBe(`"${'p'.repeat(63)}\\ude00"...`);
    expect(describeValue(`${'p'.repeat(64)}${LONE_HIGH}`)).toBe(`"${'p'.repeat(64)}"...`);
    expect(describeValue(LONE_LOW.repeat(64))).toBe(`"${'\\ude00'.repeat(64)}"`);
    expect(describeValue(LONE_LOW.repeat(65))).toBe(`"${'\\ude00'.repeat(64)}"...`);
  });

  it('escapes every control character, and a quote mark or backslash, so the value cannot end its quote', () => {
    expect(describeValue('a\nb\u001b[31m')).toBe('"a\\nb\\u001b[31m"');
    expect(describeValue('\t\r\u0000')).toBe('"\\t\\r\\u0000"');
    expect(describeValue('a\u007fb\u0080c\u009b')).toBe('"a\\u007fb\\u0080c\\u009b"');
    expect(describeValue('x" is not "y')).toBe('"x\\" is not \\"y"');
    expect(describeValue('a\\b')).toBe('"a\\\\b"');
    const besideTheControls = '\u001f ~\u007f\u009f\u00a0';
    expect(describeValue(besideTheControls)).toBe('"\\u001f ~\\u007f\\u009f\u00a0"');
  });

  it('escapes the line and paragraph separators and the bidirectional controls, so the value can neither break the line nor reorder it', () => {
    const escaped = [0x061c, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069];
    for (const code of escaped) {
      expect(describeValue(`a${String.fromCharCode(code)}b`)).toBe(`"a\\u${code.toString(16).padStart(4, '0')}b"`);
    }
    const besideThem = String.fromCharCode(0x061b, 0x061d, 0x2010, 0x2027, 0x2030);
    expect(describeValue(besideThem)).toBe(`"${besideThem}"`);
    expect(JSON.parse(describeValue('x\u2028\u202ey'))).toBe('x\u2028\u202ey');
  });

  it('escapes every format character and every character that renders as nothing by default, so no value reads as another', () => {
    // Zero width space, zero width joiner, word joiner, zero width no-break space, soft hyphen, Mongolian
    // vowel separator, combining grapheme joiner, variation selector 16, Hangul filler, and U+2065, which
    // Unicode reserves as default ignorable, and U+206A, a deprecated format character; then the Arabic
    // number sign and the interlinear annotation anchor, format characters that are not default ignorable.
    const escaped = [0x200b, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x180e, 0x034f, 0xfe0f, 0x3164, 0x2065, 0x206a, 0x0600, 0xfff9];
    for (const code of escaped) {
      expect(describeValue(`a${String.fromCharCode(code)}b`)).toBe(`"a\\u${code.toString(16).padStart(4, '0')}b"`);
    }
    // A tag character, outside the Basic Multilingual Plane, is escaped as its surrogate pair and counts as one character.
    expect(describeValue('a\u{E0041}b')).toBe('"a\\udb40\\udc41b"');
    expect(describeValue('\u{E0041}'.repeat(65))).toBe(`"${'\\udb40\\udc41'.repeat(64)}"...`);
    expect(JSON.parse(describeValue('a\u{E0041}\u200bb'))).toBe('a\u{E0041}\u200bb');
    const besideThem = `${String.fromCharCode(0x00ac, 0x00ae, 0x200a, 0x2010, 0x3163, 0x3165, 0xfefc)}${EMOJI}`;
    expect(describeValue(besideThem)).toBe(`"${besideThem}"`);
  });

  it('quotes a string so that it reads apart from a type it is named by, and parses back to the value', () => {
    expect(describeValue('of type object')).toBe('"of type object"');
    expect(describeValue({})).toBe('of type object');
    for (const value of ['', 'a\nb', `${LONE_HIGH}x`, 'x" is "y', '\u009b', EMOJI.repeat(64)]) {
      expect(JSON.parse(describeValue(value))).toBe(value);
    }
  });

  it('writes bounded, well-formed text with no control character, whatever the string', () => {
    const strings = ['\u0000'.repeat(1000), LONE_HIGH.repeat(1000), `${EMOJI}${LONE_LOW}`.repeat(1000), '\u009b'.repeat(1000), '\u{E0041}'.repeat(1000)];
    for (const value of strings) {
      const quoted = describeValue(value);
      expect(quoted).not.toMatch(LONE_SURROGATE);
      expect(quoted).not.toMatch(CONTROL);
      expect(quoted.length).toBeLessThanOrEqual(2 + 64 * 12 + 3);
    }
  });

  it('names anything else by its type alone, never converting it', () => {
    const throwing = {
      toString(): string {
        throw new Error('converted');
      },
    };
    const named: [unknown, string][] = [
      [['assertionMethod'], 'array'],
      [[], 'array'],
      [{ id: 'did:web:acme.example#key-1' }, 'object'],
      [JSON.parse('{"toString":"assertionMethod"}'), 'object'],
      [throwing, 'object'],
      [null, 'null'],
      [7, 'number'],
      [true, 'boolean'],
      [undefined, 'undefined'],
      [Symbol('key-1'), 'symbol'],
      [10n, 'bigint'],
    ];
    for (const [value, type] of named) {
      expect(describeValue(value)).toBe(`of type ${type}`);
    }
  });
});
