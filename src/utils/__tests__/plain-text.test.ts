import { describe, expect, it } from 'vitest';
import { unit } from '../../__tests__/utils/encodings.js';
import { hasUnprintableCharacter, isWellFormedUnicode } from '../plain-text.js';
import { UNSEEN_CODE_POINTS } from '../unseen-code-points.js';

describe('hasUnprintableCharacter', () => {
  it.each([
    ['NUL, the first of C0', 0x00],
    ['LF', 0x0a],
    ['VT', 0x0b],
    ['ESC', 0x1b],
    ['US, the last of C0', 0x1f],
    ['DEL', 0x7f],
    ['the first of C1', 0x80],
    ['NEL', 0x85],
    ['the last of C1', 0x9f],
    ['a soft hyphen', 0xad],
    ['a zero-width space', 0x200b],
    ['a right-to-left mark', 0x200f],
    ['a line separator', 0x2028],
    ['a paragraph separator', 0x2029],
    ['a right-to-left override', 0x202e],
    ['a word joiner', 0x2060],
    ['a first strong isolate', 0x2068],
    ['a byte order mark', 0xfeff],
    ['an interlinear annotation anchor', 0xfff9],
    ['a format character outside the basic plane', 0x1d173],
    ['a tag character', 0xe0041],
    ['a combining grapheme joiner, which renders as nothing', 0x34f],
    ['a Hangul filler', 0x3164],
    ['a variation selector', 0xfe0f],
    ['a code point reserved as ignorable', 0x2065],
    ['a variation selector outside the basic plane', 0xe0100],
  ])('finds %s', (_name, code) => {
    const character = String.fromCodePoint(code);
    expect(hasUnprintableCharacter(`del${character}1`)).toBe(true);
    expect(hasUnprintableCharacter(character)).toBe(true);
    expect(hasUnprintableCharacter(`del-1${character}`)).toBe(true);
  });

  it.each([
    ['a space, the first past C0', 0x20],
    ['a tilde, the last before DEL', 0x7e],
    ['a no-break space, the first past C1', 0xa0],
    ['the character before the zero-width space', 0x200a],
    ['the character before the line separator', 0x2027],
    ['a narrow no-break space, the first past the overrides', 0x202f],
    ['the character before the variation selectors', 0xfdff],
    ['a replacement character', 0xfffd],
    ['a character outside the basic plane', 0x1f600],
  ])('does not take %s for one', (_name, code) => {
    expect(hasUnprintableCharacter(`del${String.fromCodePoint(code)}1`)).toBe(false);
  });

  it('finds a surrogate without its pair, and not a pair', () => {
    expect(hasUnprintableCharacter(`del${unit(0xd800)}1`)).toBe(true);
    expect(hasUnprintableCharacter(`del${unit(0xdfff)}`)).toBe(true);
    expect(hasUnprintableCharacter(`del${unit(0xd83d)}${unit(0xde00)}1`)).toBe(false);
  });

  it('finds none in an empty string or plain text', () => {
    expect(hasUnprintableCharacter('')).toBe(false);
    expect(hasUnprintableCharacter('urn:uuid:8f14e45f-ceea-4e7a-9c1b-2f6d1b7a3c55')).toBe(false);
  });

  // One table says which code points a reader does not see, and the issuer
  // rule of SPEC.md section 6.2 reads the same one.
  it('finds exactly the code points of the frozen table, and the surrogates', () => {
    const listed = (code: number): boolean => UNSEEN_CODE_POINTS.some(([first, last]) => code >= first && code <= last);
    const differ: string[] = [];
    for (let code = 0; code <= 0x10ffff; code += 1) {
      const surrogate = code >= 0xd800 && code <= 0xdfff;
      const character = surrogate ? unit(code) : String.fromCodePoint(code);
      if (hasUnprintableCharacter(character) !== (surrogate || listed(code))) differ.push(code.toString(16));
    }
    expect(differ).toEqual([]);
  });
});

describe('isWellFormedUnicode', () => {
  const high = unit(0xd83d);
  const low = unit(0xde00);

  it.each([
    ['an empty string', ''],
    ['plain text', 'del-1'],
    ['a surrogate pair', `a${high}${low}b`],
    ['two pairs in a row', `${high}${low}${high}${low}`],
    ['the code units either side of the surrogates', `${unit(0xd7ff)}${unit(0xe000)}`],
  ])('holds for %s', (_name, value) => {
    expect(isWellFormedUnicode(value)).toBe(true);
  });

  it.each([
    ['a high surrogate alone', high],
    ['a low surrogate alone', low],
    ['a high surrogate at the end', `a${high}`],
    ['a high surrogate before another character', `${high}b`],
    ['a low surrogate at the start', `${low}b`],
    ['a low surrogate after another character', `a${low}b`],
    ['a pair the wrong way round', `${low}${high}`],
    ['two high surrogates before one low', `${high}${high}${low}`],
    ['one high surrogate before two low', `${high}${low}${low}`],
    ['the first and last high surrogates alone', `${unit(0xd800)}a${unit(0xdbff)}`],
    ['the first and last low surrogates alone', `${unit(0xdc00)}a${unit(0xdfff)}`],
  ])('does not hold for %s', (_name, value) => {
    expect(isWellFormedUnicode(value)).toBe(false);
  });
});
