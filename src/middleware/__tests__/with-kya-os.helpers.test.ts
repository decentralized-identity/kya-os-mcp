/**
 * `sanitizeForMessage`, which bounds and cleans every refusal reason and log line the middleware
 * builds from values a caller chose. A response proof signs the reason in RFC 8785 form, which
 * refuses a lone surrogate, so the result must be well-formed text wherever its bound falls. The
 * gates that use it are tested end to end beside them; these are the strings it is given.
 */

import { describe, it, expect } from 'vitest';
import { sanitizeForMessage } from '../with-kya-os.helpers.js';

const EMOJI = '\u{1F600}';
const LONE_HIGH = '\uD83D';
const LONE_LOW = '\uDE00';
const REPLACEMENT = '\uFFFD';
const ELLIPSIS = '\u2026';

describe('sanitizeForMessage', () => {
  it('keeps a string of at most 256 UTF-16 code units as it is', () => {
    for (const value of ['', 'Proof purpose authentication is not assertionMethod', 'x'.repeat(256), EMOJI.repeat(128)]) {
      expect(sanitizeForMessage(value)).toBe(value);
    }
  });

  it('cuts a longer string after its first 256 code units, and marks the cut', () => {
    expect(sanitizeForMessage('y'.repeat(257))).toBe(`${'y'.repeat(256)}${ELLIPSIS}`);
    expect(sanitizeForMessage('z'.repeat(400_000))).toBe(`${'z'.repeat(256)}${ELLIPSIS}`);
  });

  it('cuts before a surrogate pair the bound would split, and keeps one that ends at the bound', () => {
    expect(sanitizeForMessage(`${'a'.repeat(254)}${EMOJI}`)).toBe(`${'a'.repeat(254)}${EMOJI}`);
    expect(sanitizeForMessage(`${'a'.repeat(254)}${EMOJI}b`)).toBe(`${'a'.repeat(254)}${EMOJI}${ELLIPSIS}`);
    expect(sanitizeForMessage(`${'a'.repeat(255)}${EMOJI}`)).toBe(`${'a'.repeat(255)}${ELLIPSIS}`);
    expect(sanitizeForMessage(`${'a'.repeat(256)}${EMOJI}`)).toBe(`${'a'.repeat(256)}${ELLIPSIS}`);
    expect(sanitizeForMessage(`a${EMOJI.repeat(200)}`)).toBe(`a${EMOJI.repeat(127)}${ELLIPSIS}`);
    expect(sanitizeForMessage(EMOJI.repeat(200))).toBe(`${EMOJI.repeat(128)}${ELLIPSIS}`);
  });

  it('replaces a lone surrogate with U+FFFD, on either side of the bound', () => {
    expect(sanitizeForMessage(`a${LONE_HIGH}b${LONE_LOW}c`)).toBe(`a${REPLACEMENT}b${REPLACEMENT}c`);
    expect(sanitizeForMessage(`${LONE_LOW}${LONE_HIGH}`)).toBe(REPLACEMENT.repeat(2));
    expect(sanitizeForMessage(`${LONE_HIGH}${EMOJI}${LONE_HIGH}`)).toBe(`${REPLACEMENT}${EMOJI}${REPLACEMENT}`);
    expect(sanitizeForMessage(`${'a'.repeat(255)}${LONE_HIGH}`)).toBe(`${'a'.repeat(255)}${REPLACEMENT}`);
    expect(sanitizeForMessage(`${'a'.repeat(255)}${LONE_HIGH}b`)).toBe(`${'a'.repeat(255)}${REPLACEMENT}${ELLIPSIS}`);
    expect(sanitizeForMessage(`${'a'.repeat(256)}${LONE_LOW}`)).toBe(`${'a'.repeat(256)}${ELLIPSIS}`);
    for (const code of [0xd800, 0xdbff, 0xdc00, 0xdfff]) {
      expect(sanitizeForMessage(`a${String.fromCharCode(code)}b`)).toBe(`a${REPLACEMENT}b`);
    }
  });

  it('reads U+FFFF as one code unit, so it never hides the character after it', () => {
    // U+FFFF is the last code point one code unit holds: read as a pair, it would carry the next unit.
    for (const next of ['\u0007', '\uD800', '\u009B']) {
      expect(sanitizeForMessage(`\uFFFF${next}`)).toBe(`\uFFFF${REPLACEMENT}`);
    }
  });

  it('replaces with U+FFFD the controls and every character describeValue escapes, and nothing else', () => {
    // The C0 and C1 controls, the line and paragraph separators, format characters such as the
    // bidirectional controls, and characters that render as nothing by default, in and out of the BMP.
    const control = [0x00, 0x09, 0x0a, 0x0d, 0x1b, 0x1f, 0x7f, 0x80, 0x9f, 0x2028, 0x2029, 0x202e, 0x2066, 0x200b, 0xad, 0x600, 0x3164, 0xfe0f, 0xe0041]
      .map((code) => String.fromCodePoint(code));
    expect(sanitizeForMessage(`a${control.join('')}b`)).toBe(`a${REPLACEMENT.repeat(control.length)}b`);
    const kept = [0x20, 0x7e, 0xa0, 0xe9, 0x2026, 0xfffd, 0xd7ff, 0xe000, 0x1f600].map((code) => String.fromCodePoint(code)).join('');
    expect(sanitizeForMessage(kept)).toBe(kept);
  });

  it('bounds the result at maxLen code units when given one', () => {
    expect(sanitizeForMessage(`ab${EMOJI}c`, 3)).toBe(`ab${ELLIPSIS}`);
    expect(sanitizeForMessage(`ab${EMOJI}c`, 4)).toBe(`ab${EMOJI}${ELLIPSIS}`);
    expect(sanitizeForMessage(`ab${EMOJI}`, 4)).toBe(`ab${EMOJI}`);
  });

  it('writes any other value as String does', () => {
    expect(sanitizeForMessage(7)).toBe('7');
    expect(sanitizeForMessage(undefined)).toBe('undefined');
    expect(sanitizeForMessage(new Error(`bad${String.fromCharCode(10)}line`))).toBe(`Error: bad${REPLACEMENT}line`);
  });

  it('is its own fixed point, so sanitizing a sanitized reason again changes nothing', () => {
    for (const value of [`${'a'.repeat(255)}${EMOJI}`, 'y'.repeat(300), `a${LONE_HIGH}`, `${'a'.repeat(254)}${EMOJI}b`]) {
      const once = sanitizeForMessage(value);
      expect(sanitizeForMessage(once)).toBe(once);
    }
  });
});
