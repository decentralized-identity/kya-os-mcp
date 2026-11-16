/**
 * What makes a string unfit to be recorded as it stands. Identifiers a caller
 * presents end up in audit events, proofs and log lines; these are the tests
 * every such record applies, kept here so they apply one rule.
 */

import { hasUnseenCodePoint } from './unseen-code-points.js';

/**
 * Whether a string is well-formed Unicode: it holds no surrogate without its
 * pair, a high surrogate without the low one after it or a low surrogate
 * without the high one before it.
 */
export function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * Whether a string holds a character that does not print as itself: a
 * control character, a format character (a bidirectional override, a
 * zero-width space, a byte order mark), a line or paragraph separator, a
 * code point that renders as nothing by default (a variation selector, a
 * Hangul filler), or a surrogate without its pair. The code points are those
 * of the frozen table (SPEC.md §7.8), so every runtime and the Python
 * reference give one verdict. A string that holds none shows a reader what
 * it holds, in a log line or anywhere else it is printed.
 */
export function hasUnprintableCharacter(value: string): boolean {
  return !isWellFormedUnicode(value) || hasUnseenCodePoint(value);
}
