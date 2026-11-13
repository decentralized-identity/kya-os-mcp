/**
 * What makes a string unfit to be recorded as it stands. Identifiers a caller
 * presents end up in audit events, proofs and log lines; these are the tests
 * every such record applies, kept here so they apply one rule.
 */

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
 * The code points that do not print as themselves (SPEC.md §7.8), first and
 * last of each run: Unicode's control characters (Cc), its format characters
 * (Cf) and its line and paragraph separators (Zl, Zp), as Unicode 16.0 and
 * 17.0 assign them. They are written out rather than read from the runtime's
 * tables, which follow its own Unicode version, so that every runtime and
 * the Python reference record the same ids as they stand.
 */
const DO_NOT_PRINT: readonly (readonly [number, number])[] = [
  [0x0000, 0x001f], // C0 controls
  [0x007f, 0x009f], // DEL and the C1 controls
  [0x00ad, 0x00ad], // soft hyphen
  [0x0600, 0x0605], // Arabic number signs
  [0x061c, 0x061c], // Arabic letter mark
  [0x06dd, 0x06dd], // Arabic end of ayah
  [0x070f, 0x070f], // Syriac abbreviation mark
  [0x0890, 0x0891], // Arabic pound and piastre marks above
  [0x08e2, 0x08e2], // Arabic disputed end of ayah
  [0x180e, 0x180e], // Mongolian vowel separator
  [0x200b, 0x200f], // zero-width space and joiners, left-to-right and right-to-left marks
  [0x2028, 0x202e], // line and paragraph separators, bidirectional embeddings and overrides
  [0x2060, 0x2064], // word joiner, invisible operators
  [0x2066, 0x206f], // bidirectional isolates, deprecated format characters
  [0xfeff, 0xfeff], // zero-width no-break space, the byte order mark
  [0xfff9, 0xfffb], // interlinear annotation
  [0x110bd, 0x110bd], // Kaithi number sign
  [0x110cd, 0x110cd], // Kaithi number sign above
  [0x13430, 0x1343f], // Egyptian hieroglyph format controls
  [0x1bca0, 0x1bca3], // shorthand format controls
  [0x1d173, 0x1d17a], // musical symbol format controls
  [0xe0001, 0xe0001], // language tag
  [0xe0020, 0xe007f], // tag characters
];

const codePoint = (code: number): string => `\\u{${code.toString(16)}}`;
const DOES_NOT_PRINT = new RegExp(
  `[${DO_NOT_PRINT.map(([first, last]) => `${codePoint(first)}-${codePoint(last)}`).join('')}]`,
  'u',
);

/**
 * Whether a string holds a character that does not print as itself: a
 * control character, a format character (a bidirectional override, a
 * zero-width space, a byte order mark), a line or paragraph separator, or a
 * surrogate without its pair. A string that holds none shows a reader what
 * it holds, in a log line or anywhere else it is printed.
 */
export function hasUnprintableCharacter(value: string): boolean {
  return !isWellFormedUnicode(value) || DOES_NOT_PRINT.test(value);
}
