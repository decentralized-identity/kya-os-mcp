/**
 * The code points a reader does not see in a name: Unicode's control characters (Cc), its format
 * characters (Cf), its line and paragraph separators (Zl, Zp), and every code point that renders as
 * nothing by default (Default_Ignorable_Code_Point), such as a variation selector or a Hangul
 * filler. A name that holds one prints as another name does, so a rule that says a name is what it
 * shows refuses them all.
 *
 * The set is frozen in one table, `conformance/unseen-code-points.json`, as Unicode 16.0 and 17.0
 * both assign it. It is not read from the runtime, whose regular expressions follow the Unicode
 * version it was built with, so Node.js 20, Node.js 22 and the Python reference give one verdict
 * on one string. The Python reference reads the file. The package carries the same runs here, as
 * code: a build for a browser or a Worker has no file to read, and importing JSON needs an import
 * attribute that Node.js 18 cannot parse and Node.js 20.11 warns about on every start.
 * `./__tests__/unseen-code-points.test.ts` holds these runs to the file, number for number.
 */

/** First and last code point of each run, ascending; no two runs touch. */
export const UNSEEN_CODE_POINTS: readonly (readonly [number, number])[] = [
  [0x0000, 0x001f], // C0 controls
  [0x007f, 0x009f], // DEL and the C1 controls
  [0x00ad, 0x00ad], // soft hyphen
  [0x034f, 0x034f], // combining grapheme joiner
  [0x0600, 0x0605], // Arabic number signs
  [0x061c, 0x061c], // Arabic letter mark
  [0x06dd, 0x06dd], // Arabic end of ayah
  [0x070f, 0x070f], // Syriac abbreviation mark
  [0x0890, 0x0891], // Arabic pound and piastre marks above
  [0x08e2, 0x08e2], // Arabic disputed end of ayah
  [0x115f, 0x1160], // Hangul choseong and jungseong fillers
  [0x17b4, 0x17b5], // Khmer inherent vowels
  [0x180b, 0x180f], // Mongolian variation selectors and vowel separator
  [0x200b, 0x200f], // zero width space and joiners, direction marks
  [0x2028, 0x202e], // line and paragraph separators, bidirectional embeddings and overrides
  [0x2060, 0x206f], // word joiner, invisible operators, bidirectional isolates, deprecated format characters
  [0x3164, 0x3164], // Hangul filler
  [0xfe00, 0xfe0f], // variation selectors
  [0xfeff, 0xfeff], // zero width no-break space, the byte order mark
  [0xffa0, 0xffa0], // halfwidth Hangul filler
  [0xfff0, 0xfffb], // reserved as ignorable, and interlinear annotation
  [0x110bd, 0x110bd], // Kaithi number sign
  [0x110cd, 0x110cd], // Kaithi number sign above
  [0x13430, 0x1343f], // Egyptian hieroglyph format controls
  [0x1bca0, 0x1bca3], // shorthand format controls
  [0x1d173, 0x1d17a], // musical symbol format controls
  [0xe0000, 0xe0fff], // tags, variation selectors supplement, and the rest of the plane reserved as ignorable
];

const escaped = (code: number): string => `\\u{${code.toString(16)}}`;
const UNSEEN_SOURCE = `[${UNSEEN_CODE_POINTS.map(([first, last]) => `${escaped(first)}-${escaped(last)}`).join('')}]`;
const UNSEEN = new RegExp(UNSEEN_SOURCE, 'u');
const EVERY_UNSEEN = new RegExp(UNSEEN_SOURCE, 'gu');

/**
 * Whether `value` holds a code point of {@link UNSEEN_CODE_POINTS}. A surrogate without its pair
 * is no code point of the table: a caller that must refuse one tests for it as well.
 */
export function hasUnseenCodePoint(value: string): boolean {
  return UNSEEN.test(value);
}

/** `text` with each code point of {@link UNSEEN_CODE_POINTS} in it replaced by what `shown` makes of it. */
export function replaceUnseenCodePoints(text: string, shown: (codePoint: string) => string): string {
  return text.replace(EVERY_UNSEEN, shown);
}
