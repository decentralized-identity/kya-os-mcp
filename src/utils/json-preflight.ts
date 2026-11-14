/**
 * A lexical pass over JSON text before `JSON.parse` sees it, so the engine never builds a value
 * deeper, wider or with longer member names than the limits allow. `JSON.parse` still checks the
 * grammar; this pass only counts.
 */

/** The shape JSON text may have before it is parsed. */
export interface JsonLimits {
  /** Containers open at once. */
  readonly maxDepth: number;
  /** Object members in all, duplicate names counted. */
  readonly maxMembers: number;
  /** A member name's length in UTF-16 code units, once its escapes are decoded. */
  readonly maxMemberLength: number;
}

const OPEN_OBJECT = 0x7b, OPEN_ARRAY = 0x5b, CLOSE_OBJECT = 0x7d, CLOSE_ARRAY = 0x5d;
const QUOTE = 0x22, BACKSLASH = 0x5c, COLON = 0x3a, LETTER_U = 0x75;

/** JSON's four whitespace characters, looked up by code unit. */
const WHITESPACE = new Uint8Array(128);
for (const code of [0x09, 0x0a, 0x0d, 0x20]) WHITESPACE[code] = 1;

/** Throw when `text` nests deeper than, or has more or longer member names than, `limits` allow. */
export function checkJsonTokens(text: string, limits: JsonLimits): void {
  let depth = 0;
  let members = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code === OPEN_OBJECT || code === OPEN_ARRAY) {
      depth++;
      if (depth > limits.maxDepth) throw new Error('JSON nesting limit exceeded');
    } else if (code === CLOSE_OBJECT || code === CLOSE_ARRAY) {
      depth--;
    } else if (code === QUOTE) {
      let units = 0;
      for (i++; i < text.length && text.charCodeAt(i) !== QUOTE; i++) {
        if (text.charCodeAt(i) === BACKSLASH) {
          i++;
          if (text.charCodeAt(i) === LETTER_U) i += 4;
        }
        units++;
      }
      let next = i + 1;
      while (WHITESPACE[text.charCodeAt(next)] === 1) next++;
      if (text.charCodeAt(next) === COLON) {
        members++;
        if (units > limits.maxMemberLength || members > limits.maxMembers) {
          throw new Error('JSON member limit exceeded');
        }
      }
    }
  }
}
