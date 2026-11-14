/**
 * How a refusal reason names a value the other party chose, such as a key id, an issuer DID or a
 * proof purpose. Such a value is as long as its author likes, need not be a string, and need not
 * be well-formed text, and a reason is shown to people, written to logs and signed into response
 * proofs, so a reason quotes at most the value's first 64 characters, as one line of well-formed
 * text set apart by quote marks, and never converts it. A value could otherwise break the line with
 * a control character or a line or paragraph separator (U+2028, U+2029), which some readers and
 * JavaScript source end a line at, or make the reason read in another order than it is written
 * with a bidirectional control, so those are escaped too. A value could also read as another, as a
 * key id with a zero width space in it reads as the id without one, so every character that renders
 * as nothing by default (Unicode's Default_Ignorable_Code_Point) and every format character
 * (General_Category Cf, which holds the bidirectional controls) is escaped as well, which shows it.
 */

/** How many characters of a string a refusal reason quotes, counted as code points. */
export const QUOTED_VALUE_LENGTH = 64;

/**
 * What a JSON string may hold unescaped and a quote escapes: DEL and the C1 controls, the line and
 * paragraph separators, every format character, the bidirectional controls among them, and every
 * character that renders as nothing by default, such as a zero width space or a tag character.
 */
const ESCAPED_CHARACTER = /[\u007f-\u009f\u2028\u2029\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const ESCAPED = new RegExp(ESCAPED_CHARACTER.source, 'gu');

/**
 * Whether `character`, one code point, is one a quote escapes beyond those `JSON.stringify` escapes
 * ({@link ESCAPED_CHARACTER}). `sanitizeForMessage` replaces the same ones, so text for people
 * shows none of them as it stands, quoted or not.
 */
export function isEscapedCharacter(character: string): boolean {
  return ESCAPED_CHARACTER.test(character);
}

/**
 * `value` as a refusal reason names it. A string is quoted as a JSON string of at most its first 64
 * characters, with `...` after the closing quote when it was cut, so the quote marks show where the
 * value starts and ends: `"did:web:acme.example"`, and `""` for the empty string. Every control
 * character, line or paragraph separator, format character and character that renders as nothing,
 * a quote mark and a backslash in it are escaped, so the value can neither break the line, reorder
 * it, hide a character nor end its own quote, and so is a lone surrogate (as `\ud800`), so the
 * quote is well-formed text, which the RFC 8785 form a response proof signs a reason in requires.
 * Characters are counted as code points, so the cut never splits a surrogate pair. Anything else
 * is named by its JSON type alone (`null`, `array`, or what `typeof` names), as in `of type
 * object`, and is never converted: converting a parsed object calls its `toString` member, which
 * its author may have made a string, and that throws.
 */
export function describeValue(value: unknown): string {
  if (typeof value !== 'string') {
    return `of type ${value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value}`;
  }
  let kept = '';
  let characters = 0;
  for (const character of value) {
    if (characters === QUOTED_VALUE_LENGTH) return `${quote(kept)}...`;
    kept += character;
    characters += 1;
  }
  return quote(kept);
}

/**
 * `text` as a JSON string. `JSON.stringify` escapes the C0 controls, a quote mark, a backslash and
 * a lone surrogate; the characters of {@link ESCAPED} are escaped here the same way, as `\uXXXX`
 * for each UTF-16 code unit, so one outside the Basic Multilingual Plane reads as its surrogate pair.
 */
function quote(text: string): string {
  return JSON.stringify(text).replace(ESCAPED, (character) => {
    let escaped = '';
    for (let unit = 0; unit < character.length; unit += 1) {
      escaped += `\\u${character.charCodeAt(unit).toString(16).padStart(4, '0')}`;
    }
    return escaped;
  });
}
