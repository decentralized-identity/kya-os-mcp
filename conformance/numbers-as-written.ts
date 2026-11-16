/**
 * The text of a vector file, and the numbers it holds as written.
 *
 * `JSON.stringify` writes a number as the shortest text for its value. A
 * vector that turns on how a number is read needs another text in the file,
 * one every JSON parser reads as that same value: the generator holds the
 * value, the file is written with the text in its place, and the text is
 * read back to be sure the file holds what was generated.
 *
 * `JSON.stringify` also writes a character that does not print as itself as
 * it is, past the C0 controls: a bidirectional override, which shows the
 * text after it in another order, or a zero-width space, which shows as
 * nothing. The file writes each such character as a `\u` escape instead, so
 * it shows a reader, and a diff, what it holds.
 */

import { hasUnprintableCharacter } from '../src/utils/plain-text.js';
import type { VectorFile } from './types.js';

/** A number a vector file holds as written, where `JSON.stringify` writes another text for its value. */
export interface NumberAsWritten {
  /** The one member of the file that holds it. */
  member: string;
  /** The value every JSON parser reads the text as, which the generator holds. */
  value: number;
  text: string;
}

/**
 * `9007199254740993.5` is no integer as written, and is read as the binary64
 * value 9007199254740994, an integer of magnitude above 2^53 - 1 (SPEC §7.8),
 * which `JSON.stringify` writes as that integer.
 */
export const READ_AS_LARGE_INTEGER: NumberAsWritten = {
  member: 'ceiling',
  value: 9_007_199_254_740_994,
  text: '9007199254740993.5',
};

/** Characters outside printable ASCII: those a character that does not print is among. */
const PAST_PRINTABLE_ASCII = /[^\x20-\x7e\n]/gu;

/** `character` as JSON escapes of its UTF-16 code units, when it does not print as itself. */
function shownAsWritten(character: string): string {
  if (!hasUnprintableCharacter(character)) return character;
  let escaped = '';
  for (let index = 0; index < character.length; index += 1) {
    escaped += `\\u${character.charCodeAt(index).toString(16).padStart(4, '0')}`;
  }
  return escaped;
}

/**
 * The text of the vector file `name`: `file` as `JSON.stringify` writes it,
 * with each of `numbersAsWritten` written as its text, and each character
 * that does not print as itself (SPEC §7.8) written as an escape. Such a
 * character is only ever in a string, where an escape reads as it does.
 *
 * @throws when a number's member is not in the file exactly once, or the
 *   text does not read as what was generated.
 */
export function vectorFileText(
  file: VectorFile,
  name: string,
  numbersAsWritten: readonly NumberAsWritten[],
): string {
  const generated = JSON.stringify(file, null, 2) + '\n';
  let text = generated;
  for (const { member, value, text: written } of numbersAsWritten) {
    const parts = text.split(`${JSON.stringify(member)}: ${JSON.stringify(value)}`);
    if (parts.length !== 2) throw new Error(`expected ${name} to hold ${member} once`);
    text = parts.join(`${JSON.stringify(member)}: ${written}`);
  }
  text = text.replace(PAST_PRINTABLE_ASCII, shownAsWritten);
  // The file reads as what the generator holds, whatever text it holds.
  if (JSON.stringify(JSON.parse(text), null, 2) + '\n' !== generated) {
    throw new Error(`expected ${name} to read as it was generated`);
  }
  return text;
}
