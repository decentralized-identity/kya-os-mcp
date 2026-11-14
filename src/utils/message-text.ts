/**
 * Text for people: a refusal reason, or a log line, that interpolates values a caller chose. The
 * delegation verifier and the middleware both write such text, so its sanitizer lives here, below
 * both.
 */

import { isEscapedCharacter } from "./describe-value.js";

declare const messageText: unique symbol;
/** Internal evidence that human-facing text is bounded and contains no lone surrogate. */
export type MessageText = string & { readonly [messageText]: true };

/**
 * Strip control characters and cap length on caller-derived values before they
 * are interpolated into client-facing reasons or log lines. A hostile
 * credential could otherwise embed newlines / control chars in an id or scope to
 * forge or corrupt log entries (log injection) or break a terminal, or a
 * bidirectional control or a character that renders as nothing to make a line
 * read otherwise than it is written, so every character `describeValue` escapes
 * is replaced as well, and a reason shows none of them, quoted or not. The fixed
 * parts of a reason contain no control chars, so sanitizing the whole assembled
 * string at the emission boundary is equivalent to sanitizing each interpolated
 * value, and is idempotent.
 *
 * The result is well-formed text, as the RFC 8785 form a response proof signs a
 * reason in requires: a lone surrogate becomes U+FFFD, and the cap of `maxLen`
 * UTF-16 code units falls before a surrogate pair it would split. A longer value
 * is read only as far as the cap.
 */
export function sanitizeForMessage(value: unknown, maxLen = 256): MessageText {
  const s = typeof value === "string" ? value : String(value);
  // Replace C0 control chars (incl. CR, LF, TAB, ESC) and every character
  // describeValue escapes (DEL, the C1 controls, the line and paragraph
  // separators, format and default-ignorable characters) with U+FFFD, and a lone
  // surrogate (one codePointAt reads alone) so the text stays well-formed.
  // Filtered by code point to keep this source ASCII-only (no literal control
  // chars).
  let out = "";
  for (let i = 0; i < s.length; ) {
    const code = s.codePointAt(i) ?? 0;
    const width = code > 0xffff ? 2 : 1;
    if (out.length + width > maxLen) return `${out}\u2026` as MessageText;
    const character = s.slice(i, i + width);
    const replaced = code <= 0x1f || (code >= 0xd800 && code <= 0xdfff) || isEscapedCharacter(character);
    out += replaced ? "\uFFFD" : character;
    i += width;
  }
  return out as MessageText;
}
