/**
 * The DID rule: a DID as W3C DID Core 1.0 §3.1 writes one. A DID is `did:`, a method name of
 * lower-case letters and digits, `:`, and a method-specific id: parts joined by `:`, each a run of
 * letters, digits, `.`, `-`, `_` and percent-encoded octets (`%` and two hex digits), of which only
 * the last may not be empty. A DID URL, which adds a path, a query or a fragment, is not a DID, and
 * neither is a value holding any other character, which a DID writes percent-encoded. The rule is
 * syntax alone: whether a DID is a usable one of its method, such as a did:web DID naming a host, is
 * for the method's resolver to decide.
 *
 * {@link didPattern} is the rule as the regular expression a JSON Schema publishes for a DID member,
 * held to the methods the member takes. {@link whyNotDid} says why a value breaks it, in one short
 * reason decided by the value alone, so the reason may be shown to whoever presented the value; the
 * two agree on every string. {@link isDid} tests a value against the rule for any method.
 */

import { describeValue } from './describe-value.js';

/** One character of a DID method name, as a regular expression class: a lower-case ASCII letter or a digit (DID Core `method-char`). */
const METHOD_CHAR = '[a-z0-9]';

/** One character of a method-specific id that stands for itself, as a regular expression class: an ASCII letter, a digit, `.`, `-` or `_`. */
const PLAIN_ID_CHAR = '[A-Za-z0-9._-]';

/** One hex digit, in either case, as a regular expression class (DID Core `HEXDIG`). */
const HEX_DIGIT = '[0-9A-Fa-f]';

/** One character of a method-specific id, as a pattern: one that stands for itself, or a percent-encoded octet (DID Core `idchar`). */
const ID_CHAR = `(?:${PLAIN_ID_CHAR}|%${HEX_DIGIT}{2})`;

/** A DID method name: one or more lower-case letters and digits (DID Core `method-name`). */
const METHOD_NAME = new RegExp(`^${METHOD_CHAR}+$`);

/** A character a method-specific id holds as it stands: one of DID Core's `idchar` other than `%`, or the `:` between parts. */
const PLAIN_ID_CHARACTER = new RegExp(`^(?:${PLAIN_ID_CHAR}|:)$`);

/** The two hex digits that follow a `%` in a percent-encoded octet. */
const HEX_PAIR = new RegExp(`^${HEX_DIGIT}{2}$`);

/** A white-space character, as `\s` in a regular expression reads one: a space, a tab, a line break, a no-break space and the like. */
const WHITE_SPACE = /^\s$/u;

/** The parts a DID URL adds to a DID, by the character that starts each, with the characters that start a later part and so end it. */
const DID_URL_PARTS: ReadonlyMap<string, { readonly name: string; readonly endsAt: string }> = new Map([
  ['/', { name: 'path', endsAt: '?#' }],
  ['?', { name: 'query', endsAt: '#' }],
  ['#', { name: 'fragment', endsAt: '' }],
]);

/** The scheme written in any case. DID Core writes it `did:`, in lower case alone. */
const SCHEME_IN_ANY_CASE = /^[Dd][Ii][Dd]:/;

/** The DID rule for any method, which {@link isDid} tests. */
const ANY_DID = didPattern();

/**
 * The DID rule as an anchored regular expression without flags, which matches a DID of one of
 * `methods`, or of any method when `methods` is empty or absent. Its `source` is the `pattern` a JSON
 * Schema publishes for a DID member, with the method names in the order given: for `['key', 'web']`,
 * `^did:(?:key|web):(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$`.
 * It matches in time linear in the length of the value, since it reads each character in one way
 * only. Throws a `TypeError` when a name in `methods` is not a DID method name.
 */
export function didPattern(methods: readonly string[] = []): RegExp {
  const method = methodNames(methods).length === 0 ? `${METHOD_CHAR}+` : `(?:${methods.join('|')})`;
  return new RegExp(`^did:${method}:(?:${ID_CHAR}*:)*${ID_CHAR}+$`);
}

/**
 * Whether `value` is a DID of any method, by the DID rule. It narrows `value` to
 * `did:${string}:${string}`, the type of every DID and of many strings that are not DIDs, so a string
 * it refuses keeps the type `string`.
 */
export function isDid(value: unknown): value is `did:${string}:${string}` {
  return typeof value === 'string' && ANY_DID.test(value);
}

/**
 * Why `value` is not a DID of one of `methods` (of any method when `methods` is empty or absent), or
 * `undefined` exactly when `didPattern(methods)` matches it. The reason is the first that applies, in
 * the order a DID is read: that the value is not a string, is empty, or does not start with `did:`;
 * that it has no method-specific id, no method name, or a method name of other characters; that its
 * method is not one of `methods`; then the first character of the method-specific id, read left to
 * right, that a DID does not hold as it stands; and last, an empty last part. That character is the
 * start of a path, query or fragment, which makes the value a DID URL when a DID comes before it and
 * otherwise follows an empty method-specific id or an empty last part; a `%` without two hex digits;
 * a space; other white space, named by its code point, as `U+00A0`, since a quote of it reads as a
 * space; or any other character. A reason quotes what it names as {@link describeValue} does, so it
 * stays short and one line however long the value, and it says nothing a resolution could change.
 * Throws a `TypeError` when a name in `methods` is not a DID method name, as {@link didPattern} does.
 */
export function whyNotDid(value: unknown, methods: readonly string[] = []): string | undefined {
  const named = methodNames(methods);
  if (typeof value !== 'string') return `is ${describeValue(value)}, not a string`;
  if (value === '') return 'is empty';
  if (!value.startsWith('did:')) {
    return SCHEME_IN_ANY_CASE.test(value)
      ? `starts with ${describeValue(value.slice(0, 4))}; the scheme is written in lower case: "did:"`
      : 'does not start with "did:"';
  }
  const methodEnd = value.indexOf(':', 4);
  if (methodEnd === -1 || methodEnd === value.length - 1) return 'has no method-specific id';
  const method = value.slice(4, methodEnd);
  if (method === '') return 'has no method name';
  if (!METHOD_NAME.test(method)) {
    return `has the method name ${describeValue(method)}, which may hold only lower-case letters and digits`;
  }
  if (named.length > 0 && !named.includes(method)) return `uses ${describeValue(`did:${method}`)}, not ${listed(named)}`;
  return whyNotMethodSpecificId(value.slice(methodEnd + 1));
}

/**
 * Why `id`, the non-empty method-specific id of a DID, breaks the rule, or `undefined` when it keeps
 * it. Its characters are read left to right, by code point, so a character outside the Basic
 * Multilingual Plane is quoted whole.
 */
function whyNotMethodSpecificId(id: string): string | undefined {
  let at = 0;
  while (at < id.length) {
    const codePoint = id.codePointAt(at)!;
    const character = String.fromCodePoint(codePoint);
    const part = DID_URL_PARTS.get(character);
    if (part !== undefined) {
      if (at === 0) return 'has no method-specific id';
      const quoted = describeValue(id.slice(at, endOf(id, at, part.endsAt)));
      return id[at - 1] === ':' ? `has an empty part before ${quoted}` : `is a DID URL: drop the ${quoted} ${part.name}`;
    }
    if (character === '%') {
      if (!HEX_PAIR.test(id.slice(at + 1, at + 3))) return 'has a "%" not followed by two hex digits';
      at += 3;
      continue;
    }
    if (character === ' ') return 'contains a space';
    if (WHITE_SPACE.test(character)) {
      return `contains the white-space character ${writtenCodePoint(codePoint)}, which a DID writes percent-encoded`;
    }
    if (!PLAIN_ID_CHARACTER.test(character)) {
      return `contains ${describeValue(character)}, which a DID writes percent-encoded`;
    }
    at += character.length;
  }
  return id.endsWith(':') ? 'ends with ":", so its last part is empty' : undefined;
}

/** `codePoint` as the Unicode Standard writes one in running text: `U+` and four to six upper-case hex digits, as `U+00A0`. */
function writtenCodePoint(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** Where in `text` the part that starts at `start` ends: at the first of `ends` after it, or at the end of `text`. */
function endOf(text: string, start: number, ends: string): number {
  for (let at = start + 1; at < text.length; at += 1) {
    if (ends.includes(text[at]!)) return at;
  }
  return text.length;
}

/** `methods`, once each is a DID method name; a `TypeError` names the first that is not. */
function methodNames(methods: readonly string[]): readonly string[] {
  for (const method of methods) {
    if (typeof method !== 'string' || !METHOD_NAME.test(method)) {
      throw new TypeError(
        `A DID method name holds only lower-case letters and digits, and the method ${describeValue(method)} does not`,
      );
    }
  }
  return methods;
}

/** `methods` as a reason lists them: `did:key`, `did:key or did:web`, `did:key, did:web or did:webvh`. */
function listed(methods: readonly string[]): string {
  const dids = methods.map((method) => `did:${method}`);
  const last = dids.pop() ?? '';
  return dids.length === 0 ? last : `${dids.join(', ')} or ${last}`;
}
