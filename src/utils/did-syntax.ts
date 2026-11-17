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

/** A DID method name: one or more lower-case letters and digits (DID Core `method-name`). */
const METHOD_NAME = /^[a-z0-9]+$/;

/** One character of a method-specific id, as a pattern: a letter, a digit, `.`, `-`, `_`, or a percent-encoded octet (DID Core `idchar`). */
const ID_CHAR = '(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})';

/** A character a method-specific id holds as it stands: one of DID Core's `idchar` other than `%`, or the `:` between parts. */
const PLAIN_ID_CHARACTER = /^[A-Za-z0-9._:-]$/;

/** The two hex digits that follow a `%` in a percent-encoded octet. */
const HEX_PAIR = /^[0-9A-Fa-f]{2}$/;

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
  const method = methodNames(methods).length === 0 ? '[a-z0-9]+' : `(?:${methods.join('|')})`;
  return new RegExp(`^did:${method}:(?:${ID_CHAR}*:)*${ID_CHAR}+$`);
}

/** Whether `value` is a DID of any method, by the DID rule. */
export function isDid(value: unknown): value is string {
  return typeof value === 'string' && ANY_DID.test(value);
}

/**
 * Why `value` is not a DID of one of `methods` (of any method when `methods` is empty or absent), or
 * `undefined` exactly when `didPattern(methods)` matches it. The reason is the first that applies, in
 * the order a DID is read: that the value is not a string, is empty, or does not start with `did:`;
 * that it has no method-specific id, no method name, or a method name of other characters; that its
 * method is not one of `methods`; then the first character of the method-specific id, read left to
 * right, that a DID does not hold as it stands (the start of a path, query or fragment, which makes
 * the value a DID URL, a `%` without two hex digits, a space, or any other character); and last, an
 * empty last part. A reason quotes what it names as {@link describeValue} does, so it stays short and
 * one line however long the value, and it says nothing a resolution could change. Throws a
 * `TypeError` when a name in `methods` is not a DID method name, as {@link didPattern} does.
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
    const character = String.fromCodePoint(id.codePointAt(at)!);
    if (character === '#') return `is a DID URL: drop the ${describeValue(id.slice(at))} fragment`;
    if (character === '?') return `is a DID URL: drop the ${describeValue(id.slice(at, endOf(id, at, '#')))} query`;
    if (character === '/') return `is a DID URL: drop the ${describeValue(id.slice(at, endOf(id, at, '?#')))} path`;
    if (character === '%') {
      if (!HEX_PAIR.test(id.slice(at + 1, at + 3))) return 'has a "%" not followed by two hex digits';
      at += 3;
      continue;
    }
    if (character === ' ') return 'contains a space';
    if (!PLAIN_ID_CHARACTER.test(character)) {
      return `contains ${describeValue(character)}, which a DID writes percent-encoded`;
    }
    at += character.length;
  }
  return id.endsWith(':') ? 'ends with ":", so its last part is empty' : undefined;
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
