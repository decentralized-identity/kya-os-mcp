/**
 * Strict RFC 8785 JSON canonicalization for integrity-critical inputs.
 *
 * `json-canonicalize` intentionally follows JSON serialization semantics, which
 * can silently erase or coerce unsupported JavaScript values. Protocol digests
 * must fail closed instead: two distinguishable JavaScript inputs must never be
 * accepted as the same canonical JSON value by accident.
 *
 * The serializer here is our own, over the value as validated. Any library
 * that honours `toJSON` — `json-canonicalize` hands every object with one to
 * `JSON.stringify` — lets a member named `toJSON` switch off key sorting, and a
 * hidden `toJSON` function replace the value outright. A `toJSON` member is
 * ordinary data here, and properties JSON does not carry (non-enumerable
 * ones, and an array's non-index ones) are ignored, never consulted.
 */

const encoder = new TextEncoder();

/** RFC 8785 requires invalid Unicode data (unpaired UTF-16 surrogates) to fail. */
function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** Validate that a value has an unambiguous JSON representation. */
export function assertCanonicalJsonValue(
  value: unknown,
  path = '$',
  ancestors: WeakSet<object> = new WeakSet<object>(),
): void {
  serialize(value, new Serializer(path, ancestors));
}

/**
 * Output and position for one serialization. Text goes into one shared list
 * that is joined once, and the path is a stack turned into a string only for
 * an error message, so the work stays linear in the size of the input however
 * deeply it nests.
 */
class Serializer {
  readonly out: string[] = [];
  private readonly segments: string[] = [];

  constructor(
    private readonly root: string,
    readonly ancestors: WeakSet<object>,
  ) {}

  enter(segment: string): void {
    this.segments.push(segment);
  }

  leave(): void {
    this.segments.pop();
  }

  fail(problem: string, suffix = ''): never {
    throw new TypeError(`Cannot canonicalize ${problem} at ${this.root}${this.segments.join('')}${suffix}`);
  }
}

/**
 * Validate `value` and serialize it per RFC 8785 in one pass, so the output is
 * built from exactly the data that was checked. Strings and numbers are
 * written as ECMAScript `JSON.stringify` writes them, which is the RFC 8785
 * rule (§3.2.2.2, §3.2.2.3); `toJSON` is never called.
 *
 * One stack frame per nesting level: arrays and objects recurse from here
 * directly, so deep input reaches the same depth it did before.
 */
function serialize(value: unknown, s: Serializer): void {
  if (value === null) {
    s.out.push('null');
    return;
  }
  if (typeof value === 'boolean') {
    s.out.push(value ? 'true' : 'false');
    return;
  }

  if (typeof value === 'string') {
    if (hasLoneSurrogate(value)) s.fail('string with lone surrogate');
    s.out.push(JSON.stringify(value));
    return;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) s.fail('non-finite number', `: ${value}`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) s.fail('unsafe integer', `: ${value}`);
    s.out.push(JSON.stringify(value)); // shortest round-trip form; -0 is written as 0
    return;
  }

  if (typeof value === 'undefined') s.fail('undefined');
  if (typeof value === 'function') s.fail('function');
  if (typeof value === 'symbol') s.fail('symbol');
  if (typeof value === 'bigint') s.fail('bigint');
  if (typeof value !== 'object') s.fail('unsupported value');
  if (s.ancestors.has(value)) s.fail('cyclic reference');

  s.ancestors.add(value);
  try {
    const array = Array.isArray(value);
    const members = array ? arrayElements(value, s) : objectMembers(value, s);
    s.out.push(array ? '[' : '{');
    for (let index = 0; index < members.length; index += 1) {
      const [segment, key, descriptor] = members[index]!;
      if (index > 0) s.out.push(',');
      if (!array) s.out.push(JSON.stringify(key), ':');
      s.enter(segment);
      // A getter could answer differently each time it is read, so the value
      // checked might not be the value written: refused.
      if (!('value' in descriptor)) s.fail('accessor property');
      serialize(descriptor.value, s);
      s.leave();
    }
    s.out.push(array ? ']' : '}');
  } finally {
    s.ancestors.delete(value);
  }
}

/** A member to write: its path segment, its key (objects), and its property. */
type Member = [segment: string, key: string, descriptor: PropertyDescriptor];

/**
 * Elements only. Any other own property (a `toJSON`, a RegExp match's `index`
 * and `input`) is not JSON and never reaches the output, so it is ignored.
 */
function arrayElements(array: unknown[], s: Serializer): Member[] {
  const elements: Member[] = [];
  for (let index = 0; index < array.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(array, index);
    if (!descriptor) {
      s.enter(`[${index}]`);
      s.fail('sparse array element');
    }
    elements.push([`[${index}]`, '', descriptor]);
  }
  return elements;
}

/**
 * Enumerable string-keyed members, sorted. Non-enumerable ones are not JSON
 * and are ignored.
 */
function objectMembers(object: object, s: Serializer): Member[] {
  const prototype = Object.getPrototypeOf(object) as object | null;
  if (prototype !== Object.prototype && prototype !== null) s.fail('non-plain object');

  const members: Member[] = [];
  for (const key of Reflect.ownKeys(object)) {
    if (typeof key === 'symbol') s.fail('symbol-keyed property');
    if (hasLoneSurrogate(key)) s.fail('object key with lone surrogate');
    const descriptor = Object.getOwnPropertyDescriptor(object, key)!;
    if (descriptor.enumerable) members.push([`.${key}`, key, descriptor]);
  }
  // RFC 8785 §3.2.3: sort member names by their UTF-16 code units, which is
  // exactly how JavaScript compares strings.
  return members.sort(([, a], [, b]) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Canonicalize a strict JSON value according to RFC 8785. */
export function canonicalizeJson(value: unknown): string {
  const s = new Serializer('$', new WeakSet<object>());
  serialize(value, s);
  return s.out.join('');
}

/** Canonical UTF-8 bytes for hashing or signing. */
export function canonicalizeJsonBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalizeJson(value));
}
