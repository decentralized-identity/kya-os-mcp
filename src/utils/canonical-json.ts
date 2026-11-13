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
 * ordinary data here, and properties JSON does not carry (an object's
 * non-enumerable ones, and an array's other than its elements) are ignored,
 * never consulted. {@link jsonMembers} says which those are.
 */

import { isPlainObjectOfThisRealm } from './guards.js';
import { isWellFormedUnicode } from './plain-text.js';

const encoder = new TextEncoder();

/**
 * Thrown for a value that has no canonical JSON form: the canonicalizer's own
 * refusal of the value. Its class tells that apart from anything else that
 * can go wrong on the way, a call stack that ran out say, which is nothing
 * the value is. It is the `TypeError` these refusals have always been, under
 * the same name and with the same message.
 */
export class CanonicalJsonError extends TypeError {}

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
 * that is joined once, and the path is a stack of an element's index or a
 * member's key, turned into a string only for an error message, so the work
 * stays linear in the size of the input however deeply it nests.
 */
class Serializer {
  readonly out: string[] = [];
  private readonly segments: Array<number | string> = [];

  constructor(
    private readonly root: string,
    readonly ancestors: WeakSet<object>,
  ) {}

  /** Step into an array's element at an index, or an object's member by its key. */
  enter(segment: number | string): void {
    this.segments.push(segment);
  }

  leave(): void {
    this.segments.pop();
  }

  fail(problem: string, suffix = ''): never {
    const path = this.segments.map((segment) => (typeof segment === 'number' ? `[${segment}]` : `.${segment}`));
    throw new CanonicalJsonError(`Cannot canonicalize ${problem} at ${this.root}${path.join('')}${suffix}`);
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
    // RFC 8785 requires invalid Unicode data (unpaired UTF-16 surrogates) to fail.
    if (!isWellFormedUnicode(value)) s.fail('string with lone surrogate');
    s.out.push(JSON.stringify(value));
    return;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) s.fail('non-finite number', `: ${value}`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) s.fail('unsafe integer', `: ${value}`);
    // The shortest form that reads back as the number, as JSON.stringify
    // writes it: -0 is written as 0.
    s.out.push(String(value));
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
    if (Array.isArray(value)) {
      refuseHoles(value, s);
      s.out.push('[');
      for (let index = 0; index < value.length; index += 1) {
        if (index > 0) s.out.push(',');
        const property = Object.getOwnPropertyDescriptor(value, index);
        if (property === undefined) refuseHole(index, s);
        serializeMember(index, property, s);
      }
      s.out.push(']');
    } else {
      const members = objectMembers(value, s);
      s.out.push('{');
      for (let index = 0; index < members.length; index += 1) {
        const [key, property] = members[index]!;
        s.out.push(index > 0 ? ',' : '', JSON.stringify(key), ':');
        serializeMember(key, property, s);
      }
      s.out.push('}');
    }
  } finally {
    s.ancestors.delete(value);
  }
}

/** Write the value of an element or member, at `segment` of the path, from its property as it stands. */
function serializeMember(segment: number | string, property: PropertyDescriptor, s: Serializer): void {
  s.enter(segment);
  // A getter could answer differently each time it is read, so the value
  // checked might not be the value written: refused.
  if (!('value' in property)) s.fail('accessor property');
  serialize(property.value, s);
  s.leave();
}

/** A member of an array or object: its key, an element's being its index, and its property. */
export type JsonMember = [key: string, property: PropertyDescriptor];

/**
 * The enumerable string-keyed members of an array or object, in the order
 * it holds them, each with its property as it stands: no accessor is called
 * to list them. These are an object's members in JSON.
 */
export function enumerableMembers(value: object): JsonMember[] {
  const members: JsonMember[] = [];
  // `Object.keys` lists exactly these keys, in this order, faster than
  // listing every own key and filtering them. Each property is then read as
  // it stands, and kept only if it still reads as enumerable: a Proxy need
  // not answer twice alike.
  for (const key of Object.keys(value)) {
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property?.enumerable) members.push([key, property]);
  }
  return members;
}

/**
 * The value of an object's member named `key` as the object's JSON form
 * has it, one of its {@link enumerableMembers}. Undefined when there is no
 * such member, or it is an accessor, which is not called.
 */
export function jsonMemberValue(object: object, key: string): unknown {
  const property = Object.getOwnPropertyDescriptor(object, key);
  return property?.enumerable ? property.value : undefined;
}

/**
 * The members the JSON form of an array or object is written from, in the
 * order the value holds them, each with its property as it stands.
 *
 * - An array's are its elements, from index 0 up to its length, enumerable
 *   or not: `JSON.stringify` writes every one. They end at the first index
 *   that holds no element, since a hole has no JSON form and nothing after
 *   it is read. Any other own property of an array (a `toJSON`, a RegExp
 *   match's `index` and `input`) is not JSON.
 * - An object's are its {@link enumerableMembers}. One that is not
 *   enumerable is not JSON.
 *
 * The canonicalizer writes these and nothing else, and the count of how
 * deep a value nests reads these same members (`./plain-data.ts`), so
 * nothing the canonicalizer recurses into goes uncounted.
 */
export function jsonMembers(container: object): JsonMember[] {
  if (!Array.isArray(container)) return enumerableMembers(container);
  const elements: JsonMember[] = [];
  for (let index = 0; index < container.length; index += 1) {
    const property = Object.getOwnPropertyDescriptor(container, index);
    if (property === undefined) break;
    elements.push([String(index), property]);
  }
  return elements;
}

/**
 * Refuse an array with a hole before any of its elements is written: an
 * array's members are its elements (see {@link jsonMembers}), and it has one
 * at every index.
 */
function refuseHoles(array: unknown[], s: Serializer): void {
  for (let index = 0; index < array.length; index += 1) {
    if (!Object.hasOwn(array, index)) refuseHole(index, s);
  }
}

function refuseHole(index: number, s: Serializer): never {
  s.enter(index);
  return s.fail('sparse array element');
}

/**
 * Enumerable string-keyed members (see {@link jsonMembers}), sorted. A
 * member keyed by a symbol, or by a string with a lone surrogate, refuses
 * the object even when it is not enumerable.
 */
function objectMembers(object: object, s: Serializer): JsonMember[] {
  if (!isPlainObjectOfThisRealm(object)) s.fail('non-plain object');

  for (const key of Reflect.ownKeys(object)) {
    if (typeof key === 'symbol') s.fail('symbol-keyed property');
    if (!isWellFormedUnicode(key)) s.fail('object key with lone surrogate');
  }
  // RFC 8785 §3.2.3: sort member names by their UTF-16 code units, which is
  // exactly how JavaScript compares strings.
  return jsonMembers(object).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
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
