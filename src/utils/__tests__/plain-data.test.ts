/**
 * What is settled about a value before anything recursive reads it: how deep
 * it nests, and whether it is plain data. Both are decided by one walk, a
 * loop, so neither turns on how deep a call stack the runtime has, and
 * neither runs code the value carries.
 */
import { describe, expect, it } from 'vitest';
import { arrays, mixed, objects } from '../../__tests__/utils/nesting.js';
import { jsonTextNestsDeeperThan, nestsDeeperThan, readPlainData } from '../plain-data.js';

/** Whether one walk takes `value` for plain data. */
const isPlainData = (value: unknown): boolean => readPlainData(value, Number.POSITIVE_INFINITY).plainData;

/** A walk of a million levels takes seconds on a busy machine. */
const millionLevels = { timeout: 60_000 };

/**
 * `container` behind a Proxy that counts how often its members are listed,
 * and stops the walk once that is more than `ceiling`. A walk runs
 * synchronously, so a timeout cannot end one that goes on: a walk that lists
 * a value more often than it should fails at once instead.
 */
function listedAtMost(container: object, ceiling: number): { value: object; listed: () => number } {
  let listed = 0;
  const value = new Proxy(container, {
    ownKeys(target) {
      listed += 1;
      if (listed > ceiling) throw new Error(`the innermost value was listed ${listed} times`);
      return Reflect.ownKeys(target);
    },
  });
  return { value, listed: () => listed };
}

/** `levels` levels of `nested` around an innermost array listed at most once. */
const listedOnce = (nested: (levels: number, leaf: unknown) => unknown, levels: number): unknown =>
  nested(levels - 1, listedAtMost(['leaf'], 1).value);

describe('nestsDeeperThan', () => {
  it.each([
    ['a string', 'text'],
    ['a number', 7],
    ['null', null],
    ['undefined', undefined],
    ['a function', () => 1],
  ])('counts no level for %s, which nothing nests in', (_name, value) => {
    expect(nestsDeeperThan(value, 0)).toBe(false);
  });

  it('counts the value itself as level 1', () => {
    expect(nestsDeeperThan({}, 1)).toBe(false);
    expect(nestsDeeperThan([], 1)).toBe(false);
    expect(nestsDeeperThan({}, 0)).toBe(true);
    expect(nestsDeeperThan([], 0)).toBe(true);
  });

  it.each([
    ['arrays', arrays],
    ['objects', objects],
    ['arrays and objects in turn', mixed],
  ])('counts one level for each of the %s a value is inside', (_name, nested) => {
    for (const levels of [1, 2, 3, 64, 65, 1000]) {
      expect(nestsDeeperThan(listedOnce(nested, levels), levels)).toBe(false);
      expect(nestsDeeperThan(listedOnce(nested, levels), levels - 1)).toBe(true);
    }
  });

  it('takes the deepest of the members, wherever it stands among them', () => {
    const shallow = { a: 1, b: [2], c: { d: 3 } };
    for (const value of [
      { first: arrays(5), ...shallow },
      { ...shallow, last: arrays(5) },
      [1, [2], arrays(5), 'x'],
    ]) {
      expect(nestsDeeperThan(value, 6)).toBe(false);
      expect(nestsDeeperThan(value, 5)).toBe(true);
    }
  });

  it('counts a value that holds itself as deeper than any limit', millionLevels, () => {
    const selfHeld: Record<string, unknown> = { id: 'x' };
    selfHeld.self = selfHeld;
    const ring: unknown[] = [];
    ring.push([[ring]]);
    for (const limit of [1, 64, 1_000_000]) {
      expect(nestsDeeperThan(selfHeld, limit)).toBe(true);
      expect(nestsDeeperThan(ring, limit)).toBe(true);
    }
  });

  it('counts a value met twice at its deepest place, and not as a value that holds itself', () => {
    const shared = arrays(3);
    // Level 2 through `near`, and level 4 through `far`: 3 more below either.
    const value = { near: shared, far: [[shared]] };
    expect(nestsDeeperThan(value, 6)).toBe(false);
    expect(nestsDeeperThan(value, 5)).toBe(true);
    // The same when the deeper path is met first.
    const reversed = { far: [[shared]], near: shared };
    expect(nestsDeeperThan(reversed, 6)).toBe(false);
    expect(nestsDeeperThan(reversed, 5)).toBe(true);
  });

  it('reads a value shared by many others once, not once for each path to it or each level it is met at', () => {
    // Forty levels, each holding the next twice: 2^39 paths to the last,
    // which past a few listings stops the walk (see `listedAtMost`).
    const last = listedAtMost(['leaf', 'leaf'], 8);
    let value: unknown = last.value;
    for (let level = 1; level < 40; level += 1) value = [value, value];

    expect(nestsDeeperThan(value, 40)).toBe(false);
    expect(last.listed()).toBe(1);
    expect(nestsDeeperThan(value, 39)).toBe(true);
    expect(last.listed()).toBe(1);
  });

  it('takes no call stack: a value nested a million deep is counted', millionLevels, () => {
    expect(nestsDeeperThan(listedOnce(arrays, 1_000_000), 64)).toBe(true);
    expect(nestsDeeperThan(listedOnce(arrays, 1_000_000), 1_000_000)).toBe(false);
    expect(nestsDeeperThan(listedOnce(objects, 1_000_000), 999_999)).toBe(true);
  });

  it('follows the named members of an array, as a copy does', () => {
    const tagged: unknown[] & { kept?: unknown } = [1];
    tagged.kept = arrays(3);
    expect(nestsDeeperThan(tagged, 4)).toBe(false);
    expect(nestsDeeperThan(tagged, 3)).toBe(true);
  });

  it('follows an element that is not enumerable, as the canonicalizer does', () => {
    const hidden = Object.defineProperty([1], 0, { value: arrays(3), enumerable: false });
    expect(nestsDeeperThan(hidden, 4)).toBe(false);
    expect(nestsDeeperThan(hidden, 3)).toBe(true);
    expect(nestsDeeperThan({ a: hidden }, 4)).toBe(true);
    // Deeper than any call stack, and still counted by the loop.
    const abyss = Object.defineProperty([1], 0, { value: listedOnce(arrays, 200_000), enumerable: false });
    expect(nestsDeeperThan(abyss, 64)).toBe(true);
    expect(nestsDeeperThan(abyss, 200_001)).toBe(false);
  });

  it('follows an element past a hole, as a copy does', () => {
    const holed: unknown[] = [];
    holed[1] = arrays(3);
    expect(nestsDeeperThan(holed, 4)).toBe(false);
    expect(nestsDeeperThan(holed, 3)).toBe(true);
  });

  it('runs no accessor, and does not follow one', () => {
    let reads = 0;
    const guarded = Object.defineProperty({}, 'deep', {
      enumerable: true,
      get: () => {
        reads += 1;
        return arrays(100);
      },
    });
    expect(nestsDeeperThan(guarded, 1)).toBe(false);
    expect(reads).toBe(0);
  });

  it('does not follow a member that is not enumerable, or one keyed by a symbol: neither is JSON', () => {
    const hidden = Object.defineProperty({}, 'deep', { enumerable: false, value: arrays(100) });
    expect(nestsDeeperThan(hidden, 1)).toBe(false);
    expect(nestsDeeperThan({ [Symbol('deep')]: arrays(100) }, 1)).toBe(false);
  });
});

describe('jsonTextNestsDeeperThan', () => {
  const text = (value: unknown) => JSON.stringify(value);

  it.each([
    ['arrays', arrays],
    ['objects', objects],
    ['arrays and objects in turn', mixed],
  ])('counts the %s of a JSON text as nestsDeeperThan counts the value it parses to', (_name, nested) => {
    for (const levels of [1, 2, 64, 65, 500]) {
      expect(jsonTextNestsDeeperThan(text(nested(levels)), levels)).toBe(false);
      expect(jsonTextNestsDeeperThan(text(nested(levels)), levels - 1)).toBe(true);
    }
  });

  it('counts no level for a text with no array or object in it', () => {
    for (const scalar of ['"text"', '7', 'null', 'true', '']) {
      expect(jsonTextNestsDeeperThan(scalar, 0)).toBe(false);
    }
  });

  it('counts the deepest place, not how many arrays and objects there are', () => {
    const wide = text(Array.from({ length: 500 }, () => [{ a: [1] }]));
    expect(jsonTextNestsDeeperThan(wide, 4)).toBe(false);
    expect(jsonTextNestsDeeperThan(wide, 3)).toBe(true);
  });

  it('passes over brackets inside a string', () => {
    expect(jsonTextNestsDeeperThan(text({ a: '[[[[[[[[' }), 1)).toBe(false);
    expect(jsonTextNestsDeeperThan(text({ '{{{{{{': 1 }), 1)).toBe(false);
    expect(jsonTextNestsDeeperThan(text(['}', ']', '{', '[']), 1)).toBe(false);
  });

  it('does not take an escaped quote for the end of a string', () => {
    // {"a":"\"[[[[","b":[[1]]}: the brackets after the escaped quote are text.
    const escaped = text({ a: '"[[[[', b: [[1]] });
    expect(escaped).toContain('\\"[[[[');
    expect(jsonTextNestsDeeperThan(escaped, 3)).toBe(false);
    expect(jsonTextNestsDeeperThan(escaped, 2)).toBe(true);
  });

  it('takes a quote after an escaped backslash for the end of a string', () => {
    // {"a":"\\","b":[[[1]]]}: the string ends at the quote after the two backslashes.
    const ended = text({ a: '\\', b: [[[1]]] });
    expect(ended).toContain('"\\\\"');
    expect(jsonTextNestsDeeperThan(ended, 4)).toBe(false);
    expect(jsonTextNestsDeeperThan(ended, 3)).toBe(true);
  });

  it('counts a text that closes what it did not open as it stands, without failing', () => {
    // Not JSON, which a parser will say. The count does not go wrong on it.
    expect(jsonTextNestsDeeperThan(']]]]', 0)).toBe(false);
    expect(jsonTextNestsDeeperThan(']]]][', 0)).toBe(false);
    expect(jsonTextNestsDeeperThan('[[[[', 3)).toBe(true);
    expect(jsonTextNestsDeeperThan('"[[[[', 0)).toBe(false);
  });

  it('is one pass: a text nested a million deep is counted without being parsed', millionLevels, () => {
    const deep = '['.repeat(1_000_000) + ']'.repeat(1_000_000);
    expect(jsonTextNestsDeeperThan(deep, 64)).toBe(true);
    expect(jsonTextNestsDeeperThan(deep, 1_000_000)).toBe(false);
  });
});

describe('isPlainData', () => {
  class Held {
    constructor(readonly kept = 'by a store') {}
  }
  class Scopes extends Array<string> {}
  class Stamp extends Date {}

  it.each([
    ['a string', 'text'],
    ['a number', 7],
    ['a number that is not finite', Number.NaN],
    ['a boolean', false],
    ['null', null],
    ['undefined', undefined],
    ['a bigint', 1n],
    ['an empty object', {}],
    ['an empty array', []],
    ['what JSON parses to', JSON.parse('{"a":[1,"two",{"three":null}],"b":{"c":true}}')],
    ['an object with no prototype', Object.assign(Object.create(null), { a: [1] })],
    ['a frozen object', Object.freeze({ a: Object.freeze([1]) })],
    ['an object that holds undefined', { a: undefined }],
    ['an object that holds a bigint', { a: 1n }],
    // eslint-disable-next-line no-sparse-arrays -- a hole is the case
    ['an array with a hole', [1, , 3]],
    ['an array of a subclass of Array', Scopes.from(['a', 'b'])],
    ['an array with a named member', Object.assign(['a'], { kept: 'by a store' })],
    ['a Date', new Date(0)],
    ['an object that holds a Date', { at: new Date(0) }],
    ['an object with a member named __proto__', JSON.parse('{"__proto__":{"a":1}}')],
  ])('takes %s for plain data', (_name, value) => {
    expect(isPlainData(value)).toBe(true);
  });

  it.each([
    ['a function', () => 1],
    ['a symbol', Symbol('tag')],
    ['a class instance', new Held()],
    ['a Map', new Map([['a', 1]])],
    ['a Set', new Set([1])],
    ['a RegExp', /a/],
    ['a typed array', new Uint8Array(2)],
    ['an Error', new Error('fault')],
    ['a boxed string', Object('text')],
    ['an instance of a subclass of Date', new Stamp(0)],
    ['an object given the prototype of a Date', Object.create(Date.prototype)],
    ['an object given another object for a prototype', Object.create({ inherited: 1 })],
    ['an object with a symbol-keyed member', { [Symbol('tag')]: 1 }],
    ['an object with a symbol-keyed member that is not enumerable',
      Object.defineProperty({}, Symbol('tag'), { enumerable: false, value: 1 })],
    ['an object with a getter', Object.defineProperty({}, 'a', { enumerable: true, get: () => 1 })],
    ['an object with a setter alone', Object.defineProperty({}, 'a', { enumerable: true, set: () => undefined })],
    ['an array with a getter for an element', Object.defineProperty([0], 0, { enumerable: true, get: () => 1 })],
    ['an array with an element that is not enumerable', Object.defineProperty([0], 0, { enumerable: false, value: 1 })],
    ['an array with a getter that is not enumerable for an element',
      Object.defineProperty([0], 0, { enumerable: false, get: () => 1 })],
  ])('does not take %s for plain data, alone or inside plain data', (_name, value) => {
    expect(isPlainData(value)).toBe(false);
    expect(isPlainData({ a: [1, { b: value }] })).toBe(false);
    expect(isPlainData([[value]])).toBe(false);
    expect(isPlainData({ first: 1, held: value, last: 2 })).toBe(false);
  });

  it('judges the named members of an array, which a copy keeps', () => {
    expect(isPlainData(Object.assign(['a'], { kept: new Held() }))).toBe(false);
    expect(isPlainData(Object.assign(['a'], { kept: () => 1 }))).toBe(false);
  });

  it('passes over a member that is not enumerable, which a copy leaves out', () => {
    const hidden = Object.defineProperty({ a: 1 }, 'kept', { enumerable: false, value: new Held() });
    expect(isPlainData(hidden)).toBe(true);
    const guarded = Object.defineProperty({ a: 1 }, 'kept', { enumerable: false, get: () => 1 });
    expect(isPlainData(guarded)).toBe(true);
    const named = Object.defineProperty(['a'], 'kept', { enumerable: false, value: new Held() });
    expect(isPlainData(named)).toBe(true);
  });

  it('does not pass over an element that is not enumerable: a copy leaves it out, and JSON has it', () => {
    const hidden = Object.defineProperty(['a', 'b'], 1, { enumerable: false, value: 'b' });
    expect(isPlainData(hidden)).toBe(false);
    expect(JSON.stringify(hidden)).toBe('["a","b"]');
    expect(JSON.stringify(structuredClone(hidden))).toBe('["a",null]');
  });

  it('runs no accessor', () => {
    let reads = 0;
    const guarded = Object.defineProperty({ a: 1 }, 'b', {
      enumerable: true,
      get: () => {
        reads += 1;
        return 2;
      },
    });
    expect(isPlainData(guarded)).toBe(false);
    expect(isPlainData({ held: [guarded] })).toBe(false);
    expect(reads).toBe(0);
  });

  it('takes a transparent Proxy for the plain data it stands before: only a copy can tell', () => {
    const proxied = new Proxy({ a: [1] }, {});
    expect(isPlainData(proxied)).toBe(true);
    expect(() => structuredClone(proxied)).toThrow();
  });

  it('follows each object once, so a value that holds itself, or one met twice, is judged and ends', () => {
    const selfHeld: Record<string, unknown> = { id: 'x' };
    selfHeld.self = selfHeld;
    expect(isPlainData(selfHeld)).toBe(true);
    const shared = { a: 1 };
    expect(isPlainData([shared, shared, { again: shared }])).toBe(true);
    const tainted: Record<string, unknown> = { id: 'x', held: new Held() };
    tainted.self = tainted;
    expect(isPlainData(tainted)).toBe(false);
  });

  it('takes no call stack: plain data nested a million deep is judged', millionLevels, () => {
    expect(isPlainData(listedOnce(arrays, 1_000_000))).toBe(true);
    let deep: unknown = new Held();
    for (let level = 0; level < 1_000_000; level += 1) deep = { a: deep };
    expect(isPlainData(deep)).toBe(false);
  });

  it('is what a copy keeps: a value it takes for plain data and its copy canonicalize alike', () => {
    const value = JSON.parse('{"b":[1,{"c":null}],"a":"x","__proto__":{"d":2}}') as object;
    expect(isPlainData(value)).toBe(true);
    expect(JSON.stringify(structuredClone(value))).toBe(JSON.stringify(value));
    // What it refuses is what a copy would make something else of.
    expect(structuredClone(new Held())).not.toBeInstanceOf(Held);
    expect(Object.getOwnPropertySymbols(structuredClone({ [Symbol('tag')]: 1 }))).toHaveLength(0);
    expect(Object.getOwnPropertyDescriptor(
      structuredClone(Object.defineProperty({}, 'a', { enumerable: true, get: () => 1 })),
      'a',
    )).toHaveProperty('value', 1);
    // And a Date is kept as it is.
    expect(structuredClone({ at: new Date(5) }).at).toEqual(new Date(5));
  });
});
