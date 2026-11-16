import { describe, it, expect, vi } from 'vitest';
import { canonicalize } from 'json-canonicalize';
import {
  CanonicalJsonError,
  assertCanonicalJsonValue,
  canonicalizeJson,
  canonicalizeJsonBytes,
  enumerableMembers,
  jsonMemberValue,
  jsonMembers,
} from '../canonical-json.js';

/** Deterministic PRNG (mulberry32) so a failing case reproduces. */
function prng(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Code points that stress escaping and UTF-16 ordering, plus astral ones (surrogate pairs). */
const CODE_POINTS = [
  0x00, 0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x1f, 0x20, 0x22, 0x2f, 0x41, 0x5c, 0x61, 0x7f, 0x80,
  0xe9, 0x2028, 0x2029, 0x20ac, 0xd7ff, 0xe000, 0xfb33, 0xffee, 0xfffd, 0x10000, 0x1f600,
  0x1d11e, 0x10ffff,
];

function randomString(rand: () => number): string {
  let out = '';
  const length = Math.floor(rand() * 8);
  for (let i = 0; i < length; i += 1) {
    out += String.fromCodePoint(CODE_POINTS[Math.floor(rand() * CODE_POINTS.length)]!);
  }
  return out;
}

function randomNumber(rand: () => number): number {
  switch (Math.floor(rand() * 6)) {
    case 0:
      return Math.floor((rand() - 0.5) * 2 * Number.MAX_SAFE_INTEGER);
    case 1:
      return Math.floor((rand() - 0.5) * 2000);
    case 2:
      return -0;
    case 3: // fractions across magnitudes, from 1e-300 to ~1e15
      return (rand() - 0.5) * 10 ** Math.floor(rand() * 315 - 300);
    case 4:
      return Number.MIN_VALUE * Math.ceil(rand() * 10);
    default:
      return rand();
  }
}

/** A random plain JSON value that both serializers must accept (no `toJSON` keys). */
function randomJson(rand: () => number, depth: number): unknown {
  const kind = depth <= 0 ? Math.floor(rand() * 4) : Math.floor(rand() * 6);
  switch (kind) {
    case 0:
      return null;
    case 1:
      return rand() < 0.5;
    case 2:
      return randomNumber(rand);
    case 3:
      return randomString(rand);
    case 4:
      return Array.from({ length: Math.floor(rand() * 5) }, () => randomJson(rand, depth - 1));
    default: {
      const object: Record<string, unknown> = {};
      const size = Math.floor(rand() * 6);
      for (let i = 0; i < size; i += 1) {
        object[randomString(rand)] = randomJson(rand, depth - 1);
      }
      return object;
    }
  }
}

describe('canonicalizeJson', () => {
  it('matches json-canonicalize on randomized plain JSON (RFC 8785 equivalence)', () => {
    const rand = prng(8785);
    for (let i = 0; i < 2_000; i += 1) {
      const value = randomJson(rand, 4);
      expect(canonicalizeJson(value)).toBe(canonicalize(value));
    }
  });

  it('matches the RFC 8785 §3.2.3 sorting example (UTF-16 code unit order)', () => {
    const value = {
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      'דּ': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '😀': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      'ö': 'Latin Small Letter O With Diaeresis',
    };
    const order = ['\r', '1', '\u0080', 'ö', '€', '😀', 'דּ'] as const;
    const members = order.map((key) => `${JSON.stringify(key)}:${JSON.stringify(value[key])}`);
    expect(canonicalizeJson(value)).toBe(`{${members.join(',')}}`);
  });

  it('writes numbers per RFC 8785 §3.2.2.3', () => {
    expect(canonicalizeJson([-0, 1e-7, 1e21 / 1e6, 0.1 + 0.2, 333333333.33333329, 5e-324])).toBe(
      '[0,1e-7,1000000000000000,0.30000000000000004,333333333.3333333,5e-324]',
    );
  });

  it('encodes the canonical string as UTF-8 bytes', () => {
    expect(new TextDecoder().decode(canonicalizeJsonBytes({ b: '€', a: 1 }))).toBe('{"a":1,"b":"€"}');
  });

  describe('a member named toJSON is data, never a serialization hook', () => {
    it('sorts members independent of insertion order', () => {
      const jcs = '{"a":2,"b":1,"toJSON":"x"}';
      expect(canonicalizeJson({ toJSON: 'x', b: 1, a: 2 })).toBe(jcs);
      expect(canonicalizeJson({ a: 2, b: 1, toJSON: 'x' })).toBe(jcs);
    });

    it('sorts members nested below a toJSON-bearing object', () => {
      expect(canonicalizeJson({ b: 1, toJSON: 'x', a: { d: 1, c: 2 } })).toBe(
        '{"a":{"c":2,"d":1},"b":1,"toJSON":"x"}',
      );
      expect(
        canonicalizeJson({ method: 'tools/call', params: { arguments: { toJSON: 1, z: { b: 1, a: 1 } } } }),
      ).toBe('{"method":"tools/call","params":{"arguments":{"toJSON":1,"z":{"a":1,"b":1}}}}');
    });

    it('ignores a hidden (non-enumerable) toJSON instead of honouring it', () => {
      const value = { amount: 1 };
      Object.defineProperty(value, 'toJSON', { value: () => ({ evil: 1 }), enumerable: false });
      expect(canonicalizeJson(value)).toBe('{"amount":1}');
    });

    it("ignores an array's own toJSON instead of honouring it", () => {
      const array = Object.assign(['a', 'b'], { toJSON: () => 'swap' });
      expect(canonicalizeJson(array)).toBe('["a","b"]');
    });
  });

  describe('properties JSON does not carry are ignored, as JSON.stringify ignores them', () => {
    it('serializes a RegExp match array as its elements', () => {
      const match = 'abc'.match(/b/)!; // carries own `index`, `input`, `groups`
      expect(canonicalizeJson(match)).toBe('["b"]');
      expect(canonicalizeJson({ m: match })).toBe(canonicalize({ m: ['b'] }));
    });

    it.each([
      ['a non-enumerable data property', () => Object.defineProperty({ a: 1 }, 'x', { value: 2 }), '{"a":1}'],
      ['a non-index array property', () => Object.assign([1], { extra: 2 }), '[1]'],
      ['a symbol on an array', () => Object.assign([1], { [Symbol('s')]: 2 }), '[1]'],
      ['a 2^32 - 1 key on an array (not an index)', () => Object.assign([1], { 4294967295: 2 }), '[1]'],
      ['a non-enumerable element (still an element)', () => Object.defineProperty([0], 0, { value: 1, enumerable: false }), '[1]'],
    ])('%s', (_label, build, expected) => {
      expect(canonicalizeJson(build())).toBe(expected);
      expect(() => assertCanonicalJsonValue(build())).not.toThrow();
    });
  });

  describe('fails closed on values without one unambiguous JSON form', () => {
    it.each([
      ['a getter element', () => Object.defineProperty([0], 0, { get: () => 1, enumerable: true }), /accessor property at \$\[0\]/],
      ['a getter member', () => Object.defineProperty({}, 'x', { get: () => 1, enumerable: true }), /accessor property at \$\.x/],
      ['a sparse array', () => [1, , 3], /sparse array element at \$\[1\]/],
      ['a sparse array whose element before the hole has no JSON form', () => [undefined, , 3], /sparse array element at \$\[1\]/],
      ['a getter element that is not enumerable', () => Object.defineProperty([], 0, { get: () => 1 }), /accessor property at \$\[0\]/],
      ['a symbol-keyed member', () => ({ [Symbol('s')]: 1 }), /symbol-keyed property at \$/],
      ['a symbol-keyed member that is not enumerable', () => Object.defineProperty({}, Symbol('s'), { value: 1 }), /symbol-keyed property at \$/],
      [
        'a key with a lone surrogate on a member that is not enumerable',
        () => Object.defineProperty({ a: 1 }, '\udc00', { value: 1 }),
        /object key with lone surrogate at \$/,
      ],
      ['a non-plain object', () => ({ at: new Date(0) }), /non-plain object at \$\.at/],
      ['an undefined deep inside', () => ({ a: [{ b: undefined }] }), /undefined at \$\.a\[0\]\.b/],
    ])('rejects %s, naming where', (_label, build, message) => {
      expect(() => canonicalizeJson(build())).toThrow(message);
      expect(() => assertCanonicalJsonValue(build())).toThrow(TypeError);
    });

    it('rejects with an error of its own class, which is a TypeError and is named one', () => {
      for (const refuse of [canonicalizeJson, canonicalizeJsonBytes, assertCanonicalJsonValue]) {
        let thrown: unknown;
        try {
          refuse({ a: undefined });
        } catch (error) {
          thrown = error;
        }
        // The class is what tells a value with no canonical form from any
        // other failure on the way, a call stack that ran out say.
        expect(thrown).toBeInstanceOf(CanonicalJsonError);
        expect(thrown).toBeInstanceOf(TypeError);
        expect((thrown as Error).name).toBe('TypeError');
        expect((thrown as Error).message).toBe('Cannot canonicalize undefined at $.a');
      }
      expect(new TypeError('another failure')).not.toBeInstanceOf(CanonicalJsonError);
      expect(new RangeError('Maximum call stack size exceeded')).not.toBeInstanceOf(CanonicalJsonError);
    });

    it('names the path under a caller-supplied root', () => {
      expect(() => assertCanonicalJsonValue({ a: Number.NaN }, '$.content')).toThrow(
        /non-finite number at \$\.content\.a: NaN/,
      );
    });

    it('refuses an element that is gone when it is written, though it was there when the holes were checked, which only a Proxy can show', () => {
      const asked: string[] = [];
      const vanishing = new Proxy([1, 2], {
        getOwnPropertyDescriptor(target, key) {
          asked.push(String(key));
          const readsOfOne = asked.filter((read) => read === '1').length;
          return key === '1' && readsOfOne > 1 ? undefined : Reflect.getOwnPropertyDescriptor(target, key);
        },
      });
      let thrown: unknown;
      try {
        canonicalizeJson(vanishing);
      } catch (error) {
        thrown = error;
      }
      // Each index is read once to check for holes, then once to be written.
      expect(asked).toEqual(['0', '1', '0', '1']);
      expect(thrown).toBeInstanceOf(CanonicalJsonError);
      expect((thrown as Error).message).toBe('Cannot canonicalize sparse array element at $[1]');
    });

    it('still accepts an array that shares structure without a cycle', () => {
      const shared = { a: 1 };
      expect(canonicalizeJson([shared, shared])).toBe('[{"a":1},{"a":1}]');
    });
  });

  describe('reads the members jsonMembers lists, and no others', () => {
    it('writes each element, enumerable or not, and each enumerable member of an object', () => {
      const elements = Object.defineProperty(['a', 'b', 'c'], 1, { value: 'B', enumerable: false });
      const members = Object.defineProperty({ z: 1, a: 2 }, 'hidden', { value: 3, enumerable: false });
      expect(jsonMembers(elements).map(([key]) => key)).toEqual(['0', '1', '2']);
      expect(canonicalizeJson(elements)).toBe('["a","B","c"]');
      expect(jsonMembers(members).map(([key]) => key)).toEqual(['z', 'a']);
      expect(canonicalizeJson(members)).toBe('{"a":2,"z":1}');
    });
  });

  describe('cost is linear in the input, however deeply it nests', () => {
    const DEPTH = 1_600;
    const leaf = 'x'.repeat(1 << 20); // 1 MiB

    function nested(depth: number): unknown {
      let value: unknown = leaf;
      for (let i = 0; i < depth; i += 1) value = i % 2 === 0 ? { a: value } : [value];
      return value;
    }

    it('never joins more text than it returns', () => {
      // A serializer that joins each subtree into a string and then joins those
      // again copies the deep leaf once per level (size x depth). Count every
      // character Array.prototype.join produces during one call, 400 levels
      // deep: enough to show the copying, shallow enough for any stack.
      const join = vi.spyOn(Array.prototype, 'join');
      let output: string;
      let joined: number;
      try {
        output = canonicalizeJson(nested(400));
        // Read before mockRestore(), which clears the recorded results.
        joined = join.mock.results.reduce(
          (total, { value }) => total + (typeof value === 'string' ? value.length : 0),
          0,
        );
      } finally {
        join.mockRestore();
      }
      expect(output.length).toBeGreaterThan(leaf.length);
      expect(joined).toBeLessThanOrEqual(output.length);
    });

    it('serializes a 1 MiB leaf 1600 levels deep in time comparable to a flat one', () => {
      const deep = nested(DEPTH);
      const flat = { a: leaf };
      canonicalizeJson(flat); // warm up
      const t0 = performance.now();
      canonicalizeJson(flat);
      const flatMs = performance.now() - t0;
      const t1 = performance.now();
      const out = canonicalizeJson(deep);
      const deepMs = performance.now() - t1;
      expect(out.length).toBeGreaterThan(leaf.length + 2 * DEPTH);
      // Generous: re-joining per level took hundreds of ms here.
      expect(deepMs).toBeLessThan(10 * flatMs + 150);
    });
  });
});

describe('jsonMembers', () => {
  it("lists an array's elements in order, enumerable or not, and nothing else of it", () => {
    const array = Object.assign(['a', 'b'], { named: 'n' });
    Object.defineProperty(array, 1, { value: 'B', enumerable: false });
    Object.defineProperty(array, 'hidden', { value: 'h', enumerable: false });
    const members = jsonMembers(array);
    expect(members.map(([key]) => key)).toEqual(['0', '1']);
    expect(members.map(([, property]) => property.value)).toEqual(['a', 'B']);
    expect(members[1]![1].enumerable).toBe(false);
  });

  it("ends an array's elements at its first hole: nothing after one is read", () => {
    const holed: unknown[] = ['a'];
    holed[2] = 'c';
    expect(jsonMembers(holed).map(([key]) => key)).toEqual(['0']);
    expect(jsonMembers(new Array(5)).map(([key]) => key)).toEqual([]);
    // A length nothing fills is not walked: the first hole ends it.
    const vast: unknown[] = ['a'];
    vast.length = 2 ** 32 - 1;
    expect(jsonMembers(vast).map(([key]) => key)).toEqual(['0']);
  });

  it("lists an object's enumerable string-keyed members, in the order it holds them", () => {
    const object = { z: 1, a: 2, [Symbol('s')]: 3 };
    Object.defineProperty(object, 'hidden', { value: 4, enumerable: false });
    expect(jsonMembers(object).map(([key]) => key)).toEqual(['z', 'a']);
  });

  it('lists an accessor as its property, without calling it', () => {
    let reads = 0;
    const object = Object.defineProperty({}, 'x', { enumerable: true, get: () => ++reads });
    const array = Object.defineProperty([0], 0, { get: () => ++reads });
    expect('get' in jsonMembers(object)[0]![1]).toBe(true);
    expect('get' in jsonMembers(array)[0]![1]).toBe(true);
    expect(reads).toBe(0);
  });

  it('lists no member for a key that has no property, which only a Proxy can show', () => {
    const phantom = new Proxy({}, { ownKeys: () => ['ghost'] });
    expect(Reflect.ownKeys(phantom)).toEqual(['ghost']);
    expect(jsonMembers(phantom)).toEqual([]);
    expect(canonicalizeJson(phantom)).toBe('{}');
  });
});

describe('enumerableMembers', () => {
  it('lists what a copy of an array keeps: its enumerable elements, past a hole too, and named members', () => {
    const array: unknown[] = ['a'];
    array[2] = 'c';
    Object.assign(array, { named: 'n' });
    Object.defineProperty(array, 0, { value: 'A', enumerable: false });
    expect(enumerableMembers(array).map(([key]) => key)).toEqual(['2', 'named']);
    expect(Object.keys(structuredClone(array))).toEqual(['2', 'named']);
  });

  it('lists what jsonMembers lists of an object', () => {
    const object = Object.defineProperty({ b: 1, a: [2] }, 'c', { value: 3, enumerable: false });
    expect(enumerableMembers(object)).toEqual(jsonMembers(object));
  });

  it('keeps a member only when the property it reads is enumerable, whatever a Proxy answered when its keys were listed', () => {
    let asked = 0;
    const changing = new Proxy({ a: 1, b: 2 }, {
      getOwnPropertyDescriptor(target, key) {
        const property = Reflect.getOwnPropertyDescriptor(target, key);
        // `b` is enumerable when first asked about, and not after.
        return key === 'b' && (asked += 1) > 1 ? { ...property, enumerable: false } : property;
      },
    });
    expect(enumerableMembers(changing).map(([key]) => key)).toEqual(['a']);
    expect(asked).toBe(2);
  });
});

describe('jsonMemberValue', () => {
  it('reads an own enumerable data member', () => {
    expect(jsonMemberValue({ id: 'urn:uuid:1' }, 'id')).toBe('urn:uuid:1');
    expect(jsonMemberValue(JSON.parse('{"__proto__":{"a":1}}') as object, '__proto__')).toEqual({ a: 1 });
  });

  it('reads nothing that the JSON form of the object does not have', () => {
    let reads = 0;
    const object = Object.create({ inherited: 'x' }) as Record<string, unknown>;
    Object.defineProperty(object, 'hidden', { value: 'x', enumerable: false });
    Object.defineProperty(object, 'getter', { enumerable: true, get: () => ++reads });
    for (const key of ['inherited', 'hidden', 'getter', 'absent']) {
      expect(jsonMemberValue(object, key)).toBeUndefined();
    }
    expect(reads).toBe(0);
  });
});
