/**
 * The one walk that settles whether a value is plain data and how deep it
 * nests: what it reads of a value, what it keeps of the top of one it reads
 * no further, and the copy it makes of one it reads in full.
 */
import { describe, expect, it } from 'vitest';
import { arrays } from '../../__tests__/utils/nesting.js';
import { copyPlainData, jsonTextNestsDeeperThan, nestsDeeperThan, readPlainData } from '../plain-data.js';

/** How often a walk read the members of the arrays and objects of a value. */
interface Reads {
  /** A member's property, read by its descriptor. */
  descriptors: number;
  /** An array's or object's keys, listed. */
  listings: number;
}

/**
 * `value` rebuilt with each array and object in it behind a Proxy that
 * counts in `reads` what is read of it. The Proxies pass every read through,
 * so the value reads as the plain data it was built from.
 */
function counted(value: unknown, reads: Reads): unknown {
  if (typeof value !== 'object' || value === null) return value;
  const target: object = Array.isArray(value)
    ? value.map((member) => counted(member, reads))
    : Object.fromEntries(Object.entries(value).map(([key, member]) => [key, counted(member, reads)]));
  return new Proxy(target, {
    getOwnPropertyDescriptor(held, key) {
      reads.descriptors += 1;
      return Reflect.getOwnPropertyDescriptor(held, key);
    },
    ownKeys(held) {
      reads.listings += 1;
      return Reflect.ownKeys(held);
    },
  });
}

/**
 * The reads one walk makes of a value of `members` members, `arrays` of its
 * arrays and objects being arrays and `objects` objects: each member's
 * descriptor once as the walk reads it, and once more as its keys are listed,
 * since listing a Proxy's keys reads each descriptor to see whether it is
 * enumerable, an array's `length` among them; and the keys of each array and
 * object listed once, an object's symbol keys once more.
 */
const oneWalk = (members: number, arrays: number, objects: number): Reads => ({
  descriptors: 2 * members + arrays,
  listings: arrays + 2 * objects,
});

describe('readPlainData', () => {
  // Three objects, three arrays, and eight members among them.
  const value = { a: [1, 2, { b: 'x' }], c: { d: [[]] } };

  it('reads each member of a value once, and lists the keys of each array and object once', () => {
    const reads: Reads = { descriptors: 0, listings: 0 };
    expect(readPlainData(counted(value, reads), 64)).toEqual({ plainData: true, nestsDeeper: false });
    expect(reads).toEqual(oneWalk(8, 3, 3));
  });

  it('reads an array of any length once, one descriptor for each element', () => {
    for (const length of [1, 1000, 100_000]) {
      const reads: Reads = { descriptors: 0, listings: 0 };
      const long = Array.from({ length }, (_, index) => index);
      expect(readPlainData(counted({ long }, reads), 64)).toEqual({ plainData: true, nestsDeeper: false });
      expect(reads).toEqual(oneWalk(length + 1, 1, 1));
    }
  });

  it('reads no more when it counts the depth too, however deep the value is', () => {
    for (const levels of [1, 64, 65, 1000]) {
      const reads: Reads = { descriptors: 0, listings: 0 };
      expect(readPlainData(counted(arrays(levels), reads), 64)).toEqual({
        plainData: true,
        nestsDeeper: levels > 64,
      });
      expect(reads).toEqual(oneWalk(levels, levels, 0));
    }
  });

  it('says a value is not plain data, however deep it is, before it says how deep', () => {
    expect(readPlainData({ deep: arrays(100), held: new Map() }, 64)).toEqual({ plainData: false });
    expect(readPlainData({ held: new Map(), deep: arrays(100) }, 64)).toEqual({ plainData: false });
    expect(readPlainData({ deep: arrays(100) }, 64)).toEqual({ plainData: true, nestsDeeper: true });
  });

  it('keeps the top levels of objects as it read them, and no array, Date or deeper object', () => {
    const credential = {
      id: 'urn:a',
      n: 7,
      at: new Date(0),
      list: [{ id: 'in an array' }],
      credentialSubject: { delegation: { id: 'del-1', deeper: { id: 'not kept' } }, other: 'x' },
    };
    expect(readPlainData(credential, 64, 3)).toEqual({
      plainData: true,
      nestsDeeper: false,
      top: { id: 'urn:a', n: 7, credentialSubject: { delegation: { id: 'del-1' }, other: 'x' } },
    });
    expect(readPlainData(credential, 64, 1)).toMatchObject({ top: { id: 'urn:a', n: 7 } });
    expect(readPlainData(credential, 64)).not.toHaveProperty('top');
  });

  it('keeps a member named __proto__ as a member, and an object met twice as one view', () => {
    const shared = { id: 'del-1' };
    const read = readPlainData({ ...JSON.parse('{"__proto__":"a member"}'), a: shared, b: { c: shared } }, 64, 3);
    expect(read.plainData && Object.getOwnPropertyDescriptor(read.top, '__proto__')?.value).toBe('a member');
    expect(read.plainData && read.top!.a).toBe(read.plainData && (read.top!.b as { c: unknown }).c);
  });
});

describe('the depth the walk counts', () => {
  it('is the depth of the JSON text, for a value held twice inside another held twice', () => {
    // `inner` is met first at level 2, `outer` at level 2 and again at level
    // 7, so `inner` is deepest at level 8: the levels counted of each must
    // hold up when it is met again.
    const inner = arrays(3);
    const outer = [inner];
    const value = [inner, outer, arrays(5, outer)];
    const text = JSON.stringify(value);
    for (let limit = 1; limit <= 12; limit += 1) {
      const deeper = jsonTextNestsDeeperThan(text, limit);
      expect(nestsDeeperThan(value, limit), `limit ${limit}`).toBe(deeper);
      expect(readPlainData(value, limit), `limit ${limit}`).toEqual({ plainData: true, nestsDeeper: deeper });
    }
  });

  it('passes over an element past a hole that is not enumerable, which neither a copy nor JSON has', () => {
    const holed: unknown[] = new Array(2);
    Object.defineProperty(holed, 1, { value: arrays(100), enumerable: false, writable: true, configurable: true });
    expect(readPlainData({ holed }, 64)).toEqual({ plainData: true, nestsDeeper: false });
    expect(nestsDeeperThan({ holed }, 64)).toBe(false);
    // Before any hole it is an element, which JSON has and a copy leaves out.
    const unlisted = Object.defineProperty([0], 0, { value: arrays(100), enumerable: false });
    expect(readPlainData({ unlisted }, 64)).toEqual({ plainData: false });
    expect(nestsDeeperThan({ unlisted }, 64)).toBe(true);
  });
});

describe('copyPlainData', () => {
  it('copies plain data within the limit, after one walk', () => {
    const value = { a: [1, { b: 'x' }] };
    const read = copyPlainData(value, 64);
    expect(read).toEqual({ copy: value });
    expect('copy' in read && read.copy).not.toBe(value);
  });

  it('refuses a Proxy, which only a copy can tell, as not plain data', () => {
    expect(copyPlainData(new Proxy({ a: 1 }, {}), 64)).toEqual({ refused: 'not plain data' });
  });

  it('refuses whatever throws as it is read as not plain data', () => {
    const revocable = Proxy.revocable({}, {});
    revocable.revoke();
    expect(copyPlainData({ a: revocable.proxy }, 64)).toEqual({ refused: 'not plain data' });
  });

  it('makes no copy of plain data nested too deep, and gives the top levels the walk read', () => {
    expect(copyPlainData({ id: 'urn:a', deep: arrays(64) }, 64, 1)).toEqual({
      refused: 'nests too deep',
      top: { id: 'urn:a' },
    });
    expect(copyPlainData({ id: 'urn:a', deep: arrays(64) }, 64)).toEqual({ refused: 'nests too deep' });
  });

  it('makes a copy that nestsDeeperThan counts as it is when it is asked, not as it was when it was made', () => {
    const read = copyPlainData({ a: arrays(10) }, 64);
    const copy = (read as { copy: { a: unknown } }).copy;
    expect(nestsDeeperThan(copy, 64)).toBe(false);
    expect(nestsDeeperThan(copy, 10)).toBe(true);
    // The copy is handed on, and whoever holds it can change it: an array
    // nested deeper in it since is counted, here and in a copy of it alike.
    copy.a = arrays(100);
    expect(nestsDeeperThan(copy, 64)).toBe(true);
    expect(nestsDeeperThan(structuredClone(copy), 64)).toBe(true);
    copy.a = arrays(63);
    expect(nestsDeeperThan(copy, 64)).toBe(false);
  });
});
