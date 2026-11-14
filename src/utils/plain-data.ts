/**
 * What is settled about a value before anything recursive reads it: how deep
 * it nests, and whether it is plain data.
 *
 * A parser, a copy and a canonicalizer each recurse, and each runs out of
 * stack at a depth of its own that differs from one runtime to the next. A
 * verdict that turned on that depth would be the runtime's and not the
 * value's. So the depth is counted here first, by loops over an explicit
 * stack that no input can exhaust, and what comes after reads only values
 * within the bound.
 *
 * Both are settled by one walk ({@link readPlainData}), which reads each
 * array and object of a value once. Nothing here calls an accessor: a member
 * is read through its descriptor.
 */

import { isPlainObjectOfThisRealm } from './guards.js';
import { checkJsonTokens } from './json-preflight.js';

/** Whether `value` is an array or any other object: something a value nests inside. */
const isContainer = (value: unknown): value is object => typeof value === 'object' && value !== null;

/**
 * Whether `value` is a `Date` as the runtime makes one, and not an object
 * given a `Date`'s prototype, which a copy would make a plain object of. It
 * is one value, with no members that a copy or a canonicalizer reads.
 */
function isDate(value: object): boolean {
  if (Object.getPrototypeOf(value) !== Date.prototype) return false;
  try {
    Date.prototype.getTime.call(value);
    return true;
  } catch {
    return false;
  }
}

/** Whether `key` names an element of an array of `length` elements. */
function isElementKey(key: string, length: number): boolean {
  const index = Number(key);
  return Number.isInteger(index) && index >= 0 && index < length && String(index) === key;
}

/** What one walk found of a value: see {@link readPlainData}. */
export type PlainDataReading =
  | { plainData: false }
  | {
      plainData: true;
      /** Whether its arrays and objects nest more than the limit deep. */
      nestsDeeper: boolean;
      /** What it holds near its top, as the walk read it (see {@link readPlainData}). */
      top?: Record<string, unknown>;
    };

/**
 * One reading of a value: each array and object in it read once, at the
 * shallowest level it is met at, with what it holds, and how deep they nest
 * then counted from what was read.
 */
class Walk {
  /** The arrays and objects each read holds, in the order it holds them. */
  readonly holds = new Map<object, object[]>();
  /** The level each array and object was first met at, read or still to be read. */
  private readonly levels = new Map<object, number>();
  /** Of each object read within the top levels, the members read of it. */
  private readonly views = new Map<object, Record<string, unknown>>();

  constructor(
    /** Whether each member is held to plain data (see {@link readPlainData}), or only followed. */
    private readonly plain: boolean,
    /** How many levels of objects to keep a view of. */
    private readonly topLevels: number,
  ) {}

  /**
   * Read `value` and everything in it, level by level. False as soon as
   * something read is not plain data, when `plain`; and, when not, as soon
   * as an array or object is met deeper than `stopPast`.
   */
  read(value: object, stopPast: number): boolean {
    const queue: object[] = [value];
    this.levels.set(value, 1);
    for (let next = 0; next < queue.length; next += 1) {
      const container = queue[next]!;
      const level = this.levels.get(container)!;
      if (level > stopPast) return false;
      const held: object[] = [];
      const view = level <= this.topLevels ? this.viewOf(container) : undefined;
      if (!this.members(container, held, view, level)) return false;
      this.holds.set(container, held);
      for (const member of held) {
        if (this.levels.has(member)) continue;
        this.levels.set(member, level + 1);
        queue.push(member);
      }
    }
    return true;
  }

  /** The view of `value`'s top levels, when one was kept. */
  top(value: object): Record<string, unknown> | undefined {
    return this.views.get(value);
  }

  private viewOf(object: object): Record<string, unknown> | undefined {
    if (Array.isArray(object) || isDate(object)) return undefined;
    let view = this.views.get(object);
    if (view === undefined) this.views.set(object, (view = {}));
    return view;
  }

  /**
   * Read the members of `container` that a copy or a canonicalizer reads on,
   * listing in `held` those that are arrays or objects. A `Date` has none.
   */
  private members(
    container: object,
    held: object[],
    view: Record<string, unknown> | undefined,
    level: number,
  ): boolean {
    if (isDate(container)) return true;
    if (Array.isArray(container)) return this.elements(container, held);
    if (this.plain) {
      if (!isPlainObjectOfThisRealm(container)) return false;
      if (Object.getOwnPropertySymbols(container).length > 0) return false;
    }
    for (const key of Object.keys(container)) {
      const property = Object.getOwnPropertyDescriptor(container, key);
      if (!property?.enumerable) continue;
      if (!this.take(property, held)) return false;
      if (view !== undefined) this.keep(view, key, property.value, level);
    }
    return true;
  }

  /**
   * An array's members: each element, up to its length, and its enumerable
   * named members, which a copy keeps. JSON has every element up to the
   * first hole, enumerable or not; past a hole a copy keeps the enumerable
   * ones, and neither has the others.
   */
  private elements(array: unknown[], held: object[]): boolean {
    let enumerable = 0;
    let holed = false;
    for (let index = 0; index < array.length; index += 1) {
      const property = Object.getOwnPropertyDescriptor(array, index);
      if (property === undefined) {
        holed = true;
        continue;
      }
      if (property.enumerable) enumerable += 1;
      else if (holed) continue;
      if (!this.take(property, held)) return false;
    }
    // Its enumerable keys are its enumerable elements, unless it has named
    // members as well, which are then read one by one.
    const keys = Object.keys(array);
    if (keys.length === enumerable) return true;
    for (const key of keys) {
      if (isElementKey(key, array.length)) continue;
      const property = Object.getOwnPropertyDescriptor(array, key);
      if (property?.enumerable && !this.take(property, held)) return false;
    }
    return true;
  }

  /**
   * Take a member's property: false when the walk holds members to plain
   * data and this one is not (an accessor, an element that is not
   * enumerable, a function or a symbol). Its value is listed in `held` when
   * it is an array or object. An accessor's value is not read, and so not
   * followed.
   */
  private take(property: PropertyDescriptor, held: object[]): boolean {
    if (this.plain && (!property.enumerable || !('value' in property))) return false;
    const value: unknown = property.value;
    if (this.plain && (typeof value === 'function' || typeof value === 'symbol')) return false;
    if (isContainer(value)) held.push(value);
    return true;
  }

  /** Keep in `view` a member read of an object at `level`, an object within the top levels as its own view. */
  private keep(view: Record<string, unknown>, key: string, value: unknown, level: number): void {
    const kept = isContainer(value) ? (level < this.topLevels ? this.viewOf(value) : undefined) : value;
    if (kept === undefined && isContainer(value)) return;
    Object.defineProperty(view, key, { value: kept, enumerable: true, writable: true, configurable: true });
  }

  /**
   * Whether what was read of `value` nests more than `limit` deep: the
   * levels of each array and object counted once, from the deepest of what
   * it holds, with no call stack. A value that holds itself nests without
   * end.
   *
   * The walk that measures a DID document
   * (`delegation/did-document-walk.ts`) counts depth as well, and cannot
   * count it here. It recurses, which is safe there because it refuses at
   * the first container past the limit, and it does so while it charges
   * bytes, counts members and refuses what JSON cannot hold: a `Date`, a
   * hole in an array, a bigint and a value that holds itself are each
   * refused by name, where a credential holding one is counted here and
   * left for its copy or its canonicalizer to judge. It reads array
   * elements as values, so an accessor on one runs, and nothing here runs
   * an accessor. It follows a container once for each path to it, where one
   * shared by many is counted once here. And it belongs to the delegation
   * layer, which nothing in `utils` imports.
   */
  nestsDeeperThan(value: object, limit: number): boolean {
    if (limit < 1) return true;
    // How many levels each array or object counted nests, itself included.
    const counted = new Map<object, number>();
    const path = new Set<object>([value]);
    const open: Array<{ container: object; level: number; next: number; levels: number }> = [
      { container: value, level: 1, next: 0, levels: 1 },
    ];
    while (open.length > 0) {
      const top = open[open.length - 1]!;
      const held = this.holds.get(top.container)!;
      if (top.next < held.length) {
        const member = held[top.next]!;
        top.next += 1;
        if (path.has(member)) return true;
        const known = counted.get(member);
        if (known !== undefined) {
          if (top.level + known > limit) return true;
          top.levels = Math.max(top.levels, known + 1);
        } else {
          if (top.level + 1 > limit) return true;
          path.add(member);
          open.push({ container: member, level: top.level + 1, next: 0, levels: 1 });
        }
        continue;
      }
      open.pop();
      path.delete(top.container);
      counted.set(top.container, top.levels);
      const below = open[open.length - 1];
      if (below !== undefined) below.levels = Math.max(below.levels, top.levels + 1);
    }
    return false;
  }
}

/**
 * Whether `value` is plain data, and how deep it nests, from one walk that
 * reads each array and object in it once.
 *
 * Plain data is what a copy of keeps as it is, so that what a canonicalizer
 * reads of the copy is what it would have read of the value. Every object in
 * it is an array, or has the prototype `Object.prototype` or none, and holds
 * no symbol-keyed member; every element of an array is enumerable, since a
 * copy leaves out one that is not and a canonicalizer reads it; every
 * enumerable member of an array or object is a data property, not an
 * accessor; and nothing in it is a function or a symbol. So a class
 * instance, a `Map` and an object with a getter are not plain data: a copy
 * would make plain data of each, by leaving out its class or its entries, or
 * by keeping what the getter answered. What a copy keeps as it is passes,
 * for whatever reads the copy to refuse or pass over: `undefined`, a bigint,
 * an array with a hole, and a `Date`. A Proxy is read as what it answers:
 * only a copy can tell one.
 *
 * Of plain data it says whether its arrays and objects nest more than
 * `limit` deep, counted as {@link nestsDeeperThan} counts them, and gives
 * `top`: its objects down to `topLevels` levels, each as a new object of the
 * members the walk read of it, an object within those levels as its own such
 * object, and no array, `Date` or deeper object. That is what a value read
 * no further shows near its top, from this one reading of it.
 *
 * A value that is not plain data is read no further than it takes to tell.
 */
export function readPlainData(value: unknown, limit: number, topLevels = 0): PlainDataReading {
  if (!isContainer(value)) {
    return typeof value === 'function' || typeof value === 'symbol'
      ? { plainData: false }
      : { plainData: true, nestsDeeper: false };
  }
  const walk = new Walk(true, topLevels);
  if (!walk.read(value, Number.POSITIVE_INFINITY)) return { plainData: false };
  const top = walk.top(value);
  return { plainData: true, nestsDeeper: walk.nestsDeeperThan(value, limit), ...(top === undefined ? {} : { top }) };
}

/** Why {@link copyPlainData} made no copy of a value. */
export type NotCopied = { refused: 'not plain data' } | { refused: 'nests too deep'; top?: Record<string, unknown> };

/**
 * A copy of `value` when it is plain data that nests no more than `limit`
 * deep ({@link readPlainData}): one walk, and then the copy, which refuses
 * a Proxy. Anything that throws on the way, a Proxy's trap say, is no plain
 * data. Of plain data nested deeper there is no copy, since a copy recurses,
 * and `top` is what the walk read of its top `topLevels` levels.
 *
 * The copy is within the limit as it is made, and no longer than it is left
 * alone: it is not frozen, and whoever it is handed to can nest more in it.
 * So nothing is remembered of it here, and {@link nestsDeeperThan} counts it
 * like any other value, each time it is asked.
 */
export function copyPlainData(value: unknown, limit: number, topLevels = 0): { copy: unknown } | NotCopied {
  try {
    const reading = readPlainData(value, limit, topLevels);
    if (!reading.plainData) return { refused: 'not plain data' };
    if (reading.nestsDeeper) {
      return { refused: 'nests too deep', ...(reading.top === undefined ? {} : { top: reading.top }) };
    }
    return { copy: structuredClone(value) };
  } catch {
    return { refused: 'not plain data' };
  }
}

/**
 * Whether the arrays and objects of `value` nest more than `limit` deep.
 *
 * `value` itself is level 1 when it is an array or an object, and an array or
 * object that is a member of another is one level deeper than it: the
 * nesting of the JSON text a value read from JSON was written as. A value
 * that holds itself nests without end, so it is deeper than any limit.
 *
 * A member is followed when a canonicalizer or a copy would read it on: an
 * array's elements, enumerable or not up to its first hole and enumerable
 * past it, and the enumerable members of either. An accessor is not called,
 * a member of an object that is not enumerable is neither JSON nor copied,
 * and nothing in a `Date` is read. Each array and object is read once.
 *
 * The answer is of `value` as it is at this call, counted anew at each one.
 * No earlier count of an object is taken for it, a copy
 * {@link copyPlainData} made included: an object can be changed between
 * two calls, and a count taken before the change would pass what a
 * recursive reader then runs out of stack on.
 */
export function nestsDeeperThan(value: unknown, limit: number): boolean {
  if (!isContainer(value)) return false;
  const walk = new Walk(false, 0);
  return !walk.read(value, limit) || walk.nestsDeeperThan(value, limit);
}

/** Limits that leave a JSON text's member names uncounted, so only its depth is held. */
const DEPTH_ONLY = { maxMembers: Infinity, maxMemberLength: Infinity } as const;

/**
 * Whether the arrays and objects of a JSON text nest more than `limit` deep,
 * counted as {@link nestsDeeperThan} counts the value the text would parse
 * to: the brackets `[` and `{` open outside a string at any one place, as
 * `checkJsonTokens` (`./json-preflight.ts`) counts them before a DID document
 * or a status list is parsed.
 *
 * One pass over the text, before any parser reads it. For a text that is not
 * JSON the count says nothing of what it is: a parser refuses such a text,
 * and nests no deeper while reading it than the brackets counted here.
 */
export function jsonTextNestsDeeperThan(text: string, limit: number): boolean {
  try {
    checkJsonTokens(text, { maxDepth: limit, ...DEPTH_ONLY });
    return false;
  } catch {
    return true;
  }
}
