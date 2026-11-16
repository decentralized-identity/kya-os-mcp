/**
 * Values nested a given number of levels deep, for tests of how deep a value
 * may nest (SPEC.md §7.8). Each is built in a loop, so any depth can be, far
 * deeper than a call stack reaches.
 */

/** `levels` arrays, one inside the other, around `leaf`. */
export function arrays(levels: number, leaf: unknown = 'leaf'): unknown {
  let value = leaf;
  for (let level = 0; level < levels; level += 1) value = [value];
  return value;
}

/** `levels` objects, one inside the other, around `leaf`. */
export function objects(levels: number, leaf: unknown = 'leaf'): unknown {
  let value = leaf;
  for (let level = 0; level < levels; level += 1) value = { a: value };
  return value;
}

/** Arrays and objects in turn, `levels` of them, around `leaf`. */
export function mixed(levels: number, leaf: unknown = 'leaf'): unknown {
  let value = leaf;
  for (let level = 0; level < levels; level += 1) value = level % 2 === 0 ? { a: value } : [value];
  return value;
}
