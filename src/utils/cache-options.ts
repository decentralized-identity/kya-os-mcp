/**
 * The options that bound a cache a verifier or resolver keeps: how long an entry is served, and how
 * many entries are kept. Each is checked once, where the verifier or resolver is built, as
 * `dependencyTimeoutMs` is (`./deadline.ts`), so a mistyped value fails there. Unchecked, a TTL
 * that is not a finite number, such as the `NaN` that `Number(process.env.UNSET)` gives, or
 * `Infinity`, never expires, so a "not revoked" verdict is served long after the list revokes the
 * credential, and a capacity of `NaN` never evicts. Nothing is converted, so `null` and a numeric
 * string are refused, not read as the default or as a number.
 */

import { describeOptionValue } from './describe-value.js';

/**
 * `value` as the cache TTL option `option`, in milliseconds: a finite number, 0 or more, where 0
 * keeps nothing. Throws a `TypeError` naming the option, as `[kya-os] <option> must be ...`, for
 * any other value, `undefined` included: call it only for an option that has no default, or that
 * is given.
 */
export function requiredCacheTtlOption(value: unknown, option: string): number {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value;
  throw new TypeError(`[kya-os] ${option} must be a finite number of milliseconds, 0 or more (got ${describeOptionValue(value)})`);
}

/** `value` as the cache TTL option `option`, as {@link requiredCacheTtlOption} reads it, or `undefined` when it is left out. */
export function cacheTtlOption(value: unknown, option: string): number | undefined {
  return value === undefined ? undefined : requiredCacheTtlOption(value, option);
}

/**
 * `value` as the cache capacity option `option`: a whole number greater than 0, or `undefined`
 * when it is left out. Throws a `TypeError` naming the option for any other value.
 */
export function cacheCapacityOption(value: unknown, option: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number' && Number.isInteger(value) && value > 0) return value;
  throw new TypeError(`[kya-os] ${option} must be a whole number greater than 0 (got ${describeOptionValue(value)})`);
}
