/**
 * StatusList Lifetime
 *
 * How long each version of a status list a `StatusList2021Manager` signs may be read. A list that
 * states no end is read until its issuer replaces it, so a copy signed before a revocation, which a
 * cache, a mirror or a party that wants to stay unrevoked keeps, reads as current for as long as its
 * key verifies (SPEC.md §6.6). A list that states its end is unresolvable past it, so such a copy
 * stops being read within the lifetime of the version it is.
 */

import type { StatusList2021Credential } from '../types/protocol.js';
import { describeOptionValue } from '../utils/describe-value.js';

/**
 * The `listLifetimeMs` option as a number of milliseconds, or `undefined` when it is not set.
 * Throws a `TypeError` naming the option for any value that is not a whole number of milliseconds
 * greater than 0, so a mistyped option fails where the manager is built.
 */
export function listLifetimeOf(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new TypeError(
      `[kya-os] listLifetimeMs must be a whole number of milliseconds greater than 0 (got ${describeOptionValue(value)})`,
    );
  }
  return value as number;
}

/**
 * `list` with the end `lifetimeMs` after `nowMs`, as the `expirationDate` a `StatusList2021Credential`
 * states it in (SPEC.md §6.6), every other member kept. `issuanceDate` stays the date the list was
 * first issued, so a verifier whose clock runs behind never reads a version as not yet valid.
 */
export function withEnd<T extends StatusList2021Credential>(list: T, lifetimeMs: number, nowMs: number): T {
  return { ...list, expirationDate: new Date(nowMs + lifetimeMs).toISOString() };
}
