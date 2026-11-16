/**
 * The context of a status check, carried with the status entry it is about.
 *
 * The library names the credential a status entry belongs to in a second argument to every
 * status-list resolver and checker it calls (`StatusCheckContext`). TypeScript lets a function that
 * takes fewer parameters stand in for one that takes more, so a resolver written before that
 * argument existed, wrapping a library checker and calling it with the entry alone, still compiles,
 * and the checker it wraps is then told nothing about the credential and fails closed. So each such
 * call also hands over a fresh shallow copy of the entry that carries the context under a
 * non-enumerable key, {@link STATUS_CHECK_CONTEXT}, and the library's checkers read it there when no
 * second argument is given. The copy has the entry's own enumerable members and no others, so it
 * serializes, enumerates and compares as the entry does, and a copy made of it by spreading or by
 * JSON does not carry the context on. The entry itself is never changed, so one entry checked under
 * two contexts at once is never read under the wrong one.
 */

import type { StatusCheckContext } from './statuslist-keeper.js';
import { isRecord } from './guards.js';

/**
 * The key under which a status entry carries the context of its check. It is registered with
 * `Symbol.for`, so two copies of this package loaded into one process read each other's entries.
 */
export const STATUS_CHECK_CONTEXT: unique symbol = Symbol.for('@kya-os/mcp/status-check-context');

/**
 * A fresh shallow copy of `entry` that carries `context` under {@link STATUS_CHECK_CONTEXT}, for the
 * library to pass to a status-list resolver or checker beside `context` itself. With no context, or
 * an entry that is not an object, or one whose members cannot be copied, the entry is passed as it
 * is: the second argument still names the context, and a checker given neither refuses the entry.
 */
export function carryingContext<T>(entry: T, context: StatusCheckContext | undefined): T {
  if (context === undefined || !isRecord(entry)) return entry;
  let copy: Record<string | symbol, unknown>;
  try {
    copy = { ...entry };
  } catch {
    return entry;
  }
  Object.defineProperty(copy, STATUS_CHECK_CONTEXT, { value: context, enumerable: false, writable: false, configurable: false });
  return copy as T;
}

/**
 * The context `entry` carries under {@link STATUS_CHECK_CONTEXT}, read from its own data property
 * without calling any accessor, or `undefined` when it carries none.
 */
export function carriedContext(entry: unknown): StatusCheckContext | undefined {
  if (typeof entry !== 'object' || entry === null) return undefined;
  try {
    const carried: unknown = Object.getOwnPropertyDescriptor(entry, STATUS_CHECK_CONTEXT)?.value;
    return isRecord(carried) ? (carried as unknown as StatusCheckContext) : undefined;
  } catch {
    return undefined;
  }
}
