/**
 * KYA-OS Entity Card: hold one call to the caveats a delegation verdict carries (SPEC.md §6.10).
 *
 * A verdict that passes carries the chain's caveats at their tightest (`./caveats.ts`), but the
 * library never sees what a call spends, so the host holds the call to them. {@link caveatRefusal}
 * does that by the rule the chain itself is held to, so a host writes no decimal or currency check
 * of its own: every caveat applies to every call, each `MaxAmount` compared as an exact decimal.
 */

import { isRecord } from '../utils/guards.js';
import { describeOptionValue } from '../utils/describe-value.js';
import { clockSkewOption } from '../utils/validity-window.js';
import { caveatBreach, type EffectiveCaveats } from './caveats.js';
import type { Caveat } from './delegation.js';

/** What one call spends, and when, for {@link caveatRefusal}. */
export interface CaveatCall {
  /**
   * The amount the call spends, as a plain non-negative decimal string such as `"60.00"`, compared
   * exactly. A call that states none, or one in another form, is refused under any `MaxAmount`.
   */
  amount?: string;
  /** The currency of `amount`, such as `"USD"`, compared whole with the currency a `MaxAmount` names. */
  currency?: string;
  /** When the call is made, in epoch milliseconds, for each `ValidUntil`. Default: the time of the check. */
  at?: number;
  /**
   * The clock tolerance, in milliseconds, each `ValidUntil` is read with: a number from 0 to
   * 600,000. Default 120,000, as the guard reads it. Any other value throws a `TypeError`.
   */
  maxClockSkewMs?: number;
  /**
   * The types of caveats the library does not interpret that the host enforces itself, such as
   * `['RequiresHumanApproval']`. A caveat in `unknownCaveats` of any other type refuses the call. A
   * known type named here still holds the call to the members the library reads.
   */
  enforcedTypes?: readonly string[];
}

/**
 * Why the call `call` describes breaks a caveat `verdict` carries, as a short reason, or
 * `undefined` when it keeps to every one. Pass the grant of `requireDelegation` or
 * `verifyRequestDelegation`, or what `evaluateDelegationChain` finds, once it passes:
 *
 * ```ts
 * const refusal = caveatRefusal(authority, { amount: order.total, currency: order.currency });
 * if (refusal !== undefined) return { status: 403, error: { code: 'limit_exceeded', message: refusal } };
 * ```
 *
 * Every caveat applies to every call. A `MaxAmount` that names a currency refuses a call in any
 * other, or in none, and one that names none limits the amount whatever its currency, so two in
 * different currencies refuse every call. Each `ValidUntil` is read at `at`, with the clock
 * tolerance. It fails closed: a verdict without `caveats` and `unknownCaveats`, as a test double or
 * a cached grant may be, a malformed caveat, and a caveat the library does not interpret, unless
 * `enforcedTypes` names its type, each refuse the call. Throws a `TypeError` naming an option it
 * cannot use.
 */
export function caveatRefusal(verdict: EffectiveCaveats, call: CaveatCall = {}): string | undefined {
  const enforcedTypes = enforcedTypesOption(call.enforcedTypes);
  const held = { amount: call.amount, currency: call.currency, atMs: atOption(call.at), skewMs: clockSkewOption(call.maxClockSkewMs) };
  const caveats = isRecord(verdict) ? verdict.caveats : undefined;
  const unknownCaveats = isRecord(verdict) ? verdict.unknownCaveats : undefined;
  if (!Array.isArray(caveats) || !Array.isArray(unknownCaveats)) {
    return 'the verdict carries no caveats and unknownCaveats, so the call cannot be held to its limits';
  }
  for (const caveat of [...caveats, ...unknownCaveats]) {
    if (!isRecord(caveat) || typeof caveat.type !== 'string') return 'the delegation carries a malformed caveat: it is not a caveat object';
    // Read as the library reads a caveat it parsed: every member it knows is checked for its form.
    const breach = caveatBreach(caveat as Caveat, held, enforcedTypes);
    if (breach !== undefined) return breach;
  }
  return undefined;
}

/** `enforcedTypes` as a set, or a `TypeError` naming it when it is not an array of strings. */
function enforcedTypesOption(value: unknown): ReadonlySet<string> {
  if (value === undefined) return new Set();
  if (Array.isArray(value) && value.every((type) => typeof type === 'string')) return new Set(value as string[]);
  throw new TypeError(`[kya-os] caveatRefusal: enforcedTypes must be an array of caveat types, each a string (got ${describeOptionValue(value)})`);
}

/** `at` in epoch milliseconds, the time of the check when it is left out, or a `TypeError` naming it. */
function atOption(value: unknown): number {
  if (value === undefined) return Date.now();
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  throw new TypeError(`[kya-os] caveatRefusal: at must be a time in epoch milliseconds (got ${describeOptionValue(value)})`);
}
