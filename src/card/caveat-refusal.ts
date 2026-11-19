/**
 * KYA-OS Entity Card: hold one call to the caveats a delegation verdict carries (SPEC.md §6.10).
 *
 * A verdict that passes carries the chain's caveats at their tightest (`./caveats.ts`), but the
 * library never sees what a call spends, so the host holds the call to them. {@link caveatRefusal}
 * does that by the rule the chain itself is held to, so a host writes no decimal or currency check
 * of its own: every caveat applies to every call, each `MaxAmount` compared as an exact decimal.
 */

import { isRefusalCode, type RefusalCode } from '../refusal-codes.js';
import { describeOptionValue, describeValue } from '../utils/describe-value.js';
import { isRecord } from '../utils/guards.js';
import { coded } from '../utils/refusal.js';
import { clockSkewOption } from '../utils/validity-window.js';
import { caveatBreach, isKnownCaveatType, type EffectiveCaveats } from './caveats.js';
import type { Caveat } from './delegation.js';

/** What one call spends, and when, for {@link caveatRefusal}. */
export interface CaveatCall {
  /**
   * The amount the call spends, as a plain non-negative decimal string such as `"60.00"`, compared
   * exactly. Take it from your own records, such as your price list, never from an amount the caller
   * states. A call that states none, or one in another form, is refused under any `MaxAmount`.
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
   * The caveat types the library does not know that the host enforces itself, such as
   * `['RequiresHumanApproval']`. A caveat in `unknownCaveats` of any other type refuses the call.
   * A type the library knows, `MaxAmount` or `ValidUntil`, throws a `TypeError` here: naming it would
   * pass every member it does not interpret, so a caveat of such a type that states one, such as
   * `per`, is always refused.
   */
  enforcedTypes?: readonly string[];
}

/**
 * Why `caveatRefusal` refuses a call: a short `reason`, which quotes at most 64 characters of any
 * value, and the `code` of the rule the call breaks, with `transient` as that code fixes it.
 */
export interface CaveatRefusal {
  readonly code: RefusalCode;
  readonly reason: string;
  readonly transient: boolean;
}

/**
 * Why the call `call` describes is not one `verdict` permits, or `undefined` when it keeps to every
 * caveat the verdict carries. Pass the whole verdict: the grant of `requireDelegation` or
 * `verifyRequestDelegation`, or what `evaluateDelegationChain` finds.
 *
 * ```ts
 * const order = priceOf(request.params.arguments); // your own records: { amount: '60.00', currency: 'USD' }
 * if (order === undefined) return { status: 400, error: { code: 'invalid_order', message: 'unknown item or quantity' } };
 * const refusal = caveatRefusal(authority, order);
 * if (refusal !== undefined) return { status: 403, error: { code: refusal.code, message: refusal.reason } };
 * ```
 *
 * Every caveat applies to every call. A `MaxAmount` that names a currency refuses a call in any
 * other, or in none, and one that names none limits the amount whatever its currency, so two in
 * different currencies refuse every call; a call outside a limit is `insufficient_scope`. Each
 * `ValidUntil`, the chain's own expiry among them, is read at `at` with the clock tolerance, and
 * one that has passed is `delegation_expired`. It fails closed: a verdict that does not pass, with
 * the code it was refused with; a verdict without `caveats` and `unknownCaveats`, as a test double
 * or a cached grant may be (`configuration_error`); a malformed caveat (`delegation_malformed`); a
 * caveat of a known type with a member the library does not interpret, and one of an unknown type
 * that `enforcedTypes` does not name (`configuration_error`). Throws a `TypeError` naming an option
 * it cannot use.
 */
export function caveatRefusal(verdict: { ok: boolean } & EffectiveCaveats, call: CaveatCall = {}): CaveatRefusal | undefined {
  const enforcedTypes = enforcedTypesOption(call.enforcedTypes);
  const held = { amount: call.amount, currency: call.currency, atMs: atOption(call.at), skewMs: clockSkewOption(call.maxClockSkewMs) };
  const refused = (code: RefusalCode, reason: string): CaveatRefusal => ({ reason, ...coded(code) });
  if (!isRecord(verdict) || verdict.ok !== true) {
    return refused(refusalCodeOf(verdict), 'the verdict does not pass the delegation, so it permits no call');
  }
  const { caveats, unknownCaveats } = verdict;
  if (!Array.isArray(caveats) || !Array.isArray(unknownCaveats)) {
    return refused('configuration_error', 'the verdict carries no caveats and unknownCaveats, so the call cannot be held to its limits');
  }
  for (const caveat of [...caveats, ...unknownCaveats] as unknown[]) {
    if (!isRecord(caveat) || typeof caveat.type !== 'string') {
      return refused('delegation_malformed', 'the delegation carries a malformed caveat: it is not a caveat object');
    }
    // Read as the library reads a caveat it parsed: every member it knows is checked for its form.
    const breach = caveatBreach(caveat as Caveat, held, enforcedTypes);
    if (breach !== undefined) return refused(breach.code, breach.reason);
  }
  return undefined;
}

/** The code a verdict that does not pass was refused with, as a guard or a chain result states it; else `chain_invalid`. */
function refusalCodeOf(verdict: unknown): RefusalCode {
  if (!isRecord(verdict)) return 'chain_invalid';
  if (isRefusalCode(verdict.refusalCode)) return verdict.refusalCode;
  return isRefusalCode(verdict.code) ? verdict.code : 'chain_invalid';
}

/** `enforcedTypes` as a set, or a `TypeError` naming it when it is not an array of strings or names a known type. */
function enforcedTypesOption(value: unknown): ReadonlySet<string> {
  if (value === undefined) return new Set();
  if (!Array.isArray(value) || !value.every((type) => typeof type === 'string')) {
    throw new TypeError(`[kya-os] caveatRefusal: enforcedTypes must be an array of caveat types, each a string (got ${describeOptionValue(value)})`);
  }
  const known = (value as string[]).find(isKnownCaveatType);
  if (known !== undefined) {
    throw new TypeError(
      `[kya-os] caveatRefusal: enforcedTypes names ${describeValue(known)}, a caveat type the library enforces itself; ` +
        'one that states a member the library does not interpret is always refused',
    );
  }
  return new Set(value as string[]);
}

/** `at` in epoch milliseconds, the time of the check when it is left out, or a `TypeError` naming it. */
function atOption(value: unknown): number {
  if (value === undefined) return Date.now();
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  throw new TypeError(`[kya-os] caveatRefusal: at must be a time in epoch milliseconds (got ${describeOptionValue(value)})`);
}
