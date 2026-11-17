/**
 * The window rule: where an instant stands against the validity window a credential states, its
 * start and its end, each read as `./rfc3339.ts` reads a date. One rule reads the window of a status
 * list (`./statuslist-validity.ts`) and of each Entity Card delegation hop (`../card/hop-window.ts`).
 *
 * A verifier's clock and an issuer's are never quite the same. A list or a hop stamped a moment ago
 * by an issuer whose clock runs a second ahead states a start a second after the verifier's now, and
 * would be refused until the verifier's clock catches up. So each bound is held with a tolerance,
 * `maxClockSkewMs`: a window is read from its start less the tolerance to its end plus the
 * tolerance. It defaults to the proof verifier's tolerance for a request's timestamp, 120 seconds
 * (SPEC.md §11.3), and is at most the longest that verifier takes, 600 seconds (SPEC.md §10.1). It is
 * checked once, where the reader is built, as `dependencyTimeoutMs` is (`./deadline.ts`): unchecked,
 * a tolerance of `NaN`, such as `Number(process.env.UNSET)` gives, would hold neither bound at all.
 */

import { describeOptionValue } from './describe-value.js';

/** The tolerance each bound is held with when none is configured: the proof verifier's default skew, in milliseconds. */
export const DEFAULT_MAX_CLOCK_SKEW_MS = 120_000;

/** The longest tolerance a reader takes: the proof verifier's longest skew, in milliseconds. */
export const LONGEST_CLOCK_SKEW_MS = 600_000;

/** How an instant falls outside a window: past its end, or before its start. */
export type WindowBreach = 'expired' | 'not_yet_valid';

/**
 * Where `nowMs` stands against the window from `fromMs` to `untilMs`, each in epoch milliseconds and
 * `undefined` for a bound the window does not state, with each bound held with `skewMs`: `expired`
 * past `untilMs + skewMs`, `not_yet_valid` before `fromMs - skewMs`, else `undefined`. The bounds are
 * inclusive. A window both expired and not yet valid is `expired`.
 */
export function windowBreach(fromMs: number | undefined, untilMs: number | undefined, nowMs: number, skewMs: number): WindowBreach | undefined {
  if (untilMs !== undefined && nowMs > untilMs + skewMs) return 'expired';
  if (fromMs !== undefined && nowMs < fromMs - skewMs) return 'not_yet_valid';
  return undefined;
}

/**
 * Why `value` cannot be the tolerance option `option`, or `undefined` when it can: left out, or a
 * number of milliseconds from 0, which holds each bound exactly, to {@link LONGEST_CLOCK_SKEW_MS}.
 * Nothing is converted, so `null` and a numeric string are refused, not read as the default or as a
 * number.
 */
export function clockSkewRefusal(value: unknown, option = 'maxClockSkewMs'): string | undefined {
  if (value === undefined || (typeof value === 'number' && value >= 0 && value <= LONGEST_CLOCK_SKEW_MS)) return undefined;
  return `${option} must be a number of milliseconds from 0 to ${LONGEST_CLOCK_SKEW_MS} (got ${describeOptionValue(value)})`;
}

/**
 * `value` as the tolerance option `option`, in milliseconds: {@link DEFAULT_MAX_CLOCK_SKEW_MS} when it
 * is left out. Throws a `TypeError` naming the option, as `[kya-os] <option> must be ...`, for a
 * value {@link clockSkewRefusal} refuses, so a mistyped option fails where the reader is built.
 */
export function clockSkewOption(value: unknown, option = 'maxClockSkewMs'): number {
  const refusal = clockSkewRefusal(value, option);
  if (refusal !== undefined) throw new TypeError(`[kya-os] ${refusal}`);
  return value === undefined ? DEFAULT_MAX_CLOCK_SKEW_MS : (value as number);
}
