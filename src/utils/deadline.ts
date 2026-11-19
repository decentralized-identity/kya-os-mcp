/**
 * The deadline a verifier puts on a dependency it waits on. A DID resolver, a status list resolver,
 * a chain resolver, a revocation checker and each verifier a host supplies are code the library
 * does not control, and one that never answers would hold a verification open. Every such call is
 * made through here, under one timer, so none can. The timer's length is the host's to set, as the
 * `dependencyTimeoutMs` option of each verifier and resolver, which {@link dependencyTimeout}
 * validates once where that verifier is built; it is {@link OUTBOUND_READ_TIMEOUT_MS} by default.
 *
 * A check that asks one dependency per credential of a chain also has a {@link TimeBudget}: the
 * time the whole check may take, {@link DEFAULT_TOTAL_TIMEOUT_MS} unless the host sets
 * `totalTimeoutMs`. A chain may be any length, so it is this, and no count of credentials, that
 * keeps dependencies that each answer just in time from holding a check open between them.
 */

import { describeOptionValue } from './describe-value.js';
import { OUTBOUND_READ_TIMEOUT_MS } from './outbound-read-limits.js';

/**
 * The longest `dependencyTimeoutMs` a verifier takes: the longest delay a timer holds, 2^31 - 1 ms,
 * about 24.8 days. A runtime fires a timer set for longer at once, which would refuse every call.
 */
export const MAX_DEPENDENCY_TIMEOUT_MS = 2_147_483_647;

/**
 * How long a whole check may take when `totalTimeoutMs` is left out: 30 seconds, half the 60 an
 * MCP client waits for an answer by default, so a refusal still reaches a caller that is waiting.
 */
export const DEFAULT_TOTAL_TIMEOUT_MS = 30_000;

/**
 * Why `value` cannot be the timeout `option`, or `undefined` when it can: a finite number of
 * milliseconds greater than 0 and at most {@link MAX_DEPENDENCY_TIMEOUT_MS}. Nothing is converted,
 * so `null` and a numeric string are refused, not read as the default or as a number.
 */
function timeoutRefusal(option: string, value: unknown): string | undefined {
  if (typeof value === 'number' && value > 0 && value <= MAX_DEPENDENCY_TIMEOUT_MS) return undefined;
  return `${option} must be a number of milliseconds greater than 0 and at most ${MAX_DEPENDENCY_TIMEOUT_MS} (got ${describeOptionValue(value)})`;
}

/**
 * The timeout `option` set to `value`: `fallback` when it is left out, else `value`. Throws a
 * `TypeError` naming the option, as `[kya-os] <path><option> ...`, for a value
 * {@link timeoutRefusal} refuses, so a mistyped option fails where the verifier is built.
 */
function timeoutOption(option: string, value: unknown, fallback: number, path: string): number {
  if (value === undefined) return fallback;
  const refusal = timeoutRefusal(option, value);
  if (refusal !== undefined) throw new TypeError(`[kya-os] ${path}${refusal}`);
  return value as number;
}

/** Why `value` cannot be a `dependencyTimeoutMs`, or `undefined` when it can ({@link timeoutRefusal}). */
export function dependencyTimeoutRefusal(value: unknown): string | undefined {
  return timeoutRefusal('dependencyTimeoutMs', value);
}

/**
 * The deadline, in milliseconds, a verifier built with the option `value` gives each dependency:
 * {@link OUTBOUND_READ_TIMEOUT_MS} when the option is left out, else `value`. Throws a `TypeError`
 * naming the option, as `[kya-os] <path>dependencyTimeoutMs ...`, for a value
 * {@link dependencyTimeoutRefusal} refuses.
 */
export function dependencyTimeout(value: unknown, path = ''): number {
  return timeoutOption('dependencyTimeoutMs', value, OUTBOUND_READ_TIMEOUT_MS, path);
}

/** Why `value` cannot be a `totalTimeoutMs`, or `undefined` when it can ({@link timeoutRefusal}). */
export function totalTimeoutRefusal(value: unknown): string | undefined {
  return timeoutRefusal('totalTimeoutMs', value);
}

/**
 * The time, in milliseconds, a check built with the option `value` may take in all:
 * {@link DEFAULT_TOTAL_TIMEOUT_MS} when the option is left out, else `value`. Throws a `TypeError`
 * naming the option, as `[kya-os] <path>totalTimeoutMs ...`, for a value
 * {@link totalTimeoutRefusal} refuses.
 */
export function totalTimeout(value: unknown, path = ''): number {
  return timeoutOption('totalTimeoutMs', value, DEFAULT_TOTAL_TIMEOUT_MS, path);
}

/**
 * `timeoutMs` as a reason states it: in seconds when it is a whole number of them (`5 seconds`,
 * `1 second`), else in milliseconds (`7500 ms`).
 */
export function describeTimeout(timeoutMs: number): string {
  if (timeoutMs % 1000 !== 0) return `${timeoutMs} ms`;
  return timeoutMs === 1000 ? '1 second' : `${timeoutMs / 1000} seconds`;
}

/** What a {@link Deadline} rejects with once it has passed, so a caller can tell it from a failure of the work. */
export class DeadlineExceededError extends Error {}

/** One deadline that the steps of a piece of work share, so together they take at most its length. */
export interface Deadline {
  /** `work`, or a rejection with a {@link DeadlineExceededError} once the deadline has passed. */
  within<T>(work: Promise<T>): Promise<T>;
  /** Stop the timer, once the work has settled. */
  clear(): void;
}

/** A {@link Deadline} of `timeoutMs`, starting now, that rejects with `expired` as its message. */
export function startDeadline(expired: string, timeoutMs: number): Deadline {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const passed = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new DeadlineExceededError(expired)), timeoutMs);
  });
  // A step that is not waiting when the deadline passes leaves no rejection unhandled.
  passed.catch(() => undefined);
  return {
    within: work => Promise.race([work, passed]),
    clear: () => clearTimeout(timer),
  };
}

/**
 * The time a whole check may take, which every dependency it asks draws on. Each wait gets its own
 * deadline or what the check has left, whichever is less, and once the time is spent nothing more
 * is asked: dependencies that each answer in time cannot together hold the check open, however
 * many of them a chain makes it ask.
 */
export interface TimeBudget {
  /** The milliseconds the check has left: 0 or less once its time is spent. */
  left(): number;
  /** What a wait rejects with when the check, and not the dependency's own deadline, ran out. */
  readonly spent: string;
}

/** A {@link TimeBudget} of `totalMs` for `work`, as `the revocation check`, starting now. */
export function startTimeBudget(work: string, totalMs: number): TimeBudget {
  const end = performance.now() + totalMs;
  return {
    left: () => end - performance.now(),
    spent: `${work} did not finish within ${describeTimeout(totalMs)}`,
  };
}

/**
 * The {@link TimeBudget} of a check of a delegation chain built with the `totalTimeoutMs` option
 * `value`, starting now. Throws as {@link totalTimeout} does for a value it refuses.
 */
export function delegationCheckBudget(value: unknown, path = ''): TimeBudget {
  return startTimeBudget('the delegation check', totalTimeout(value, path));
}

/** How a check asks one of its dependencies: what `ask` answers, or a rejection as {@link answerWithinDeadline} rejects. */
export type Ask = <T>(who: string, ask: () => T | Promise<T>) => Promise<T>;

/** An {@link Ask} that gives each dependency `timeoutMs` of its own, and all of them together `budget`. */
export function askWithin(timeoutMs: number, budget: TimeBudget): Ask {
  return (who, ask) => answerWithinDeadline(who, ask, timeoutMs, budget);
}

/**
 * What `ask` answers, under a deadline of its own of `timeoutMs`. Rejects with a
 * {@link DeadlineExceededError} that says `who` did not answer in that time once the deadline has
 * passed, and as `ask` does when it throws or rejects. The work `ask` started is not cancelled; its
 * late answer is dropped. With a `budget`, the wait also ends when the check it is part of runs out
 * of time, with a rejection that says so, and a check whose time is spent rejects so without
 * asking.
 */
export async function answerWithinDeadline<T>(
  who: string,
  ask: () => T | Promise<T>,
  timeoutMs: number,
  budget?: TimeBudget,
): Promise<T> {
  const left = budget?.left() ?? Number.POSITIVE_INFINITY;
  if (budget !== undefined && left <= 0) throw new DeadlineExceededError(budget.spent);
  const deadline =
    budget !== undefined && left < timeoutMs
      ? startDeadline(budget.spent, left)
      : startDeadline(`${who} did not answer within ${describeTimeout(timeoutMs)}`, timeoutMs);
  try {
    return await deadline.within(Promise.resolve(ask()));
  } finally {
    deadline.clear();
  }
}
