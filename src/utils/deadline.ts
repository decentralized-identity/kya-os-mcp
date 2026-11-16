/**
 * The deadline a verifier puts on a dependency it waits on. A DID resolver, a status list resolver,
 * a chain resolver, a revocation checker and each verifier a host supplies are code the library
 * does not control, and one that never answers would hold a verification open. Every such call is
 * made through here, under one timer, so none can. The timer's length is the host's to set, as the
 * `dependencyTimeoutMs` option of each verifier and resolver, which {@link dependencyTimeout}
 * validates once where that verifier is built; it is {@link OUTBOUND_READ_TIMEOUT_MS} by default.
 */

import { describeValue } from './describe-value.js';
import { OUTBOUND_READ_TIMEOUT_MS } from './outbound-read-limits.js';

/**
 * The longest `dependencyTimeoutMs` a verifier takes: the longest delay a timer holds, 2^31 - 1 ms,
 * about 24.8 days. A runtime fires a timer set for longer at once, which would refuse every call.
 */
export const MAX_DEPENDENCY_TIMEOUT_MS = 2_147_483_647;

/**
 * Why `value` cannot be a `dependencyTimeoutMs`, or `undefined` when it can: a finite number of
 * milliseconds greater than 0 and at most {@link MAX_DEPENDENCY_TIMEOUT_MS}. Nothing is converted,
 * so `null` and a numeric string are refused, not read as the default or as a number.
 */
export function dependencyTimeoutRefusal(value: unknown): string | undefined {
  if (typeof value === 'number' && value > 0 && value <= MAX_DEPENDENCY_TIMEOUT_MS) return undefined;
  const got = typeof value === 'number' ? String(value) : `a value ${describeValue(value)}`;
  return `dependencyTimeoutMs must be a number of milliseconds greater than 0 and at most ${MAX_DEPENDENCY_TIMEOUT_MS} (got ${got})`;
}

/**
 * The deadline, in milliseconds, a verifier built with the option `value` gives each dependency:
 * {@link OUTBOUND_READ_TIMEOUT_MS} when the option is left out, else `value`. Throws a `TypeError`
 * naming the option, as `[kya-os] <path>dependencyTimeoutMs ...`, for a value
 * {@link dependencyTimeoutRefusal} refuses, so a mistyped option fails where the verifier is built.
 */
export function dependencyTimeout(value: unknown, path = ''): number {
  if (value === undefined) return OUTBOUND_READ_TIMEOUT_MS;
  const refusal = dependencyTimeoutRefusal(value);
  if (refusal !== undefined) throw new TypeError(`[kya-os] ${path}${refusal}`);
  return value as number;
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
 * What `ask` answers, under a deadline of its own of `timeoutMs`. Rejects with a
 * {@link DeadlineExceededError} that says `who` did not answer in that time once the deadline has
 * passed, and as `ask` does when it throws or rejects. The work `ask` started is not cancelled; its
 * late answer is dropped.
 */
export async function answerWithinDeadline<T>(who: string, ask: () => T | Promise<T>, timeoutMs: number): Promise<T> {
  const deadline = startDeadline(`${who} did not answer within ${describeTimeout(timeoutMs)}`, timeoutMs);
  try {
    return await deadline.within(Promise.resolve(ask()));
  } finally {
    deadline.clear();
  }
}
