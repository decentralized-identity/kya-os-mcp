/**
 * The deadline a verifier puts on a dependency it waits on. A DID resolver, a status list resolver,
 * a chain resolver, a revocation checker and each verifier a host supplies are code the library
 * does not control, and one that never answers would hold a verification open. Every such call is
 * made through here, under one timer of {@link OUTBOUND_READ_TIMEOUT_MS}, so none can.
 */

import { OUTBOUND_READ_TIMEOUT_MS } from './outbound-read-limits.js';

/** What a {@link Deadline} rejects with once it has passed, so a caller can tell it from a failure of the work. */
export class DeadlineExceededError extends Error {}

/** One deadline that the steps of a piece of work share, so together they take at most its length. */
export interface Deadline {
  /** `work`, or a rejection with a {@link DeadlineExceededError} once the deadline has passed. */
  within<T>(work: Promise<T>): Promise<T>;
  /** Stop the timer, once the work has settled. */
  clear(): void;
}

/** A {@link Deadline} of {@link OUTBOUND_READ_TIMEOUT_MS}, starting now, that rejects with `expired` as its message. */
export function startDeadline(expired: string): Deadline {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const passed = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new DeadlineExceededError(expired)), OUTBOUND_READ_TIMEOUT_MS);
  });
  // A step that is not waiting when the deadline passes leaves no rejection unhandled.
  passed.catch(() => undefined);
  return {
    within: work => Promise.race([work, passed]),
    clear: () => clearTimeout(timer),
  };
}

/**
 * What `ask` answers, under a deadline of its own. Rejects with a {@link DeadlineExceededError}
 * that says `who` did not answer once the deadline has passed, and as `ask` does when it throws or
 * rejects. The work `ask` started is not cancelled; its late answer is dropped.
 */
export async function answerWithinDeadline<T>(who: string, ask: () => T | Promise<T>): Promise<T> {
  const deadline = startDeadline(`${who} did not answer within ${OUTBOUND_READ_TIMEOUT_MS / 1000} seconds`);
  try {
    return await deadline.within(Promise.resolve(ask()));
  } finally {
    deadline.clear();
  }
}
