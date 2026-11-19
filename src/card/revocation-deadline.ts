/**
 * A revocation checker asked under the deadline its verifier gives every dependency it waits on
 * (`utils/deadline.ts`). The chain walk and `verifyCard` both ask through here, so a checker the
 * host supplies, or the list read and proof check behind the shipped one, cannot hold either open.
 */

import type { StatusCheckContext } from '../utils/statuslist-acceptance.js';
import { answerWithinDeadline, DeadlineExceededError, type TimeBudget } from '../utils/deadline.js';
import { carryingContext } from '../utils/status-check-carrier.js';
import type { BitstringRevocationChecker, RevocationStatusEntry } from './revocation.js';

/** What a checker answered, whatever it is, or the text that says it had not answered by the deadline, or that the check ran out of time. */
export type AskedRevocation = { answer: unknown } | { expired: string };

/**
 * What `check` answers about `entry`, with `context` when there is one, unread: the caller reads it
 * as any revocation answer is read. A checker that has not answered in `timeoutMs` is not waited
 * on, nor is one asked by a walk whose `budget` has run out, and the result says so, apart from any
 * answer, so an answer that is itself text is never taken for it. A checker that throws still throws. With a context, the checker is given a fresh
 * copy of `entry` that carries it too (`carryingContext`), so a checker that wraps a library checker
 * and passes on only the entry it was given keeps the context.
 */
export async function checkWithinDeadline(
  check: BitstringRevocationChecker,
  entry: RevocationStatusEntry,
  context: StatusCheckContext | undefined,
  timeoutMs: number,
  budget?: TimeBudget,
): Promise<AskedRevocation> {
  try {
    const answer: unknown = await answerWithinDeadline('the revocation checker', () =>
      context === undefined ? check(entry) : check(carryingContext(entry, context), context),
    timeoutMs, budget);
    return { answer };
  } catch (error) {
    if (error instanceof DeadlineExceededError) return { expired: error.message };
    throw error;
  }
}
