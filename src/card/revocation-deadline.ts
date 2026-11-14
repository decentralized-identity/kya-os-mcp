/**
 * A revocation checker asked under the deadline every dependency a verifier waits on gets
 * (`utils/deadline.ts`). The chain walk and `verifyCard` both ask through here, so a checker the
 * host supplies, or the list read and proof check behind the shipped one, cannot hold either open.
 */

import type { StatusCheckContext } from '../utils/statuslist-acceptance.js';
import { answerWithinDeadline, DeadlineExceededError } from '../utils/deadline.js';
import type { BitstringRevocationChecker, RevocationStatusEntry } from './revocation.js';

/** What a checker answered, whatever it is, or the text that says it had not answered by the deadline. */
export type AskedRevocation = { answer: unknown } | { expired: string };

/**
 * What `check` answers about `entry`, with `context` when there is one, unread: the caller reads it
 * as any revocation answer is read. A checker that has not answered by the deadline is not waited
 * on, and the result says so, apart from any answer, so an answer that is itself text is never
 * taken for it. A checker that throws still throws.
 */
export async function checkWithinDeadline(
  check: BitstringRevocationChecker,
  entry: RevocationStatusEntry,
  context?: StatusCheckContext,
): Promise<AskedRevocation> {
  try {
    const answer: unknown = await answerWithinDeadline('the revocation checker', () =>
      context === undefined ? check(entry) : check(entry, context),
    );
    return { answer };
  } catch (error) {
    if (error instanceof DeadlineExceededError) return { expired: error.message };
    throw error;
  }
}
