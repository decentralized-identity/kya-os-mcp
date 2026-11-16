/**
 * How a verdict of the shape `{ valid, reason? }` is read when a dependency the host supplies gave
 * it: a custom signature verifier, or the per-credential verifier of a chain walk. Such code can
 * answer anything, and reading `valid` by its truthiness would verify on `"false"`, `1` or `{}`,
 * so a verdict passes only on the literal `true` the type promises, the rule
 * `utils/revocation-answer.ts` applies to a revocation answer.
 */

import { describeValue } from './describe-value.js';
import { isRecord } from './guards.js';
import { sanitizeForMessage } from './message-text.js';

/** A verdict as a verifier holds it: `valid` is a boolean, and a refusal's `reason` is bounded text. */
export type Verdict = { readonly valid: true } | { readonly valid: false; readonly reason?: string };

/** The refusal of a verdict of `who` that could not be read, for the reason `why`. */
function unreadableVerdict(who: string, why: string): Verdict {
  return { valid: false, reason: `The verdict of ${who} could not be read: ${why}` };
}

/** The refusal of an answer of `who` one of whose members threw when it was read. */
export function verdictReadThrew(who: string): Verdict {
  return unreadableVerdict(who, 'reading its answer threw');
}

/**
 * The verdict `answer`, which `who` gave, comes to. It is valid only when `answer` is an object
 * whose `valid` is the literal `true`. On the literal `false` it is a refusal with the `reason` the
 * answer gave, when that is a string, as `sanitizeForMessage` bounds it. Anything else is a refusal
 * whose reason says the verdict could not be read: an answer that is not an object, a `valid` that
 * is not a boolean, a boxed one included, and an answer, or a `valid`, that throws when it is
 * looked at, such as a getter that throws or a revoked proxy. Each member is read once, so a getter
 * cannot answer one thing here and another later, nothing is converted, and every look at the
 * answer is inside the `try`, so no answer makes this throw.
 */
export function readVerdict(who: string, answer: unknown): Verdict {
  try {
    if (!isRecord(answer)) return unreadableVerdict(who, `its answer (${describeValue(answer)}) is not an object`);
    const valid: unknown = answer.valid;
    const reason: unknown = answer.reason;
    if (valid === true) return { valid: true };
    if (valid !== false) {
      return unreadableVerdict(who, `the valid member of its answer (${describeValue(valid)}) is neither true nor false`);
    }
    return typeof reason === 'string' ? { valid: false, reason: sanitizeForMessage(reason) } : { valid: false };
  } catch {
    return verdictReadThrew(who);
  }
}
