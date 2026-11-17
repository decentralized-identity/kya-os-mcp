/**
 * The reasons chain enforcement gives when its chain resolver or revocation checker fails,
 * refuses or gives an answer that cannot be read. Each quotes a delegation id it names as `describeValue` quotes any value the other party
 * chose, and text the enforcement did not write, the message of an error one of them threw or the
 * reason the checker gave, through `sanitizeForMessage`, so a reason stays bounded, well-formed
 * text with no control character, as a response proof that signs it requires. The chain resolver
 * and the revocation checker are the host's, and may throw their transport's words, so a thrown
 * message reaches a reason only where it may reach whoever presented the delegation
 * (`utils/thrown-words.ts`), as a `RefusalError`'s or a deadline's may; any other goes to the
 * operator's log, and the reason says only what failed.
 */

import { describeValue } from "../utils/describe-value.js";
import { sanitizeForMessage } from "../utils/message-text.js";
import { refusal, type Refusal } from "../utils/refusal.js";
import { readRevocationAnswer } from "../utils/revocation-answer.js";
import { thrownReason } from "../utils/thrown-words.js";

/** `opening`, then the words of `error` where they may be shown, or else `failed`, with the words logged. */
function thrownByHost(error: unknown, opening: string, failed: string): string {
  return thrownReason(error, { withheld: `${opening}: ${failed}`, shown: (words) => `${opening}: ${words}`, tag: "[kya-os]" });
}

/** Why a chain is refused when its resolver threw `error`. */
export function chainResolutionFailure(error: unknown): string {
  return thrownByHost(error, "Failed to resolve delegation chain", "the chain resolver failed");
}

/** Why a chain is refused when the revocation checker threw `error` checking `delegationId`. */
export function revocationCheckFailure(delegationId: string, error: unknown): string {
  return thrownByHost(error, `Revocation check failed for delegation ${describeValue(delegationId)}`, "the revocation checker failed");
}

/**
 * Why the chain of the delegation `leafId` is refused on the revocation checker's `answer` about
 * `delegationId`, one of its credentials, or `undefined` when the answer lets it pass. The answer
 * is read by the reader every revocation check shares ({@link readRevocationAnswer}): it passes
 * only on an object whose `revoked` is the literal `false`, and is revoked only on the literal
 * `true`, through the ancestor the answer names, or `delegationId` when that is not the leaf, with
 * the code the answer names, else `delegation_revoked`. Any other answer, one with a member whose getter throws included, is a
 * status that could not be read, `status_unavailable`, so no answer makes this throw.
 */
export function revocationRefusal(leafId: string, delegationId: string, answer: unknown): Refusal | undefined {
  const read = readRevocationAnswer(answer);
  if (read.revoked === false) return undefined;
  if (read.revoked === undefined) {
    return refusal(
      "status_unavailable",
      `Revocation status of delegation ${describeValue(delegationId)} could not be read: ${read.unreadable}`,
    );
  }
  const revokedAncestor = read.revokedAncestor ?? (delegationId === leafId ? undefined : delegationId);
  return refusal(read.code ?? "delegation_revoked", revokedReason(leafId, revokedAncestor, read.reason));
}

/**
 * Why the delegation `leafId` is refused as revoked: through `revokedAncestor` when one is, or
 * itself, with the reason the revocation checker gave when it gave one.
 */
export function revokedReason(
  leafId: string,
  revokedAncestor: string | undefined,
  checkerReason: string | undefined,
): string {
  const leaf = describeValue(leafId);
  if (revokedAncestor) return `Delegation ${leaf} is revoked via ancestor ${describeValue(revokedAncestor)}`;
  const given = checkerReason ? `: ${sanitizeForMessage(checkerReason)}` : "";
  return `Delegation ${leaf} is revoked${given}`;
}
