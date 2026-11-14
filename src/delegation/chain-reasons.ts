/**
 * The reasons chain enforcement gives when its chain resolver or revocation checker fails,
 * refuses or gives an answer that cannot be read. Each quotes a delegation id it names as `describeValue` quotes any value the other party
 * chose, and text the enforcement did not write, the message of an error one of them threw or the
 * reason the checker gave, through `sanitizeForMessage`, so a reason stays bounded, well-formed
 * text with no control character, as a response proof that signs it requires.
 */

import { describeValue } from "../utils/describe-value.js";
import { isRecord } from "../utils/guards.js";
import { sanitizeForMessage } from "../utils/message-text.js";
import { readRevoked } from "./revocation-answer.js";

/** The message of `error` as a reason holds it; a thrown value that is not an `Error` is not converted. */
function errorText(error: unknown): string {
  return error instanceof Error ? sanitizeForMessage(error.message) : "Unknown error";
}

/** Why a chain is refused when its resolver threw `error`. */
export function chainResolutionFailure(error: unknown): string {
  return `Failed to resolve delegation chain: ${errorText(error)}`;
}

/** Why a chain is refused when the revocation checker threw `error` checking `delegationId`. */
export function revocationCheckFailure(delegationId: string, error: unknown): string {
  return `Revocation check failed for delegation ${describeValue(delegationId)}: ${errorText(error)}`;
}

/**
 * Why the chain of the delegation `leafId` is refused on the revocation checker's `answer` about
 * `delegationId`, one of its credentials, or `undefined` when the answer lets it pass. It passes
 * only on an object whose `revoked` is the literal `false`, and is revoked only on the literal
 * `true`, through the ancestor the answer names, or `delegationId` when that is not the leaf. Any
 * other answer is a status that could not be read. An answer's `reason` and `revokedAncestor` are
 * used only when they are strings, so no answer makes this throw.
 */
export function revocationRefusal(leafId: string, delegationId: string, answer: unknown): string | undefined {
  const unreadable = `Revocation status of delegation ${describeValue(delegationId)} could not be read: `;
  if (!isRecord(answer)) {
    return `${unreadable}the revocation checker's answer (${describeValue(answer)}) is not an object`;
  }
  const revoked = readRevoked(answer.revoked);
  if (revoked === false) return undefined;
  if (revoked === undefined) {
    return `${unreadable}the revoked member of the revocation checker's answer (${describeValue(answer.revoked)}) is neither true nor false`;
  }
  const named = typeof answer.revokedAncestor === "string" ? answer.revokedAncestor : undefined;
  const revokedAncestor = named ?? (delegationId === leafId ? undefined : delegationId);
  return revokedReason(leafId, revokedAncestor, typeof answer.reason === "string" ? answer.reason : undefined);
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
