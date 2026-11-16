/**
 * The reasons chain enforcement gives when its chain resolver or revocation checker fails or
 * refuses. Each quotes a delegation id it names as `describeValue` quotes any value the other party
 * chose, and text the enforcement did not write, the message of an error one of them threw or the
 * reason the checker gave, through `sanitizeForMessage`, so a reason stays bounded, well-formed
 * text with no control character, as a response proof that signs it requires.
 */

import { describeValue } from "../utils/describe-value.js";
import { sanitizeForMessage } from "../utils/message-text.js";

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
