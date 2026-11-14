/**
 * How a revocation answer is read. A `StatusListResolver` and a `RevocationChecker` are supplied by
 * the host, and one written in JavaScript, or one with a fault, can answer anything. Reading the
 * answer by its truthiness would pass a credential on `undefined`, `null`, `0` or `""` and revoke it
 * on `"false"`, so an answer counts only when it is a literal boolean, the rule the Entity Card
 * verifier applies to its accountability verdict.
 */

import { describeValue } from "../utils/describe-value.js";

/**
 * Whether `answer` says revoked: `true` or `false` when it is that literal, and `undefined` for
 * anything else, a boxed boolean included. Nothing is converted. A caller refuses on `undefined`.
 */
export function readRevoked(answer: unknown): boolean | undefined {
  return typeof answer === "boolean" ? answer : undefined;
}

/** Why a credential is refused when its status list resolver gave `answer`, which is not a boolean. */
export function unreadableStatusReason(answer: unknown): string {
  return `Credential status could not be read: the status list resolver's answer (${describeValue(answer)}) is neither true nor false`;
}
