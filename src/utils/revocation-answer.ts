/**
 * How a revocation answer is read, by every reader of one: the delegation status check and its
 * cache, chain enforcement's revocation check, and the Entity Card's revocation seam. A
 * `StatusListResolver`, a `RevocationChecker` and a `BitstringRevocationChecker` are supplied by
 * the host, and one written in JavaScript, or one with a fault, can answer anything. Reading the
 * answer by its truthiness would pass a credential on `undefined`, `null`, `0`, `""` or `{}` and
 * revoke it on `"false"`, so an answer counts only when it is a literal boolean, and a member of an
 * answer is read once, where a getter that throws is caught.
 */

import { describeValue } from "./describe-value.js";
import { isRecord } from "./guards.js";

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

/** The members a reader takes from a revocation checker's answer, in the order they are read. */
const ANSWER_MEMBERS = ["revoked", "fresh", "reason", "revokedAncestor"] as const;

/**
 * A revocation checker's answer as {@link readRevocationAnswer} read it. `revoked` is the literal
 * the answer stated. `fresh` is `true` only when the answer's is the literal `true`. `reason` and
 * `revokedAncestor` are the answer's when they are strings. An answer that could not be read has
 * `revoked: undefined` and says why in `unreadable`, a bounded line of well-formed text that
 * completes "could not be read: ".
 */
export type RevocationAnswer =
  | { revoked: boolean; fresh: boolean; reason: string | undefined; revokedAncestor: string | undefined }
  | { revoked: undefined; unreadable: string };

/**
 * Read a revocation checker's `answer`, an object with a `revoked` member. Only an answer whose
 * `revoked` is the literal `false` lets a credential pass and only the literal `true` revokes it;
 * a caller refuses any other answer as a status that could not be read. Each member is read exactly
 * once and inside the `try`, so an answer that is a proxy, or has a getter that throws, is an
 * unreadable answer whose reason names the member, and this never throws. A value the answer
 * holds is named as `describeValue` names it and never converted.
 */
export function readRevocationAnswer(answer: unknown): RevocationAnswer {
  let reading: string | undefined;
  try {
    if (!isRecord(answer)) {
      return { revoked: undefined, unreadable: `the revocation checker's answer (${describeValue(answer)}) is not an object` };
    }
    const read: Partial<Record<(typeof ANSWER_MEMBERS)[number], unknown>> = {};
    for (const member of ANSWER_MEMBERS) {
      reading = member;
      read[member] = answer[member];
    }
    reading = undefined;
    const revoked = readRevoked(read.revoked);
    if (revoked === undefined) {
      return {
        revoked,
        unreadable: `the revoked member of the revocation checker's answer (${describeValue(read.revoked)}) is neither true nor false`,
      };
    }
    return {
      revoked,
      fresh: read.fresh === true,
      reason: typeof read.reason === "string" ? read.reason : undefined,
      revokedAncestor: typeof read.revokedAncestor === "string" ? read.revokedAncestor : undefined,
    };
  } catch {
    return {
      revoked: undefined,
      unreadable:
        reading === undefined
          ? "the revocation checker's answer threw when it was examined"
          : `the ${reading} member of the revocation checker's answer threw when it was read`,
    };
  }
}
