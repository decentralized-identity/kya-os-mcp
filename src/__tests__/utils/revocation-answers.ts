/**
 * Test helpers: the answers a revocation checker can give that are neither a pass nor a
 * revocation, each with how the shared reader (`readRevocationAnswer`) says it could not be read.
 * Both sides that read an answer, the delegation chain enforcement and the Entity Card's revocation
 * seam, are tested against the same table.
 */

const CHECKER = "the revocation checker's answer";

/** Answers that are not an object, each with how a reason names it. */
export const NOT_OBJECT_ANSWERS: readonly (readonly [string, unknown, string])[] = [
  ['undefined', undefined, `${CHECKER} (of type undefined) is not an object`],
  ['null', null, `${CHECKER} (of type null) is not an object`],
  ['0', 0, `${CHECKER} (of type number) is not an object`],
  ['false', false, `${CHECKER} (of type boolean) is not an object`],
  ['the string "false"', 'false', `${CHECKER} ("false") is not an object`],
  ['an array', [{ revoked: false, fresh: true }], `${CHECKER} (of type array) is not an object`],
];

/** Objects whose `revoked` member is neither `true` nor `false`, each with how a reason names it. */
export const NOT_BOOLEAN_ANSWERS: readonly (readonly [string, unknown, string])[] = [
  ['{}', {}, `the revoked member of ${CHECKER} (of type undefined) is neither true nor false`],
  ['{revoked: 0}', { revoked: 0, fresh: true }, `the revoked member of ${CHECKER} (of type number) is neither true nor false`],
  ['{revoked: "false"}', { revoked: 'false', fresh: true }, `the revoked member of ${CHECKER} ("false") is neither true nor false`],
  ['{revoked: undefined}', { revoked: undefined, fresh: true }, `the revoked member of ${CHECKER} (of type undefined) is neither true nor false`],
  ['{revoked: null}', { revoked: null, fresh: true }, `the revoked member of ${CHECKER} (of type null) is neither true nor false`],
  ['{revoked: a boxed false}', { revoked: new Boolean(false), fresh: true }, `the revoked member of ${CHECKER} (of type object) is neither true nor false`],
];

/** `base` with a `member` whose getter throws, and how a reason says so. */
export function throwingMember(member: string, base: Record<string, unknown> = {}): readonly [string, unknown, string] {
  const answer = Object.defineProperty({ ...base }, member, {
    enumerable: true,
    get(): never {
      throw new Error(`${member} getter boom`);
    },
  });
  return [`a ${member} getter that throws`, answer, `the ${member} member of ${CHECKER} threw when it was read`];
}

/** Answers with a getter that throws: on `revoked`, and on each other member beside a literal `revoked`. */
export const THROWING_ANSWERS: readonly (readonly [string, unknown, string])[] = [
  throwingMember('revoked'),
  throwingMember('reason', { revoked: true }),
  throwingMember('revokedAncestor', { revoked: true }),
  throwingMember('fresh', { revoked: false }),
];

/** Every answer above: none passes a credential, and none is read as revoked. */
export const UNREADABLE_ANSWERS = [...NOT_OBJECT_ANSWERS, ...NOT_BOOLEAN_ANSWERS, ...THROWING_ANSWERS];

/**
 * An answer that counts each read of a member, so a test can hold a reader to one read of each.
 * `reads` maps a member's name to how often it was read.
 */
export function countingAnswer(members: Record<string, unknown>): { answer: object; reads: Record<string, number> } {
  const reads: Record<string, number> = {};
  const answer = new Proxy(members, {
    get(target, name) {
      if (typeof name === 'string') reads[name] = (reads[name] ?? 0) + 1;
      return Reflect.get(target, name);
    },
  });
  return { answer, reads };
}
