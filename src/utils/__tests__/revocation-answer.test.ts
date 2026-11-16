/**
 * The one reader of a revocation checker's answer. Only a literal `false` in `revoked` passes and
 * only a literal `true` revokes; `fresh` is fresh only as a literal `true`; each member is read
 * once; and no answer, a proxy or a throwing getter included, makes the reader throw.
 */
import { describe, expect, it } from 'vitest';
import { countingAnswer, PASSING_WITH_THROWING_CODE, UNREADABLE_ANSWERS } from '../../__tests__/utils/revocation-answers.js';
import { readRevocationAnswer, readRevoked, unreadableStatusReason } from '../revocation-answer.js';

describe('readRevoked', () => {
  it('reads only a literal boolean', () => {
    expect(readRevoked(true)).toBe(true);
    expect(readRevoked(false)).toBe(false);
    for (const answer of [undefined, null, 0, 1, '', 'false', {}, [], new Boolean(false)]) {
      expect(readRevoked(answer)).toBeUndefined();
    }
  });

  it('says why a bare answer could not be read, naming it without converting it', () => {
    expect(unreadableStatusReason('no')).toBe(
      'Credential status could not be read: the status list resolver\'s answer ("no") is neither true nor false',
    );
  });
});

describe('readRevocationAnswer', () => {
  it('reads a literal false as not revoked, fresh only on a literal true', () => {
    expect(readRevocationAnswer({ revoked: false, fresh: true })).toEqual({
      revoked: false,
      fresh: true,
      reason: undefined,
      revokedAncestor: undefined,
    });
    for (const fresh of [undefined, null, false, 1, 'true', {}, new Boolean(true)]) {
      expect(readRevocationAnswer({ revoked: false, fresh })).toMatchObject({ revoked: false, fresh: false });
    }
    expect(readRevocationAnswer({ revoked: false })).toMatchObject({ revoked: false, fresh: false });
  });

  it('reads a literal true as revoked, with the reason and the ancestor it names as strings', () => {
    expect(readRevocationAnswer({ revoked: true, fresh: true, reason: 'key compromise', revokedAncestor: 'del-root' })).toEqual({
      revoked: true,
      fresh: true,
      reason: 'key compromise',
      revokedAncestor: 'del-root',
    });
    expect(readRevocationAnswer({ revoked: true, reason: 5, revokedAncestor: { id: 'del-root' } })).toEqual({
      revoked: true,
      fresh: false,
      reason: undefined,
      revokedAncestor: undefined,
    });
  });

  it('reads a code only when it is one of the catalog\'s refusal codes', () => {
    expect(readRevocationAnswer({ revoked: true, code: 'status_signer_untrusted' })).toMatchObject({ code: 'status_signer_untrusted' });
    for (const code of ['revoked', 5, { code: 'delegation_revoked' }, undefined]) {
      expect(readRevocationAnswer({ revoked: true, code })).toMatchObject({ revoked: true, code: undefined });
    }
  });

  it.each(UNREADABLE_ANSWERS)('reads %s as an answer that could not be read, and says why', (_label, answer, why) => {
    expect(readRevocationAnswer(answer)).toEqual({ revoked: undefined, unreadable: why });
  });

  it('reads each member exactly once, in a fixed order, and the code only of an answer that revokes', () => {
    for (const members of [{ revoked: false, fresh: true }, {}]) {
      const { answer, reads } = countingAnswer(members);
      readRevocationAnswer(answer);
      expect(Object.entries(reads)).toEqual([['revoked', 1], ['fresh', 1], ['reason', 1], ['revokedAncestor', 1]]);
    }
    const { answer, reads } = countingAnswer({ revoked: true, reason: 'r', revokedAncestor: 'a' });
    readRevocationAnswer(answer);
    expect(Object.entries(reads)).toEqual([['revoked', 1], ['fresh', 1], ['reason', 1], ['revokedAncestor', 1], ['code', 1]]);
  });

  it('passes an answer whose code getter throws, since it does not revoke', () => {
    expect(readRevocationAnswer(PASSING_WITH_THROWING_CODE)).toEqual({
      revoked: false,
      fresh: true,
      reason: undefined,
      revokedAncestor: undefined,
      code: undefined,
    });
  });

  it('does not throw on a proxy that cannot be examined, or on a member that cannot be', () => {
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const examined = "the revocation checker's answer threw when it was examined";
    expect(readRevocationAnswer(revoked.proxy)).toEqual({ revoked: undefined, unreadable: examined });
    expect(readRevocationAnswer({ revoked: revoked.proxy })).toEqual({ revoked: undefined, unreadable: examined });
    const hostile = new Proxy({}, { get: () => { throw new Error('proxy boom'); } });
    expect(readRevocationAnswer(hostile)).toEqual({
      revoked: undefined,
      unreadable: "the revoked member of the revocation checker's answer threw when it was read",
    });
  });
});
