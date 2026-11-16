/**
 * The verdict readers take what a host's dependency answered, which can be anything, and never
 * throw for it. An answer an `await` hands over is never a revoked proxy, since awaiting one throws
 * first, but a member of it can be, and a caller that reads a verdict it holds can pass one.
 */
import { describe, expect, it } from 'vitest';
import { readDelegationVerdict } from '../../auth/delegation-verdict.js';
import { revokedProxy } from '../../__tests__/utils/verdict-answers.js';
import { readVerdict } from '../verdict.js';

const UNREADABLE = 'could not be read: reading its answer threw';

describe('a verdict that throws when it is looked at', () => {
  it('is refused as unreadable by readVerdict, which does not throw', () => {
    const reason = `The verdict of the signature verifier ${UNREADABLE}`;
    const unreadable = { valid: false, reason, code: 'runtime_error', transient: true };
    expect(readVerdict('the signature verifier', revokedProxy(), 'invalid_proof')).toEqual(unreadable);
    expect(readVerdict('the signature verifier', { valid: revokedProxy() }, 'invalid_proof')).toEqual(unreadable);
  });

  it('is refused as unreadable by readDelegationVerdict, which does not throw', () => {
    const reason = `The verdict of the delegation verifier ${UNREADABLE}`;
    expect(readDelegationVerdict(revokedProxy())).toEqual({ valid: false, reason });
    expect(readDelegationVerdict({ valid: revokedProxy() })).toEqual({ valid: false, reason });
  });
});
