/**
 * The handshake asks the host's `delegationVerifier` whether an agent holds a delegation. The
 * agent is authorized only on an answer whose `valid` is the literal `true` and whose `delegation`
 * is an object. Any other answer, which untyped code or a fault can give, leaves the agent
 * unauthorized with a reason, and the handshake does not throw for it.
 */

import { describe, expect, it } from 'vitest';
import type { DelegationRecord } from '../../types/protocol.js';
import { MemoryResumeTokenStore, verifyOrHints, type AuthHandshakeConfig } from '../handshake.js';

const AGENT = 'did:key:z6MkTest';
const DELEGATION = { id: 'del-1', issuerDid: 'did:web:acme.example', subjectDid: AGENT } as unknown as DelegationRecord;
const CREDENTIAL = { agent_did: AGENT, user_did: 'did:web:acme.example', scopes: ['read:data'], authorization: { type: 'none' } };
const UNREADABLE = 'The verdict of the delegation verifier could not be read: ';

/** The handshake's outcome when the delegation verifier answers `answer`. */
function outcome(answer: unknown) {
  const config: AuthHandshakeConfig = {
    delegationVerifier: { verify: (async () => answer) as never },
    resumeTokenStore: new MemoryResumeTokenStore(),
    authorization: { authorizationUrl: 'https://example.com/consent' },
  };
  return verifyOrHints(AGENT, ['read:data'], config);
}

/** An answer whose `member` throws when read. */
const throwingOn = (member: string, rest: Record<string, unknown>): object =>
  Object.defineProperty({ ...rest }, member, {
    enumerable: true,
    get() {
      throw new Error('getter boom');
    },
  });

describe('a delegation verifier that answers a verdict', () => {
  it('authorizes on the literal true with a delegation, and hands back the delegation and credential it gave', async () => {
    expect(await outcome({ valid: true, delegation: DELEGATION, credential: CREDENTIAL })).toMatchObject({
      authorized: true, delegation: DELEGATION, credential: CREDENTIAL, reason: 'Valid delegation found',
    });
  });

  it('does not authorize on the literal false, with the reason the verifier gave', async () => {
    expect(await outcome({ valid: false, delegation: DELEGATION, reason: 'expired' })).toMatchObject({ authorized: false, reason: 'expired' });
    expect(await outcome({ valid: false })).toMatchObject({ authorized: false, reason: 'No delegation' });
  });

  it('does not authorize on the literal true without a delegation that is an object', async () => {
    for (const delegation of [undefined, null, 'del-1', 1, [DELEGATION]]) {
      expect(await outcome({ valid: true, delegation })).toMatchObject({ authorized: false, reason: 'No delegation' });
    }
  });

  it('hands back no credential that is not an object', async () => {
    const result = await outcome({ valid: true, delegation: DELEGATION, credential: 'forged' });
    expect(result).toMatchObject({ authorized: true, delegation: DELEGATION });
    expect(result.credential).toBeUndefined();
  });
});

describe('a delegation verifier whose answer is not a verdict', () => {
  it.each([
    ['{ valid: "true" }', { valid: 'true', delegation: DELEGATION }, 'the valid member of its answer ("true") is neither true nor false'],
    ['{ valid: "false" }', { valid: 'false', delegation: DELEGATION }, 'the valid member of its answer ("false") is neither true nor false'],
    ['{ valid: 1 }', { valid: 1, delegation: DELEGATION }, 'the valid member of its answer (of type number) is neither true nor false'],
    ['{ valid: 0 }', { valid: 0, delegation: DELEGATION }, 'the valid member of its answer (of type number) is neither true nor false'],
    ['{ valid: {} }', { valid: {}, delegation: DELEGATION }, 'the valid member of its answer (of type object) is neither true nor false'],
    ['{}', {}, 'the valid member of its answer (of type undefined) is neither true nor false'],
    ['undefined', undefined, 'its answer (of type undefined) is not an object'],
    ['null', null, 'its answer (of type null) is not an object'],
    ['true', true, 'its answer (of type boolean) is not an object'],
    ['an answer whose valid throws', throwingOn('valid', { delegation: DELEGATION }), 'reading its answer threw'],
    ['an answer whose reason throws', throwingOn('reason', { valid: true, delegation: DELEGATION }), 'reading its answer threw'],
    ['an answer whose delegation throws', throwingOn('delegation', { valid: true }), 'reading its answer threw'],
    ['an answer whose credential throws', throwingOn('credential', { valid: true, delegation: DELEGATION }), 'reading its answer threw'],
  ])('does not authorize, and does not throw, on %s', async (_label, answer, why) => {
    const result = await outcome(answer);
    expect(result).toMatchObject({ authorized: false, reason: `${UNREADABLE}${why}` });
    expect(result.authError).toBeDefined();
    expect(result.delegation).toBeUndefined();
  });
});
