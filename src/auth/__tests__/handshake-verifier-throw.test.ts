/**
 * When the host's `DelegationVerifier` throws, the handshake refuses the agent with the code
 * `runtime_error`, as it refuses an answer it could not read, and the challenge the client receives
 * says only that the verifier failed: the verifier is the host's, and what it threw may be its
 * transport's words about the host's network, which go to the operator's log. A `RefusalError` the
 * verifier throws gives the refusal its code and its words.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { verifyOrHints, MemoryResumeTokenStore, type AuthHandshakeConfig } from '../handshake.js';
import { logger } from '../../logging/index.js';
import { isTransientRefusal } from '../../refusal-codes.js';
import { RefusalError } from '../../utils/refusal.js';

const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

afterEach(() => {
  vi.restoreAllMocks();
});

/** What the handshake answers when the delegation verifier throws `error`, with what the operator's log was told. */
async function answerTo(error: unknown) {
  const logged = vi.spyOn(logger, 'error').mockImplementation(() => undefined);
  const config: AuthHandshakeConfig = {
    delegationVerifier: { verify: async () => Promise.reject(error) },
    resumeTokenStore: new MemoryResumeTokenStore(),
    authorization: { authorizationUrl: 'https://example.com/consent' },
  };
  const result = await verifyOrHints(AGENT, ['notes:read'], config);
  return {
    refusal: { authorized: result.authorized, reason: result.reason, code: result.code, transient: result.transient },
    challenge: result.authError?.message,
    log: logged.mock.calls.flat().map(String).join(' '),
  };
}

describe('the handshake, when the delegation verifier throws', () => {
  it('refuses as runtime_error, telling the client only that the verifier failed, and logs what it threw', async () => {
    const { refusal, challenge, log } = await answerTo(new Error('connect ECONNREFUSED 10.1.2.3:5432'));
    const reason = 'Delegation verification error: the delegation verifier failed';
    expect(refusal).toEqual({ authorized: false, reason, code: 'runtime_error', transient: isTransientRefusal('runtime_error') });
    expect(challenge).toBe(reason);
    expect(log).toContain('connect ECONNREFUSED 10.1.2.3:5432');
  });

  it('refuses with the code and the words of a RefusalError it throws', async () => {
    const { refusal, challenge } = await answerTo(new RefusalError('delegation_revoked', 'the grant was withdrawn'));
    const reason = 'Delegation verification error: the grant was withdrawn';
    expect(refusal).toEqual({ authorized: false, reason, code: 'delegation_revoked', transient: false });
    expect(challenge).toBe(reason);
  });
});
