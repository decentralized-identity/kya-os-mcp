/**
 * A durable grant caches evidence, never a decision: its credential is verified again each time
 * the grant is reused. The middleware's own verifier answers a failure as a refusal, so this
 * suite gives the grant resolution a verifier that throws instead, as one whose resolver or
 * provider failed might, and the reuse is denied, never passed.
 */

import { describe, expect, it } from 'vitest';
import { createGrantResolution } from '../with-kya-os.grants.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';
import { MemoryGrantStore } from '../../providers/grant-store.js';

const SCOPE = 'cart:write';
const SESSION = 'session';

/** The members of the middleware's dependencies that resolving a session's grant reads. */
function sessionDeps(grantStore: MemoryGrantStore): MiddlewareDeps {
  const used: Pick<MiddlewareDeps, 'grantStore' | 'holderBindingMode' | 'holderBindingVerifier'> = {
    grantStore,
    holderBindingMode: 'off',
    holderBindingVerifier: undefined,
  };
  return used as MiddlewareDeps;
}

describe('a durable grant whose credential cannot be verified again', () => {
  it('is not reused when verifying it throws', async () => {
    const grantStore = new MemoryGrantStore();
    await grantStore.bind({
      id: 'grant-1',
      agentDid: 'did:web:agent.example',
      scopes: [SCOPE],
      sessionId: SESSION,
      issuedAt: Date.now(),
      status: 'active',
      credentialJwt: 'header.claims.signature',
    });
    const asked: unknown[] = [];
    const resolution = createGrantResolution(sessionDeps(grantStore), async (evidence) => {
      asked.push(evidence);
      throw new Error('resolver down');
    });

    expect(await resolution.resolveExistingGrant('checkout', {}, SESSION, SCOPE)).toBeUndefined();
    expect(asked).toEqual(['header.claims.signature']);
  });
});
