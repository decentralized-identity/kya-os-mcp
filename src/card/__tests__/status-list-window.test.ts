/**
 * The Entity Card path reads a status list only inside the validity window it states: a delegation
 * chain whose status list, signed by its keeper with every bit clear, is past its `validUntil` or
 * before its `validFrom` is refused by `evaluateDelegationChain` as `status_unavailable`, saying
 * when, and one inside its window, or stating no end, passes fresh. Every hop and list is signed by
 * a real key and checked by the shipped proof verifiers; only the network is faked.
 */

import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { evaluateDelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { RESOURCE, now, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();

/** `evaluateDelegationChain` on a two-hop chain whose list, every bit clear, states `window`. */
async function verdictWith(window: Record<string, string>) {
  const p = parties();
  const check = createRevocationChecker({
    fetch: serve(statusList(p.acme, [], window)),
    now,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
  });
  return evaluateDelegationChain(twoHopChain(p), check, {
    resource: RESOURCE,
    resourceOwner: p.acme.did,
    now,
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
  });
}

describe('evaluateDelegationChain holds each status list to its validity window', () => {
  it('passes, fresh, on a clear list inside its window', async () => {
    expect(await verdictWith({ validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-12-31T00:00:00Z' })).toMatchObject({
      ok: true,
      fresh: true,
    });
  });

  it('passes, fresh, on a clear list that states no end, as before', async () => {
    expect(await verdictWith({})).toMatchObject({ ok: true, fresh: true });
  });

  it.each([
    ['past its validUntil', { validUntil: '2026-11-01T00:00:00Z' }, 'status list expired at "2026-11-01T00:00:00Z" (its validUntil)'],
    ['before its validFrom', { validFrom: '2026-12-01T00:00:00Z' }, 'status list is not valid until "2026-12-01T00:00:00Z" (its validFrom)'],
  ])('refuses a clear list %s as status_unavailable, saying when', async (_label, window, words) => {
    const result = await verdictWith(window);
    expect(result).toMatchObject({ ok: false, fresh: false, code: 'status_unavailable', transient: true });
    expect(result.reasons.join('; ')).toContain(words);
  });
});
