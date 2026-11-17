/**
 * The Entity Card path reads a status list only inside the validity window it states: a delegation
 * chain whose status list, signed by its keeper with every bit clear, is past its `validUntil` or
 * before its `validFrom` is refused by `evaluateDelegationChain` as `status_unavailable`, saying
 * when, and one inside its window, or stating no end, passes fresh. Each bound is held with the
 * checker's `maxClockSkewMs`, 120 seconds unless set, and a bound that is not an RFC 3339 date-time
 * with its zone is refused. Every hop and list is signed by a real key and checked by the shipped
 * proof verifiers; only the network is faked.
 */

import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { evaluateDelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { NOW_MS, RESOURCE, now, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();

const at = (offsetMs: number): string => new Date(NOW_MS + offsetMs).toISOString();

/**
 * `evaluateDelegationChain` on a two-hop chain whose list, every bit clear, states `window`, read by a
 * checker built with `maxClockSkewMs` when it is given.
 */
async function verdictWith(window: Record<string, string>, maxClockSkewMs?: number) {
  const p = parties();
  const check = createRevocationChecker({
    fetch: serve(statusList(p.acme, [], window)),
    now,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
    ...(maxClockSkewMs === undefined ? {} : { maxClockSkewMs }),
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
    ['whose validFrom states no zone', { validFrom: '2026-11-01T00:00:00' }, 'status list states a validFrom ("2026-11-01T00:00:00") that is not an RFC 3339 date-time with a time zone'],
    ['whose validUntil is an HTTP date', { validUntil: 'Thu, 31 Dec 2026 00:00:00 GMT' }, 'status list states a validUntil ("Thu, 31 Dec 2026 00:00:00 GMT") that is not an RFC 3339 date-time with a time zone'],
  ])('refuses a clear list %s as status_unavailable, saying when', async (_label, window, words) => {
    const result = await verdictWith(window);
    expect(result).toMatchObject({ ok: false, fresh: false, code: 'status_unavailable', transient: true });
    expect(result.reasons.join('; ')).toContain(words);
  });

  it('passes, fresh, on a clear list issued just now by a server whose clock runs 2 seconds ahead', async () => {
    expect(await verdictWith({ validFrom: at(2_000) })).toMatchObject({ ok: true, fresh: true });
  });

  it('passes, fresh, on a clear list 2 seconds past its validUntil, within the tolerance', async () => {
    expect(await verdictWith({ validUntil: at(-2_000) })).toMatchObject({ ok: true, fresh: true });
  });

  it("holds each bound with the checker's maxClockSkewMs, exactly with none", async () => {
    const result = await verdictWith({ validFrom: at(2_000) }, 0);
    expect(result).toMatchObject({ ok: false, fresh: false, code: 'status_unavailable' });
    expect(result.reasons.join('; ')).toContain(`status list is not valid until "${at(2_000)}" (its validFrom)`);
  });

  it.each([-1, Number.NaN, 600_001, '120000'])('throws a TypeError naming maxClockSkewMs, when the checker is built, for %s', (maxClockSkewMs) => {
    expect(() => createRevocationChecker({ fetch: serve(undefined), maxClockSkewMs: maxClockSkewMs as number })).toThrow(
      /^\[kya-os\] maxClockSkewMs must be a number of milliseconds from 0 to 600000/,
    );
  });
});
