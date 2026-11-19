/**
 * `caveatRefusal` holds one call to the caveats a delegation verdict carries, so a host never writes
 * its own decimal or currency check. Every `MaxAmount` applies to every call: one that names a
 * currency also requires the call to be in it, and one that names none limits the amount whatever
 * its currency. Each `ValidUntil` is read at the call's time. It fails closed on a verdict without
 * its caveats, on a malformed caveat, and on one the library does not interpret, unless the host
 * names that type as one it enforces itself. Every case goes through `@kya-os/mcp/card`.
 */

import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import {
  caveatRefusal,
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  type Caveat,
  type EffectiveCaveats,
} from '../index.js';
import { NOW_MS, RESOURCE, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';

const usd = (limit: string): Caveat => ({ type: 'MaxAmount', limit, currency: 'USD' });
const eur = (limit: string): Caveat => ({ type: 'MaxAmount', limit, currency: 'EUR' });
const anyCurrency = (limit: string): Caveat => ({ type: 'MaxAmount', limit });
/** A verdict as the library sets one: its caveats, and those it does not interpret apart. */
const verdict = (caveats: Caveat[], unknownCaveats: Caveat[] = []): EffectiveCaveats => ({ caveats, unknownCaveats });

describe('caveatRefusal and MaxAmount', () => {
  it('passes a call within the limit, the limit itself included, in its currency', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '60.00', currency: 'USD' })).toBeUndefined();
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '100', currency: 'USD' })).toBeUndefined();
  });

  it('refuses an amount over the limit, compared exactly', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '100.0000001', currency: 'USD' })).toBe(
      'the call\'s amount 100.0000001 is over the delegated MaxAmount of 100.00 in "USD"',
    );
  });

  it('refuses a call in another currency, or in none, under a limit that names one', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '1', currency: 'EUR' })).toBe(
      'the delegated MaxAmount of 100.00 in "USD" permits no call in "EUR"',
    );
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '1' })).toBe(
      'the delegated MaxAmount of 100.00 in "USD" permits no call that names no currency',
    );
  });

  it('refuses a call that states no amount, or one that is not a plain non-negative decimal', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { currency: 'USD' })).toBe('the call states no amount, which a delegated MaxAmount limits');
    for (const amount of ['abc', '-5', ' 60 ', '1e1', '60.', '']) {
      expect(caveatRefusal(verdict([usd('100.00')]), { amount, currency: 'USD' })).toBe(
        `the call's amount ${JSON.stringify(amount)} is not a non-negative decimal`,
      );
    }
  });

  it('holds the call to every MaxAmount: one in each of two currencies permits no call at all', () => {
    const both = verdict([usd('100'), eur('90')]);
    expect(caveatRefusal(both, { amount: '10', currency: 'USD' })).toBe('the delegated MaxAmount of 90 in "EUR" permits no call in "USD"');
    expect(caveatRefusal(both, { amount: '10', currency: 'EUR' })).toBe('the delegated MaxAmount of 100 in "USD" permits no call in "EUR"');
  });

  it('reads a MaxAmount that names no currency as a limit whatever the currency, beside one that names one', () => {
    const mixed = verdict([anyCurrency('100'), usd('50')]);
    expect(caveatRefusal(mixed, { amount: '40', currency: 'USD' })).toBeUndefined();
    expect(caveatRefusal(mixed, { amount: '60', currency: 'USD' })).toBe('the call\'s amount 60 is over the delegated MaxAmount of 50 in "USD"');
    expect(caveatRefusal(mixed, { amount: '40', currency: 'EUR' })).toBe('the delegated MaxAmount of 50 in "USD" permits no call in "EUR"');
    expect(caveatRefusal(verdict([anyCurrency('100')]), { amount: '99', currency: 'EUR' })).toBeUndefined();
    expect(caveatRefusal(verdict([anyCurrency('100')]), { amount: '101', currency: 'EUR' })).toBe(
      "the call's amount 101 is over the delegated MaxAmount of 100",
    );
  });
});

describe('caveatRefusal and ValidUntil', () => {
  const until: Caveat = { type: 'ValidUntil', date: '2026-11-04T00:00:00Z' };

  it('reads the date at the call, with the clock tolerance the guard reads it with', () => {
    expect(caveatRefusal(verdict([until]), { at: NOW_MS - 1 })).toBeUndefined();
    expect(caveatRefusal(verdict([until]), { at: NOW_MS + 120_000 })).toBeUndefined();
    expect(caveatRefusal(verdict([until]), { at: NOW_MS + 120_001 })).toBe("the delegation's ValidUntil 2026-11-04T00:00:00Z has passed");
    expect(caveatRefusal(verdict([until]), { at: NOW_MS + 1, maxClockSkewMs: 0 })).toBe(
      "the delegation's ValidUntil 2026-11-04T00:00:00Z has passed",
    );
  });

  it('reads the date at the time it is called when the call names none', () => {
    expect(caveatRefusal(verdict([until]))).toBe("the delegation's ValidUntil 2026-11-04T00:00:00Z has passed");
    expect(caveatRefusal(verdict([{ type: 'ValidUntil', date: '9999-01-01T00:00:00Z' }]))).toBeUndefined();
  });
});

describe('caveatRefusal fails closed', () => {
  it('on a verdict without its caveats, such as a test double or a cached grant written before them', () => {
    const missing = 'the verdict carries no caveats and unknownCaveats, so the call cannot be held to its limits';
    expect(caveatRefusal({}, { amount: '1', currency: 'USD' })).toBe(missing);
    expect(caveatRefusal({ caveats: [] }, { amount: '1', currency: 'USD' })).toBe(missing);
    expect(caveatRefusal(verdict([]), {})).toBeUndefined();
  });

  it('on a malformed caveat', () => {
    expect(caveatRefusal(verdict([{ type: 'MaxAmount', limit: '1e3' }]), { amount: '1' })).toBe(
      'the delegation carries a malformed caveat: MaxAmount caveat limit "1e3" is not a non-negative decimal',
    );
    expect(caveatRefusal(verdict([{ type: 'ValidUntil' }]))).toBe('the delegation carries a malformed caveat: ValidUntil caveat states no date');
  });

  it('on a caveat the library does not interpret, unless the host names its type as one it enforces', () => {
    const approval: Caveat = { type: 'RequiresHumanApproval', approvers: 2 };
    expect(caveatRefusal(verdict([approval], [approval]))).toBe(
      'the delegation carries a caveat of type "RequiresHumanApproval" that the host does not enforce',
    );
    expect(caveatRefusal(verdict([approval], [approval]), { enforcedTypes: ['RequiresHumanApproval'] })).toBeUndefined();
    // Listed only apart, as a double might, it is read all the same.
    expect(caveatRefusal(verdict([], [approval]))).toBe(
      'the delegation carries a caveat of type "RequiresHumanApproval" that the host does not enforce',
    );
  });

  it('on a known type with a member the library does not know, still holding the call to the limit it reads', () => {
    const daily: Caveat = { type: 'MaxAmount', limit: '100', currency: 'USD', per: 'day' };
    expect(caveatRefusal(verdict([daily], [daily]), { amount: '1', currency: 'USD' })).toBe(
      'the delegation carries a caveat of type "MaxAmount" that the host does not enforce',
    );
    expect(caveatRefusal(verdict([daily], [daily]), { amount: '1', currency: 'USD', enforcedTypes: ['MaxAmount'] })).toBeUndefined();
    expect(caveatRefusal(verdict([daily], [daily]), { amount: '101', currency: 'USD', enforcedTypes: ['MaxAmount'] })).toBe(
      'the call\'s amount 101 is over the delegated MaxAmount of 100 in "USD"',
    );
  });

  it('throws a TypeError naming an option it cannot use', () => {
    expect(() => caveatRefusal(verdict([]), { enforcedTypes: 'RequiresHumanApproval' as unknown as string[] })).toThrow(
      /^\[kya-os\] caveatRefusal: enforcedTypes must be an array of caveat types/,
    );
    expect(() => caveatRefusal(verdict([]), { at: Number.NaN })).toThrow(/^\[kya-os\] caveatRefusal: at must be a time in epoch milliseconds/);
    expect(() => caveatRefusal(verdict([]), { maxClockSkewMs: -1 })).toThrow(TypeError);
  });
});

describe('caveatRefusal on a grant requireDelegation passes', () => {
  it('holds the call to the worker limit the grant carries', async () => {
    const p = parties();
    const didResolver = createDidKeyResolver();
    const guard = requireDelegation({
      resource: RESOURCE,
      trustedRootIssuers: [p.acme.did],
      verifyHopProof: createDelegationProofVerifier({ didResolver }),
      checkRevocation: createRevocationChecker({
        fetch: serve(statusList(p.acme)),
        now: () => NOW_MS,
        verifyStatusList: createStatusListProofVerifier({ didResolver }),
      }),
      now: () => NOW_MS,
    });
    const grant = await guard({ meta: toDelegationChainMeta(twoHopChain(p)), proofDid: p.subAgent.did, action: 'orders.place' });
    if (!grant.ok) throw new Error('the honest chain must pass');
    expect(caveatRefusal(grant, { amount: '60.00', currency: 'USD' })).toBeUndefined();
    expect(caveatRefusal(grant, { amount: '240.00', currency: 'USD' })).toBe(
      'the call\'s amount 240.00 is over the delegated MaxAmount of 100.00 in "USD"',
    );
  });
});
