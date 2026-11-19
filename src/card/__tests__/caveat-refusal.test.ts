/**
 * `caveatRefusal` holds one call to the caveats a passing delegation verdict carries, so a host
 * never writes its own decimal or currency check, and answers with a refusal code beside its reason.
 * Every `MaxAmount` applies to every call: one that names a currency also requires the call to be in
 * it, and one that names none limits the amount whatever its currency. Each `ValidUntil` is read at
 * the call's time, the earliest hop `validUntil` among them, so a cached verdict is still held to
 * the chain's expiry. It fails closed on a verdict that does not pass, on one without its caveats,
 * on a malformed caveat, on a caveat of a known type with a member the library does not know, and on
 * one of an unknown type, unless the host names that type as one it enforces itself. A reason quotes
 * at most 64 characters of any value. Every case goes through `@kya-os/mcp/card`.
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
  validateDelegationChain,
  type Caveat,
  type CaveatRefusal,
  type DelegationChain,
  type EffectiveCaveats,
  type RefusalCode,
} from '../index.js';
import { NOW_MS, RESOURCE, hop, parties, serve, statusList, twoHopChain, type ChainParties } from './signed-chain-helpers.js';

const usd = (limit: string): Caveat => ({ type: 'MaxAmount', limit, currency: 'USD' });
const eur = (limit: string): Caveat => ({ type: 'MaxAmount', limit, currency: 'EUR' });
const anyCurrency = (limit: string): Caveat => ({ type: 'MaxAmount', limit });
/** A passing verdict as the library sets one: its caveats, and those it does not interpret apart. */
const verdict = (caveats: Caveat[], unknownCaveats: Caveat[] = []): { ok: true } & EffectiveCaveats => ({ ok: true, caveats, unknownCaveats });
/** The refusal of `code` for `reason`, which is not transient. */
const refused = (code: RefusalCode, reason: string): CaveatRefusal => ({ code, reason, transient: false });

describe('caveatRefusal and MaxAmount', () => {
  it('passes a call within the limit, the limit itself included, in its currency', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '60.00', currency: 'USD' })).toBeUndefined();
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '100', currency: 'USD' })).toBeUndefined();
  });

  it('refuses an amount over the limit, compared exactly, as a call the chain does not grant', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '100.0000001', currency: 'USD' })).toEqual(
      refused('insufficient_scope', 'the call\'s amount "100.0000001" is over the delegated MaxAmount of "100.00" in "USD"'),
    );
  });

  it('refuses a call in another currency, or in none, under a limit that names one', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '1', currency: 'EUR' })).toEqual(
      refused('insufficient_scope', 'the delegated MaxAmount of "100.00" in "USD" permits no call in "EUR"'),
    );
    expect(caveatRefusal(verdict([usd('100.00')]), { amount: '1' })).toEqual(
      refused('insufficient_scope', 'the delegated MaxAmount of "100.00" in "USD" permits no call that names no currency'),
    );
  });

  it('refuses a call that states no amount, or one that is not a plain non-negative decimal', () => {
    expect(caveatRefusal(verdict([usd('100.00')]), { currency: 'USD' })).toEqual(
      refused('insufficient_scope', 'the call states no amount, which a delegated MaxAmount limits'),
    );
    for (const amount of ['abc', '-5', ' 60 ', '1e1', '60.', '']) {
      expect(caveatRefusal(verdict([usd('100.00')]), { amount, currency: 'USD' })).toEqual(
        refused('insufficient_scope', `the call's amount ${JSON.stringify(amount)} is not a non-negative decimal`),
      );
    }
  });

  it('holds the call to every MaxAmount: one in each of two currencies permits no call at all', () => {
    const both = verdict([usd('100'), eur('90')]);
    expect(caveatRefusal(both, { amount: '10', currency: 'USD' })?.reason).toBe('the delegated MaxAmount of "90" in "EUR" permits no call in "USD"');
    expect(caveatRefusal(both, { amount: '10', currency: 'EUR' })?.reason).toBe('the delegated MaxAmount of "100" in "USD" permits no call in "EUR"');
  });

  it('reads a MaxAmount that names no currency as a limit whatever the currency, beside one that names one', () => {
    const mixed = verdict([anyCurrency('100'), usd('50')]);
    expect(caveatRefusal(mixed, { amount: '40', currency: 'USD' })).toBeUndefined();
    expect(caveatRefusal(mixed, { amount: '60', currency: 'USD' })?.reason).toBe('the call\'s amount "60" is over the delegated MaxAmount of "50" in "USD"');
    expect(caveatRefusal(mixed, { amount: '40', currency: 'EUR' })?.reason).toBe('the delegated MaxAmount of "50" in "USD" permits no call in "EUR"');
    expect(caveatRefusal(verdict([anyCurrency('100')]), { amount: '99', currency: 'EUR' })).toBeUndefined();
    expect(caveatRefusal(verdict([anyCurrency('100')]), { amount: '101', currency: 'EUR' })?.reason).toBe(
      'the call\'s amount "101" is over the delegated MaxAmount of "100"',
    );
  });

  it('quotes at most 64 characters of a limit or an amount, however long either is', () => {
    const refusal = caveatRefusal(verdict([usd('9'.repeat(1_000_000))]), { amount: '1'.repeat(1_000_001), currency: 'USD' });
    expect(refusal?.code).toBe('insufficient_scope');
    expect(refusal?.reason).toBe(`the call's amount "${'1'.repeat(64)}"... is over the delegated MaxAmount of "${'9'.repeat(64)}"... in "USD"`);
  });
});

describe('caveatRefusal and ValidUntil', () => {
  const until: Caveat = { type: 'ValidUntil', date: '2026-11-04T00:00:00Z' };
  const passed = refused('delegation_expired', 'the delegation\'s ValidUntil "2026-11-04T00:00:00Z" has passed');

  it('reads the date at the call, with the clock tolerance the guard reads it with', () => {
    expect(caveatRefusal(verdict([until]), { at: NOW_MS - 1 })).toBeUndefined();
    expect(caveatRefusal(verdict([until]), { at: NOW_MS + 120_000 })).toBeUndefined();
    expect(caveatRefusal(verdict([until]), { at: NOW_MS + 120_001 })).toEqual(passed);
    expect(caveatRefusal(verdict([until]), { at: NOW_MS + 1, maxClockSkewMs: 0 })).toEqual(passed);
  });

  it('reads the date at the time it is called when the call names none', () => {
    expect(caveatRefusal(verdict([until]))).toEqual(passed);
    expect(caveatRefusal(verdict([{ type: 'ValidUntil', date: '9999-01-01T00:00:00Z' }]))).toBeUndefined();
  });
});

describe('caveatRefusal fails closed', () => {
  it('on a verdict that does not pass, whatever caveats it carries, with the code it was refused with', () => {
    const p = parties();
    const untrusted = validateDelegationChain(twoHopChain(p), { resource: RESOURCE, resourceOwner: parties().acme.did, now: () => NOW_MS });
    expect(untrusted).toMatchObject({ ok: false, code: 'untrusted_root', caveats: [usd('100.00'), { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' }] });
    const notPassed = 'the verdict does not pass the delegation, so it permits no call';
    expect(caveatRefusal(untrusted, { amount: '1000000', currency: 'USD' })).toEqual(refused('untrusted_root', notPassed));
    expect(caveatRefusal({ ok: false, caveats: [], unknownCaveats: [] })).toEqual(refused('chain_invalid', notPassed));
    // A verdict with no `ok`, such as a double written by hand, does not pass either.
    expect(caveatRefusal({ caveats: [], unknownCaveats: [] } as unknown as { ok: true })).toEqual(refused('chain_invalid', notPassed));
  });

  it('on a verdict without its caveats, such as a test double or a cached grant written before them', () => {
    const missing = refused('configuration_error', 'the verdict carries no caveats and unknownCaveats, so the call cannot be held to its limits');
    expect(caveatRefusal({ ok: true }, { amount: '1', currency: 'USD' })).toEqual(missing);
    expect(caveatRefusal({ ok: true, caveats: [] }, { amount: '1', currency: 'USD' })).toEqual(missing);
    expect(caveatRefusal(verdict([]), {})).toBeUndefined();
  });

  it('on a malformed caveat', () => {
    expect(caveatRefusal(verdict([{ type: 'MaxAmount', limit: '1e3' }]), { amount: '1' })).toEqual(
      refused('delegation_malformed', 'the delegation carries a malformed caveat: MaxAmount caveat limit "1e3" is not a non-negative decimal'),
    );
    expect(caveatRefusal(verdict([{ type: 'ValidUntil' }]))).toEqual(
      refused('delegation_malformed', 'the delegation carries a malformed caveat: ValidUntil caveat states no date'),
    );
  });

  it('on a caveat of an unknown type, unless the host names its type as one it enforces', () => {
    const approval: Caveat = { type: 'RequiresHumanApproval', approvers: 2 };
    const notEnforced = refused('configuration_error', 'the delegation carries a caveat of type "RequiresHumanApproval" that the host does not enforce');
    expect(caveatRefusal(verdict([approval], [approval]))).toEqual(notEnforced);
    expect(caveatRefusal(verdict([approval], [approval]), { enforcedTypes: ['RequiresHumanApproval'] })).toBeUndefined();
    // Listed only apart, as a double might, it is read all the same.
    expect(caveatRefusal(verdict([], [approval]))).toEqual(notEnforced);
  });

  it('on a known type with a member the library does not know, still holding the call to the limit it reads', () => {
    const daily: Caveat = { type: 'MaxAmount', limit: '100', currency: 'USD', per: 'day' };
    expect(caveatRefusal(verdict([daily], [daily]), { amount: '1', currency: 'USD' })).toEqual(
      refused('configuration_error', 'the delegation carries a MaxAmount caveat that states "per", a member the library does not interpret'),
    );
    expect(caveatRefusal(verdict([daily], [daily]), { amount: '101', currency: 'USD' })).toEqual(
      refused('insufficient_scope', 'the call\'s amount "101" is over the delegated MaxAmount of "100" in "USD"'),
    );
  });

  it('throws a TypeError naming an option it cannot use', () => {
    expect(() => caveatRefusal(verdict([]), { enforcedTypes: 'RequiresHumanApproval' as unknown as string[] })).toThrow(
      /^\[kya-os\] caveatRefusal: enforcedTypes must be an array of caveat types/,
    );
    expect(() => caveatRefusal(verdict([]), { at: Number.NaN })).toThrow(/^\[kya-os\] caveatRefusal: at must be a time in epoch milliseconds/);
    expect(() => caveatRefusal(verdict([]), { maxClockSkewMs: -1 })).toThrow(TypeError);
  });

  it('throws a TypeError for a known type in enforcedTypes, which would let any member it does not know through', () => {
    for (const type of ['MaxAmount', 'ValidUntil']) {
      expect(() => caveatRefusal(verdict([]), { enforcedTypes: ['RequiresHumanApproval', type] })).toThrow(
        new TypeError(
          `[kya-os] caveatRefusal: enforcedTypes names "${type}", a caveat type the library enforces itself; ` +
            'one that states a member the library does not interpret is always refused',
        ),
      );
    }
  });
});

describe('caveatRefusal on a grant requireDelegation passes', () => {
  const guardFor = (p: ChainParties) => {
    const didResolver = createDidKeyResolver();
    return requireDelegation({
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
  };
  const grantOn = async (p: ChainParties, chain: DelegationChain) => {
    const grant = await guardFor(p)({ meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' });
    if (!grant.ok) throw new Error('the honest chain must pass');
    return grant;
  };

  it('holds the call to the worker limit the grant carries', async () => {
    const p = parties();
    const grant = await grantOn(p, twoHopChain(p));
    expect(caveatRefusal(grant, { amount: '60.00', currency: 'USD', at: NOW_MS })).toBeUndefined();
    expect(caveatRefusal(grant, { amount: '240.00', currency: 'USD', at: NOW_MS })).toEqual(
      refused('insufficient_scope', 'the call\'s amount "240.00" is over the delegated MaxAmount of "100.00" in "USD"'),
    );
  });

  it('holds a cached grant to the earliest validUntil of its hops, which states no ValidUntil caveat', async () => {
    const p = parties();
    const tomorrow = '2026-11-05T00:00:00Z';
    const [root] = twoHopChain(p);
    const leaf = hop({
      issuer: p.agent,
      invoker: p.subAgent.did,
      id: 'urn:zcap:leaf',
      parentCapability: root.credentialSubject.id,
      allowedAction: ['orders.place'],
      caveats: [usd('100.00')],
      statusIndex: 7,
      validUntil: tomorrow,
    });
    const grant = await grantOn(p, [root, leaf]);
    expect(grant.caveats).toEqual([usd('100.00'), { type: 'ValidUntil', date: tomorrow }]);
    expect(caveatRefusal(grant, { amount: '60.00', currency: 'USD', at: NOW_MS })).toBeUndefined();
    expect(caveatRefusal(grant, { amount: '60.00', currency: 'USD', at: NOW_MS + 7 * 86_400_000 })).toEqual(
      refused('delegation_expired', `the delegation's ValidUntil "${tomorrow}" has passed`),
    );
  });
});
