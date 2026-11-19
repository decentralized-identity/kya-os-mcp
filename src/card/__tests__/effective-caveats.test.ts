/**
 * The caveats a verified delegation chain grants under (SPEC.md §6.10). The chain rules check that
 * each hop's caveats narrow its parent's, and the verdict then carries the tightest caveat of each
 * kind the chain states, so a host holds the call to the limit from the verdict alone: the lowest
 * `MaxAmount` that names one currency, or none, the earliest `ValidUntil`, and every caveat the
 * library does not interpret, as written, listed apart. A caveat of a known type with a member the
 * library does not know is one it does not interpret. Every caveat applies to every call, so a
 * `MaxAmount` that names a currency never stands in for one that names none. A duplicate within one
 * hop never loosens what the verdict says. A passing verdict warns once per process of a caveat
 * the library does not interpret; a refused one does not. Every case goes through
 * `@kya-os/mcp/card` as an adopter calls it, on hops signed with real keys.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { logger } from '../../logging/index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateDelegationChain,
  requireDelegation,
  toDelegationChainMeta,
  validateDelegationChain,
  type BitstringRevocationChecker,
  type Caveat,
  type DelegationChain,
} from '../index.js';
import { NOW_MS, RESOURCE, hop, identity, parties, serve, statusList, twoHopChain, type ChainParties } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const now = (): number => NOW_MS;

const maxAmount = (limit: string, currency = 'USD'): Caveat => ({ type: 'MaxAmount', limit, currency });
const validUntil = (date: string): Caveat => ({ type: 'ValidUntil', date });

/** The shipped status checker, reading Acme's signed list, which speaks for every hop of its chains. */
const checkerFor = (p: ChainParties): BitstringRevocationChecker =>
  createRevocationChecker({ fetch: serve(statusList(p.acme)), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });

/** The shipped guard, trusting Acme as the root. */
const guardFor = (p: ChainParties) =>
  requireDelegation({
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: checkerFor(p),
    now,
  });

/** The guard's verdict on the sub-agent placing an order under `chain`. */
const verdictOn = (p: ChainParties, chain: DelegationChain) =>
  guardFor(p)({ meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' });

/**
 * A chain from Acme to the sub-agent with one hop for each entry of `caveats`, each hop under its
 * own: Acme to the agent, through a fresh delegate for each further hop, to the sub-agent.
 */
function chainUnder(p: ChainParties, caveats: Caveat[][]): DelegationChain {
  const delegates = [p.agent, ...caveats.slice(2).map(() => identity())].slice(0, caveats.length - 1);
  const holders = [p.acme, ...delegates, p.subAgent];
  return caveats.map((own, i) =>
    hop({
      issuer: holders[i]!,
      invoker: holders[i + 1]!.did,
      id: `urn:zcap:hop-${i}`,
      parentCapability: i === 0 ? RESOURCE : `urn:zcap:hop-${i - 1}`,
      allowedAction: ['orders.place'],
      caveats: own,
      statusIndex: 3 + i,
    }),
  );
}

describe('the verdict on a verified chain carries its effective caveats', () => {
  it('keeps the honest two-hop grant as it was, with the leaf limit beside it', async () => {
    const p = parties();
    expect(await verdictOn(p, twoHopChain(p))).toEqual({
      ok: true,
      source: 'carried',
      responsibleParty: p.acme.did,
      leafInvoker: p.subAgent.did,
      invocationTarget: RESOURCE,
      allowedAction: ['orders.place'],
      caveats: [maxAmount('100.00')],
      unknownCaveats: [],
      depth: 2,
      fresh: true,
    });
  });

  it('carries the tightest of each caveat across a three-hop chain', async () => {
    const p = parties();
    const chain = chainUnder(p, [
      [maxAmount('500.00')],
      [maxAmount('300.00'), validUntil('2026-12-15T00:00:00Z')],
      [maxAmount('100.00'), validUntil('2026-12-10T00:00:00Z')],
    ]);
    expect(await verdictOn(p, chain)).toMatchObject({
      ok: true,
      depth: 3,
      caveats: [maxAmount('100.00'), validUntil('2026-12-10T00:00:00Z')],
      unknownCaveats: [],
    });
  });

  it('carries the same caveats in what evaluateDelegationChain and validateDelegationChain find', async () => {
    const p = parties();
    const chain = chainUnder(p, [
      [maxAmount('500.00'), validUntil('2026-12-15T00:00:00Z')],
      [validUntil('2026-12-12T00:00:00Z'), maxAmount('250.00')],
      [maxAmount('100.00'), validUntil('2026-12-10T00:00:00Z')],
    ]);
    const ctx = { resource: RESOURCE, resourceOwner: p.acme.did, now, verifyHopProof: createDelegationProofVerifier({ didResolver }) };
    const effective = { caveats: [maxAmount('100.00'), validUntil('2026-12-10T00:00:00Z')], unknownCaveats: [] };
    expect(await evaluateDelegationChain(chain, checkerFor(p), ctx)).toMatchObject({ ok: true, fresh: true, ...effective });
    expect(validateDelegationChain(chain, ctx)).toMatchObject({ ok: true, ...effective });
  });

  it('carries no caveat for a chain that states none', async () => {
    const p = parties();
    expect(await verdictOn(p, chainUnder(p, [[], []]))).toMatchObject({ ok: true, caveats: [], unknownCaveats: [] });
    expect(validateDelegationChain([], { now })).toMatchObject({ ok: false, caveats: [], unknownCaveats: [] });
  });
});

describe('two caveats of one type in one hop', () => {
  it('reads the lower of two MaxAmount caveats, whichever comes first', async () => {
    const p = parties();
    const loose = chainUnder(p, [[maxAmount('500.00')], [maxAmount('1000000.00'), maxAmount('100.00')]]);
    expect(await verdictOn(p, loose)).toMatchObject({ ok: true, caveats: [maxAmount('100.00')] });
    const root = chainUnder(p, [[maxAmount('100.00'), maxAmount('1000000.00')]]);
    expect(await verdictOn(p, root)).toMatchObject({ ok: true, caveats: [maxAmount('100.00')] });
  });

  it('reads the earlier of two ValidUntil caveats', async () => {
    const p = parties();
    const chain = chainUnder(p, [[validUntil('2026-12-31T00:00:00Z'), validUntil('2026-12-01T00:00:00Z')]]);
    expect(await verdictOn(p, chain)).toMatchObject({ ok: true, caveats: [validUntil('2026-12-01T00:00:00Z')] });
  });

  it('keeps both MaxAmount caveats of different currencies, which together permit no call', async () => {
    const p = parties();
    const chain = chainUnder(p, [[maxAmount('100.00', 'USD'), maxAmount('90.00', 'EUR')]]);
    expect(await verdictOn(p, chain)).toMatchObject({ ok: true, caveats: [maxAmount('100.00', 'USD'), maxAmount('90.00', 'EUR')] });
  });

  it('keeps a MaxAmount that names no currency beside a lower one that names one', async () => {
    const p = parties();
    const anyCurrency: Caveat = { type: 'MaxAmount', limit: '100' };
    const oneHop = chainUnder(p, [[maxAmount('50'), anyCurrency]]);
    expect(await verdictOn(p, oneHop)).toMatchObject({ ok: true, caveats: [maxAmount('50'), anyCurrency] });
    const narrowed = chainUnder(p, [[anyCurrency], [maxAmount('50')]]);
    expect(await verdictOn(p, narrowed)).toMatchObject({ ok: true, caveats: [anyCurrency, maxAmount('50')] });
  });

  it('still refuses a hop none of whose duplicates narrows its parent', async () => {
    const p = parties();
    const chain = chainUnder(p, [[maxAmount('500.00')], [maxAmount('1000000.00'), maxAmount('600.00')]]);
    expect(await verdictOn(p, chain)).toMatchObject({ ok: false, status: 403, error: { code: 'delegation_invalid' }, refusalCode: 'chain_invalid' });
  });
});

describe('a caveat the library does not interpret', () => {
  const warned = Symbol.for('@kya-os/mcp/unknown-caveat-warned');
  const registry = globalThis as { [warned]?: true };
  let previous: true | undefined;

  beforeEach(() => {
    previous = registry[warned];
    delete registry[warned];
  });

  afterEach(() => {
    if (previous === undefined) delete registry[warned];
    else registry[warned] = previous;
    vi.restoreAllMocks();
  });

  it('passes the call, lists the caveat apart as written, and warns once per process', async () => {
    const p = parties();
    const approval: Caveat = { type: 'RequiresHumanApproval', approvers: 2 };
    const region: Caveat = { type: 'Region', allowed: ['EU'] };
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const chain = chainUnder(p, [[approval, maxAmount('500.00')], [approval, maxAmount('100.00'), region]]);
    const verdict = await verdictOn(p, chain);
    expect(verdict).toMatchObject({ ok: true, caveats: [approval, maxAmount('100.00'), region], unknownCaveats: [approval, region] });
    expect(await verdictOn(p, chain)).toMatchObject({ ok: true, unknownCaveats: [approval, region] });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/^\[kya-os\] .*unknownCaveats.*enforce.*or refuse/));
  });

  it('warns from a passing evaluateDelegationChain, but never from validateDelegationChain', async () => {
    const p = parties();
    const approval: Caveat = { type: 'RequiresHumanApproval', approvers: 2 };
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const chain = chainUnder(p, [[approval], [approval]]);
    const ctx = { resource: RESOURCE, resourceOwner: p.acme.did, now, verifyHopProof: createDelegationProofVerifier({ didResolver }) };
    expect(validateDelegationChain(chain, ctx)).toMatchObject({ ok: true, unknownCaveats: [approval] });
    expect(warn).not.toHaveBeenCalled();
    expect(await evaluateDelegationChain(chain, checkerFor(p), ctx)).toMatchObject({ ok: true, unknownCaveats: [approval] });
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('does not warn for a chain refused as untrusted_root, or refused by evaluateDelegationChain', async () => {
    const p = parties();
    const approval: Caveat = { type: 'RequiresHumanApproval', approvers: 2 };
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const chain = chainUnder(p, [[approval], [approval]]);
    const untrusted = requireDelegation({
      resource: RESOURCE,
      trustedRootIssuers: [identity().did],
      verifyHopProof: createDelegationProofVerifier({ didResolver }),
      checkRevocation: checkerFor(p),
      now,
    });
    expect(await untrusted({ meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' })).toMatchObject({
      ok: false,
      refusalCode: 'untrusted_root',
    });
    const revoked = createRevocationChecker({ fetch: serve(statusList(p.acme, [3])), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });
    const ctx = { resource: RESOURCE, resourceOwner: p.acme.did, now, verifyHopProof: createDelegationProofVerifier({ didResolver }) };
    expect(await evaluateDelegationChain(chain, revoked, ctx)).toMatchObject({ ok: false });
    expect(warn).not.toHaveBeenCalled();
  });

  it('treats a type written in another case as one it does not know', async () => {
    const p = parties();
    const odd: Caveat = { type: 'maxAmount', limit: '1', currency: 'USD' };
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    expect(await verdictOn(p, chainUnder(p, [[odd], [odd]]))).toMatchObject({ ok: true, caveats: [odd], unknownCaveats: [odd] });
  });

  it('treats a known type with a member it does not know as one it does not interpret, kept as written', async () => {
    const p = parties();
    const daily: Caveat = { type: 'MaxAmount', limit: '100', currency: 'USD', per: 'day' };
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    // Neither stands in for the other: the tighter plain limit does not absorb the daily one, nor it the plain one.
    const both = chainUnder(p, [[daily], [daily, maxAmount('50')]]);
    expect(await verdictOn(p, both)).toMatchObject({ ok: true, caveats: [daily, maxAmount('50')], unknownCaveats: [daily] });
    const looser = chainUnder(p, [[daily, maxAmount('500')]]);
    expect(await verdictOn(p, looser)).toMatchObject({ ok: true, caveats: [daily, maxAmount('500')], unknownCaveats: [daily] });
  });

  it('holds a hop to replicate such a caveat verbatim, as one of a type it does not know', async () => {
    const p = parties();
    const daily: Caveat = { type: 'MaxAmount', limit: '100', currency: 'USD', per: 'day' };
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    // A narrower limit that drops the member it does not know may widen it, so it is no narrowing.
    const dropped = chainUnder(p, [[daily], [maxAmount('50')]]);
    expect(await verdictOn(p, dropped)).toMatchObject({ ok: false, refusalCode: 'chain_invalid' });
    const restated = chainUnder(p, [[daily], [{ ...daily, limit: '50' }]]);
    expect(await verdictOn(p, restated)).toMatchObject({ ok: false, refusalCode: 'chain_invalid' });
  });

  it('does not warn for a chain whose every caveat it knows', async () => {
    const p = parties();
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    expect(await verdictOn(p, twoHopChain(p))).toMatchObject({ ok: true, unknownCaveats: [] });
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('a ValidUntil caveat that is not a date', () => {
  it.each<[string, Caveat, string]>([
    ['states no date', { type: 'ValidUntil' }, 'hop 0: ValidUntil caveat states no date'],
    ['states a date that is not RFC 3339', { type: 'ValidUntil', date: 'next Tuesday' }, 'hop 0: ValidUntil caveat "next Tuesday" is not an RFC 3339 date-time with a time zone'],
  ])('is refused as malformed when it %s', async (_label, caveat, reason) => {
    const p = parties();
    const chain = chainUnder(p, [[caveat]]);
    expect(validateDelegationChain(chain, { now })).toMatchObject({ ok: false, code: 'delegation_malformed', reasons: [reason] });
    expect(await verdictOn(p, chain)).toEqual({
      ok: false,
      status: 403,
      error: { code: 'delegation_invalid', message: 'the delegation chain does not authorize this caller', reasons: [reason] },
      refusalCode: 'delegation_malformed',
      transient: false,
    });
  });
});
