/**
 * The form of each caveat of a type the library knows (SPEC.md §6.10). A `ValidUntil` states a
 * date, an RFC 3339 date-time with its zone. A `MaxAmount` states its `limit` as a plain
 * non-negative decimal, compared exactly, and a `currency`, when it names one, as a string. A caveat
 * of either type in any other form can never be narrowed or held to, so it is malformed wherever it
 * sits in the chain, and the chain is refused as `delegation_malformed` before any other rule is
 * named. A type written in another case is a type the library does not know, not a malformed one.
 * Every case goes through `@kya-os/mcp/card`.
 */

import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  validateDelegationChain,
  type Caveat,
  type DelegationChain,
} from '../index.js';
import { NOW_MS, RESOURCE, hop, parties, serve, statusList, type ChainParties } from './signed-chain-helpers.js';

const now = (): number => NOW_MS;
const didResolver = createDidKeyResolver();

/** Acme to the agent under `rootCaveats`, then the agent to the sub-agent under `leafCaveats`. */
const twoHops = (p: ChainParties, rootCaveats: Caveat[], leafCaveats: Caveat[]): DelegationChain => [
  hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:root', parentCapability: RESOURCE, allowedAction: ['orders.place'], caveats: rootCaveats, statusIndex: 3 }),
  hop({ issuer: p.agent, invoker: p.subAgent.did, id: 'urn:zcap:leaf', parentCapability: 'urn:zcap:root', allowedAction: ['orders.place'], caveats: leafCaveats, statusIndex: 7 }),
];

const guardFor = (p: ChainParties) =>
  requireDelegation({
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: createRevocationChecker({ fetch: serve(statusList(p.acme)), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) }),
    now,
  });

const NOT_A_DECIMAL = 'is not a non-negative decimal';

describe('a malformed MaxAmount caveat', () => {
  it.each<[string, Caveat, string]>([
    ['states no limit', { type: 'MaxAmount', currency: 'USD' }, 'MaxAmount caveat states no limit'],
    ['states a limit that is not a number', { type: 'MaxAmount', limit: 'abc', currency: 'USD' }, `MaxAmount caveat limit "abc" ${NOT_A_DECIMAL}`],
    ['states a negative limit', { type: 'MaxAmount', limit: '-5', currency: 'USD' }, `MaxAmount caveat limit "-5" ${NOT_A_DECIMAL}`],
    ['states a limit with white space around it', { type: 'MaxAmount', limit: ' 100 ', currency: 'USD' }, `MaxAmount caveat limit " 100 " ${NOT_A_DECIMAL}`],
    ['states a limit in exponent form', { type: 'MaxAmount', limit: '1e3', currency: 'USD' }, `MaxAmount caveat limit "1e3" ${NOT_A_DECIMAL}`],
    ['states a limit with a point and no fraction', { type: 'MaxAmount', limit: '100.', currency: 'USD' }, `MaxAmount caveat limit "100." ${NOT_A_DECIMAL}`],
    ['states a limit that is not a string', { type: 'MaxAmount', limit: 100 as unknown as string }, `MaxAmount caveat limit of type number ${NOT_A_DECIMAL}`],
    ['states a currency that is not a string', { type: 'MaxAmount', limit: '100', currency: 5 as unknown as string }, 'MaxAmount caveat currency of type number is not a string'],
  ])('is refused on the root, before the hop below it is compared, when it %s', (_label, caveat, reason) => {
    const p = parties();
    const result = validateDelegationChain(twoHops(p, [caveat], [{ type: 'MaxAmount', limit: '50', currency: 'USD' }]), { now });
    expect(result).toMatchObject({ ok: false, code: 'delegation_malformed' });
    expect(result.reasons[0]).toBe(`hop 0: ${reason}`);
  });

  it('is refused on the leaf', () => {
    const p = parties();
    const result = validateDelegationChain(twoHops(p, [], [{ type: 'MaxAmount', limit: '1e3' }]), { now });
    expect(result).toMatchObject({ ok: false, code: 'delegation_malformed', reasons: [`hop 1: MaxAmount caveat limit "1e3" ${NOT_A_DECIMAL}`] });
  });

  it('is refused by the guard, as a chain that does not authorize the caller', async () => {
    const p = parties();
    const chain = twoHops(p, [{ type: 'MaxAmount', limit: 'abc', currency: 'USD' }], [{ type: 'MaxAmount', limit: 'abc', currency: 'USD' }]);
    expect(await guardFor(p)({ meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' })).toMatchObject({
      ok: false,
      status: 403,
      error: { code: 'delegation_invalid' },
      refusalCode: 'delegation_malformed',
    });
  });

  it('is malformed whatever other members it states, so a member the library does not know never excuses it', () => {
    const p = parties();
    const result = validateDelegationChain(twoHops(p, [], [{ type: 'MaxAmount', per: 'day' }]), { now });
    expect(result).toMatchObject({ ok: false, code: 'delegation_malformed', reasons: ['hop 1: MaxAmount caveat states no limit'] });
  });
});

describe('a malformed ValidUntil caveat', () => {
  it('on a hop above the leaf is the first rule the chain breaks, ahead of the narrowing it also breaks', () => {
    const p = parties();
    const result = validateDelegationChain(twoHops(p, [{ type: 'ValidUntil' }], [{ type: 'ValidUntil', date: '2026-12-01T00:00:00Z' }]), { now });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('delegation_malformed');
    expect(result.reasons[0]).toBe('hop 0: ValidUntil caveat states no date');
  });

  it('is refused by the guard on a hop above the leaf', async () => {
    const p = parties();
    const chain = twoHops(p, [{ type: 'ValidUntil' }], [{ type: 'ValidUntil' }]);
    expect(await guardFor(p)({ meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' })).toMatchObject({
      ok: false,
      error: { code: 'delegation_invalid', reasons: ['hop 0: ValidUntil caveat states no date', 'hop 1: ValidUntil caveat states no date', expect.any(String)] },
      refusalCode: 'delegation_malformed',
    });
  });

  it('with a member the library does not know is still read for its date, and refused once it has passed', () => {
    const p = parties();
    const result = validateDelegationChain(twoHops(p, [], [{ type: 'ValidUntil', date: '2026-01-01T00:00:00Z', note: 'quarter end' }]), { now });
    expect(result).toMatchObject({ ok: false, code: 'delegation_expired', reasons: ['hop 1: expired caveat (ValidUntil 2026-01-01T00:00:00Z is in the past)'] });
  });
});

describe('a caveat type written in another case', () => {
  it('is a type the library does not know: passed on as written, not malformed', () => {
    const p = parties();
    const odd: Caveat = { type: 'maxAmount', limit: 'abc' };
    const result = validateDelegationChain(twoHops(p, [odd], [odd]), { now });
    expect(result).toMatchObject({ ok: true, caveats: [odd], unknownCaveats: [odd] });
  });
});
