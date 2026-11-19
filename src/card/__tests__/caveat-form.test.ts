/**
 * The form of each caveat of a type the library knows (SPEC.md §6.10). A `ValidUntil` states a
 * date, an RFC 3339 date-time with its zone. A `MaxAmount` states its `limit` as a plain
 * non-negative decimal, compared exactly, and a `currency`, when it names one, as a string. A caveat
 * of either type in any other form can never be narrowed or held to, so it is malformed wherever it
 * sits in the chain, and the chain is refused as `delegation_malformed` before any other rule is
 * named. A caveat of any type that nests its arrays and objects deeper than a credential may is
 * malformed too, refused before anything reads it whole, so no depth makes the guard throw. A type
 * written in another case is a type the library does not know, not a malformed one. A reason
 * quotes at most 64 characters of a date. Every case goes through `@kya-os/mcp/card`.
 */

import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { MAX_CREDENTIAL_NESTING_DEPTH } from '../../delegation/signed-form.js';
import {
  attenuates,
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  validateDelegationChain,
  verifyRequestDelegation,
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

const depsFor = (p: ChainParties) => ({
  resource: RESOURCE,
  trustedRootIssuers: [p.acme.did],
  verifyHopProof: createDelegationProofVerifier({ didResolver }),
  checkRevocation: createRevocationChecker({ fetch: serve(statusList(p.acme)), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) }),
  now,
});
const guardFor = (p: ChainParties) => requireDelegation(depsFor(p));

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
    expect(result).toMatchObject({ ok: false, code: 'delegation_expired', reasons: ['hop 1: expired caveat (ValidUntil "2026-01-01T00:00:00Z" is in the past)'] });
  });

  it('is named by at most 64 characters of its date, however long its fraction of a second', () => {
    const p = parties();
    const date = `2026-01-01T00:00:00.${'0'.repeat(1_000_000)}Z`;
    const result = validateDelegationChain(twoHops(p, [], [{ type: 'ValidUntil', date }]), { now });
    expect(result).toMatchObject({ ok: false, code: 'delegation_expired', reasons: [`hop 1: expired caveat (ValidUntil "${date.slice(0, 64)}"... is in the past)`] });
  });
});

describe('a caveat nested deeper than a credential may nest', () => {
  /** A caveat of `type` whose `value` nests arrays `levels` deep, so the caveat nests one level more. */
  const nestedCaveat = (type: string, levels: number): Caveat => {
    let value: unknown = 'x';
    for (let i = 0; i < levels; i += 1) value = [value];
    return { type, value };
  };
  const tooDeep = (type: string) => `caveat ${JSON.stringify(type)} nests more than ${MAX_CREDENTIAL_NESTING_DEPTH} levels deep`;
  /** Each hop of `chain` with `caveats` set after it was signed, as no signer reads a value that deep. */
  const under = (chain: DelegationChain, caveats: Caveat[]): DelegationChain =>
    chain.map((vc) => ({ ...vc, credentialSubject: { ...vc.credentialSubject, caveats } }));

  it('is read as written up to that depth, and refused as malformed one level deeper', () => {
    const p = parties();
    const deepest = nestedCaveat('Custom', MAX_CREDENTIAL_NESTING_DEPTH - 1);
    expect(validateDelegationChain(twoHops(p, [deepest], [deepest]), { now })).toMatchObject({ ok: true, unknownCaveats: [deepest] });
    const over = nestedCaveat('Custom', MAX_CREDENTIAL_NESTING_DEPTH);
    expect(validateDelegationChain(twoHops(p, [over], [over]), { now })).toMatchObject({
      ok: false,
      code: 'delegation_malformed',
      // A malformed caveat narrows nothing and nothing narrows it, so the hop below breaks that rule too.
      reasons: [`hop 0: ${tooDeep('Custom')}`, `hop 1: ${tooDeep('Custom')}`, 'caveat "Custom" broadened or dropped by child (monotone-narrowing violated)'],
    });
  });

  it('is refused, never thrown, however deep, on one hop, on every hop, and by the hop rules', () => {
    const p = parties();
    const deep = nestedCaveat('Custom', 20_000);
    const oneHop = under(twoHops(p, [], []).slice(0, 1), [deep]);
    expect(validateDelegationChain(oneHop, { now })).toMatchObject({ ok: false, code: 'delegation_malformed', reasons: [`hop 0: ${tooDeep('Custom')}`] });
    const known = { ...nestedCaveat('MaxAmount', 20_000), limit: '100' };
    expect(validateDelegationChain(under(twoHops(p, [], []), [known]), { now })).toMatchObject({
      ok: false,
      code: 'delegation_malformed',
      reasons: [`hop 0: ${tooDeep('MaxAmount')}`, `hop 1: ${tooDeep('MaxAmount')}`, expect.any(String)],
    });
    const [root, leaf] = under(twoHops(p, [], []), [deep]);
    expect(attenuates(root!, leaf!)).toEqual(['caveat "Custom" broadened or dropped by child (monotone-narrowing violated)']);
  });

  it('is refused by verifyRequestDelegation and requireDelegation before any proof is read, which resolve rather than reject', async () => {
    const p = parties();
    // Set after signing: the chain rules run before any proof, so the proof is never read.
    const chain = under(twoHops(p, [], []).slice(0, 1), [nestedCaveat('Custom', 20_000)]);
    const input = { meta: toDelegationChainMeta(chain), proofDid: p.agent.did, action: 'orders.place' };
    const reasons = [`hop 0: ${tooDeep('Custom')}`];
    expect(await verifyRequestDelegation(input, depsFor(p))).toMatchObject({ ok: false, code: 'delegation_invalid', refusalCode: 'delegation_malformed', reasons });
    expect(await guardFor(p)(input)).toMatchObject({ ok: false, status: 403, refusalCode: 'delegation_malformed', error: { reasons } });
  });
});

describe('a caveat type written in another case', () => {
  it('is a type the library does not know: passed on as written, not malformed', () => {
    const p = parties();
    const odd: Caveat = { type: 'maxAmount', limit: 'abc' };
    const result = validateDelegationChain(twoHops(p, [odd], [odd]), { now });
    expect(result).toMatchObject({ ok: true, caveats: [odd, { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' }], unknownCaveats: [odd] });
  });
});
