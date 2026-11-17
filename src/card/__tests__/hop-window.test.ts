/**
 * The window of each Entity Card delegation hop (`../hop-window.ts`): its `validFrom`, its
 * `validUntil` and each `ValidUntil` caveat are RFC 3339 date-times with their zone, read as one
 * instant wherever they are read, and each is held with the clock tolerance, `maxClockSkewMs`, as a
 * status list's window is. Every case goes through `@kya-os/mcp/card` as an adopter calls it.
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
  type DelegationChain,
  type DelegationChainContext,
  type DelegationCredential,
  type VerifyRequestDelegationDeps,
} from '../index.js';
import { NOW_MS, RESOURCE, hop, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';

const SECOND = 1000;
const p = parties();
const at = (offsetMs: number): string => new Date(NOW_MS + offsetMs).toISOString();
const now = (): number => NOW_MS;

/** A one-hop chain whose root states `fields` over the default root, so no re-delegation narrows it. */
const rootWith = (fields: Partial<DelegationCredential>): DelegationChain => [
  { ...hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:acme-root', parentCapability: RESOURCE, allowedAction: ['orders.place'] }), ...fields },
];

/** A one-hop chain whose root carries a `ValidUntil` caveat of `date`. */
const rootUntilCaveat = (date: string): DelegationChain => [
  hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:acme-root', parentCapability: RESOURCE, allowedAction: ['orders.place'], caveats: [{ type: 'ValidUntil', date }] }),
];

/** The verdict of the card profile's chain rules, its code and reasons. */
const verdictOf = (chain: DelegationChain, ctx: DelegationChainContext = { now }) => {
  const result = validateDelegationChain(chain, ctx);
  return { ok: result.ok, code: result.code, reasons: result.reasons };
};

const NOT_A_DATE = 'is not an RFC 3339 date-time with a time zone';

describe('a hop window', () => {
  it.each<[string, DelegationChain]>([
    ['a validFrom 2 seconds ahead, as on a hop just issued by a server whose clock runs ahead', rootWith({ validFrom: at(2 * SECOND) })],
    ['a validFrom 120 seconds ahead, the tolerance exactly', rootWith({ validFrom: at(120 * SECOND) })],
    ['a validUntil 2 seconds ago', rootWith({ validUntil: at(-2 * SECOND) })],
    ['a ValidUntil caveat 2 seconds ago', rootUntilCaveat(at(-2 * SECOND))],
    ['a validFrom and validUntil at offsets from UTC', rootWith({ validFrom: '2026-11-03T18:00:00-06:00', validUntil: '2026-11-05T05:30:00+05:30' })],
  ])('is read with %s', (_label, chain) => {
    expect(verdictOf(chain)).toEqual({ ok: true, code: undefined, reasons: [] });
  });

  it.each<[string, DelegationChain, string, string]>([
    ['a validFrom more than 120 seconds ahead', rootWith({ validFrom: at(121 * SECOND) }), 'delegation_not_yet_valid', `hop 0: not yet valid (validFrom ${at(121 * SECOND)} is in the future)`],
    ['a validUntil more than 120 seconds ago', rootWith({ validUntil: at(-121 * SECOND) }), 'delegation_expired', `hop 0: expired (validUntil ${at(-121 * SECOND)} is in the past)`],
    ['a ValidUntil caveat more than 120 seconds ago', rootUntilCaveat(at(-121 * SECOND)), 'delegation_expired', `hop 0: expired caveat (ValidUntil ${at(-121 * SECOND)} is in the past)`],
    ['a validFrom with no zone, which names no single instant', rootWith({ validFrom: '2026-11-03T00:00:00' }), 'delegation_malformed', `hop 0: validFrom "2026-11-03T00:00:00" ${NOT_A_DATE}`],
    ['a validUntil with no zone', rootWith({ validUntil: '2026-12-01T00:00:00.000' }), 'delegation_malformed', `hop 0: validUntil "2026-12-01T00:00:00.000" ${NOT_A_DATE}`],
    ['a validUntil that is a date alone', rootWith({ validUntil: '2026-12-01' }), 'delegation_malformed', `hop 0: validUntil "2026-12-01" ${NOT_A_DATE}`],
    ['a ValidUntil caveat that is an HTTP date', rootUntilCaveat('Tue, 01 Dec 2026 00:00:00 GMT'), 'delegation_malformed', `hop 0: ValidUntil caveat "Tue, 01 Dec 2026 00:00:00 GMT" ${NOT_A_DATE}`],
    ['a validUntil no calendar has', rootWith({ validUntil: '2026-11-31T00:00:00Z' }), 'delegation_malformed', `hop 0: validUntil "2026-11-31T00:00:00Z" ${NOT_A_DATE}`],
  ])('is refused with %s, saying so', (_label, chain, code, reason) => {
    const verdict = verdictOf(chain);
    expect(verdict.ok).toBe(false);
    expect(verdict.code).toBe(code);
    expect(verdict.reasons).toContain(reason);
  });

  it('holds each bound with the tolerance the context gives, exactly with none', () => {
    expect(verdictOf(rootWith({ validFrom: at(1) }), { now, maxClockSkewMs: 0 }).code).toBe('delegation_not_yet_valid');
    expect(verdictOf(rootWith({ validUntil: at(-1) }), { now, maxClockSkewMs: 0 }).code).toBe('delegation_expired');
    expect(verdictOf(rootWith({ validFrom: at(300 * SECOND) }), { now, maxClockSkewMs: 300_000 }).ok).toBe(true);
  });

  it.each([-1, Number.NaN, 600_001])('refuses a chain under a maxClockSkewMs of %s as configuration_error', (maxClockSkewMs) => {
    const verdict = verdictOf(rootWith({}), { now, maxClockSkewMs });
    expect(verdict.code).toBe('configuration_error');
    expect(verdict.reasons.join()).toMatch(/^maxClockSkewMs must be a number of milliseconds from 0 to 600000/);
  });

  it('refuses a child whose validUntil states no zone as no narrowing of its parent', () => {
    const [root, leaf] = twoHopChain(p);
    const verdict = verdictOf([root, { ...leaf, validUntil: '2026-12-01T00:00:00' }]);
    expect(verdict.ok).toBe(false);
    expect(verdict.reasons).toContain(`hop 1: validUntil "2026-12-01T00:00:00" ${NOT_A_DATE}`);
    expect(verdict.reasons.some((reason) => /validUntil broadened/.test(reason))).toBe(true);
  });
});

describe("requireDelegation's maxClockSkewMs", () => {
  const didResolver = createDidKeyResolver();
  const chain = twoHopChain(p);
  /** Two seconds past the chain's validUntil, 2027-01-01T00:00:00Z. */
  const justAfter = (): number => Date.parse('2027-01-01T00:00:02Z');
  const guard = (overrides: Partial<VerifyRequestDelegationDeps>) =>
    requireDelegation({
      resource: RESOURCE,
      trustedRootIssuers: [p.acme.did],
      verifyHopProof: createDelegationProofVerifier({ didResolver }),
      checkRevocation: createRevocationChecker({ fetch: serve(statusList(p.acme, [])), now: justAfter, verifyStatusList: createStatusListProofVerifier({ didResolver }) }),
      now: justAfter,
      ...overrides,
    });
  const input = { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' };

  it('reads a chain 2 seconds past its validUntil within the default tolerance', async () => {
    expect((await guard({})(input)).ok).toBe(true);
  });

  it('holds the chain to the tolerance it is given', async () => {
    const result = await guard({ maxClockSkewMs: 0 })(input);
    expect(result.ok).toBe(false);
    expect(result.ok ? undefined : result.refusalCode).toBe('delegation_expired');
  });

  it.each([-1, Number.NaN, 600_001, '120000'])('throws a TypeError naming the option, when built, for %s', (maxClockSkewMs) => {
    expect(() => guard({ maxClockSkewMs: maxClockSkewMs as number })).toThrow(
      /^\[kya-os\] maxClockSkewMs must be a number of milliseconds from 0 to 600000/,
    );
  });
});
