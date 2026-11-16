/**
 * A verifier that accepts a delegation chain from a caller must say whose authority it trusts.
 * `trustedRootIssuers` names the DIDs allowed to grant authority, and `resourceOwner` the one DID
 * that owns the resource; with neither, `requireDelegation` and `verifyRequestDelegation` would
 * accept a chain rooted anywhere, including one an agent signs for itself. So outside development
 * they refuse to run until one is set, unless `allowAnyRootIssuer: true` opts out by name; in
 * development, and with the opt-out, they run and warn once. Every test goes through the
 * `@kya-os/mcp/card` entry (`../index.js`), as an adopter would.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { logger } from '../../logging/index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  requireDelegation,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type DelegationChain,
  type RequestDelegationInput,
  type VerifyRequestDelegationDeps,
} from '../index.js';
import {
  NOW_MS,
  RESOURCE,
  hop,
  parties,
  serve,
  statusList,
  twoHopChain,
  type ChainParties,
  type TestIdentity,
} from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();

/** What every trust-root warning of the Card says, whichever setting let it run. */
const WARNING = 'neither trustedRootIssuers nor resourceOwner is set';

/** Every fix a refusal names, in the order it names them. */
const FIXES =
  'Set trustedRootIssuers to the DIDs allowed to grant authority, or resourceOwner to the DID that owns the ' +
  'resource; in local development, set development: true; to accept any issuer anyway, set allowAnyRootIssuer: true.';

/** The refusal `entry` throws with neither pin, outside development and without the opt-out. */
const refusal = (entry: string) =>
  `[kya-os] ${WARNING}, so ${entry} would accept a delegation from any issuer, including one an agent signs ` +
  `for itself. ${FIXES}`;

/** The warning logged once when nothing pins the root, saying `why` it may run anyway. */
const warning = (why: string) =>
  `[kya-os] ${WARNING}, so a delegation from any issuer is accepted, including one an agent signs for itself, ` +
  `because ${why}. Set trustedRootIssuers to the DIDs allowed to grant authority, or resourceOwner to the DID ` +
  'that owns the resource.';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** Watch the logger, and return the trust-root warnings logged since. */
function watchWarnings(): () => string[] {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  return () => warn.mock.calls.map(([message]) => String(message)).filter((message) => message.includes(WARNING));
}

/** The shipped wiring for the parties `p`, pinning no root, with `options` over it. */
function verifier(p: ChainParties, options: Partial<VerifyRequestDelegationDeps> = {}): VerifyRequestDelegationDeps {
  return {
    resource: RESOURCE,
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: createRevocationChecker({
      fetch: serve(statusList(p.acme)),
      now: () => NOW_MS,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    }),
    now: () => NOW_MS,
    ...options,
  };
}

/** A one-hop chain `agent` signs to itself for `orders.place`: authority from no one. */
const selfIssued = (agent: TestIdentity): DelegationChain => [
  hop({
    issuer: agent,
    invoker: agent.did,
    id: 'urn:zcap:self',
    parentCapability: RESOURCE,
    allowedAction: ['orders.place'],
  }),
];

/** The request that carries `chain` for `caller`. */
const carrying = (chain: DelegationChain, caller: TestIdentity): RequestDelegationInput => ({
  meta: toDelegationChainMeta(chain),
  proofDid: caller.did,
  action: 'orders.place',
});

/** Whether a guard built from `deps` lets through a request carrying Acme's chain, and a self-issued one. */
async function guardAccepts(p: ChainParties, deps: VerifyRequestDelegationDeps) {
  const guard = requireDelegation(deps);
  const listed = await guard(carrying(twoHopChain(p), p.subAgent));
  const self = await guard(carrying(selfIssued(p.subAgent), p.subAgent));
  return { listed: listed.ok, self: self.ok };
}

describe('with neither trustedRootIssuers nor resourceOwner set', () => {
  it('requireDelegation throws when the guard is built, naming every fix', () => {
    expect(() => requireDelegation(verifier(parties()))).toThrow(new Error(refusal('requireDelegation')));
  });

  it('verifyRequestDelegation rejects the call, naming every fix, before it reads the chain', async () => {
    const p = parties();
    const resolveDelegationChain = vi.fn(async () => twoHopChain(p));
    await expect(
      verifyRequestDelegation({ meta: {}, proofDid: p.subAgent.did, action: 'orders.place' }, verifier(p, { resolveDelegationChain })),
    ).rejects.toThrow(new Error(refusal('verifyRequestDelegation')));
    expect(resolveDelegationChain).not.toHaveBeenCalled();
  });

  it('throws the same under NODE_ENV=production', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => requireDelegation(verifier(parties()))).toThrow(new Error(refusal('requireDelegation')));
  });

  it('throws the same with allowAnyRootIssuer: false', () => {
    expect(() => requireDelegation(verifier(parties(), { allowAnyRootIssuer: false }))).toThrow(
      new Error(refusal('requireDelegation')),
    );
  });
});

describe('with the root pinned', () => {
  it('trustedRootIssuers runs silently, accepts a chain from a listed root and refuses a self-issued one', async () => {
    const warnings = watchWarnings();
    const p = parties();
    expect(await guardAccepts(p, verifier(p, { trustedRootIssuers: [p.acme.did] }))).toEqual({ listed: true, self: false });
    expect(warnings()).toEqual([]);
  });

  it('resourceOwner runs silently, accepts a chain from the owner and refuses a self-issued one', async () => {
    const warnings = watchWarnings();
    const p = parties();
    expect(await guardAccepts(p, verifier(p, { resourceOwner: p.acme.did }))).toEqual({ listed: true, self: false });
    expect(warnings()).toEqual([]);
  });

  it('an empty trustedRootIssuers is valid and trusts no root', async () => {
    const p = parties();
    expect(await guardAccepts(p, verifier(p, { trustedRootIssuers: [] }))).toEqual({ listed: false, self: false });
  });

  it('allowAnyRootIssuer: false beside a pin changes nothing', async () => {
    const p = parties();
    const deps = verifier(p, { trustedRootIssuers: [p.acme.did], allowAnyRootIssuer: false });
    expect(await guardAccepts(p, deps)).toEqual({ listed: true, self: false });
  });
});

describe('allowAnyRootIssuer: true', () => {
  it('runs, accepts a chain from any root and warns once per guard, when it is built', async () => {
    const warnings = watchWarnings();
    const p = parties();
    const deps = verifier(p, { allowAnyRootIssuer: true });
    const guard = requireDelegation(deps);
    expect(warnings()).toEqual([warning('allowAnyRootIssuer is true')]);
    for (let call = 0; call < 2; call += 1) {
      expect((await guard(carrying(selfIssued(p.subAgent), p.subAgent))).ok).toBe(true);
    }
    expect(warnings()).toHaveLength(1);
    requireDelegation(deps);
    expect(warnings()).toHaveLength(2);
  });

  it('verifyRequestDelegation warns once per deps object, however often it is called', async () => {
    const warnings = watchWarnings();
    const p = parties();
    const deps = verifier(p, { allowAnyRootIssuer: true });
    for (let call = 0; call < 3; call += 1) {
      expect((await verifyRequestDelegation(carrying(selfIssued(p.subAgent), p.subAgent), deps)).ok).toBe(true);
    }
    expect(warnings()).toEqual([warning('allowAnyRootIssuer is true')]);
    await verifyRequestDelegation(carrying(selfIssued(p.subAgent), p.subAgent), { ...deps });
    expect(warnings()).toHaveLength(2);
  });

  it('is refused beside trustedRootIssuers, an empty list included, or resourceOwner', () => {
    const p = parties();
    const list =
      '[kya-os] allowAnyRootIssuer is true and trustedRootIssuers is set, and they contradict each other: the list ' +
      'names the only issuers to trust, and allowAnyRootIssuer trusts every issuer. Set one or the other.';
    for (const trustedRootIssuers of [[p.acme.did], []]) {
      expect(() => requireDelegation(verifier(p, { allowAnyRootIssuer: true, trustedRootIssuers }))).toThrow(new TypeError(list));
    }
    expect(() => requireDelegation(verifier(p, { allowAnyRootIssuer: true, resourceOwner: p.acme.did }))).toThrow(
      new TypeError(
        '[kya-os] allowAnyRootIssuer is true and resourceOwner is set, and they contradict each other: resourceOwner ' +
          'names the only issuer to trust, and allowAnyRootIssuer trusts every issuer. Set one or the other.',
      ),
    );
  });

  it('must be true or false', async () => {
    const p = parties();
    const cases: [unknown, string][] = [
      ['true', 'a value "true"'],
      [1, 'a value of type number'],
      [null, 'a value of type null'],
    ];
    for (const [value, got] of cases) {
      const deps = verifier(p, { allowAnyRootIssuer: value as boolean });
      const error = new TypeError(`[kya-os] allowAnyRootIssuer must be true or false (got ${got})`);
      expect(() => requireDelegation(deps)).toThrow(error);
      await expect(verifyRequestDelegation(carrying(selfIssued(p.subAgent), p.subAgent), deps)).rejects.toThrow(error);
    }
  });
});

describe('development: true', () => {
  it('runs, accepts a chain from any root and warns once, saying the guard throws outside development', async () => {
    const warnings = watchWarnings();
    const p = parties();
    const guard = requireDelegation(verifier(p, { development: true }));
    expect((await guard(carrying(selfIssued(p.subAgent), p.subAgent))).ok).toBe(true);
    expect(warnings()).toEqual([
      warning('development is true; outside development, requireDelegation throws without one of them'),
    ]);
  });

  it('names allowAnyRootIssuer as the reason when both are set', () => {
    const warnings = watchWarnings();
    requireDelegation(verifier(parties(), { development: true, allowAnyRootIssuer: true }));
    expect(warnings()).toEqual([warning('allowAnyRootIssuer is true')]);
  });

  it('throws under NODE_ENV=production, naming the fixes, even beside a pin', () => {
    vi.stubEnv('NODE_ENV', 'production');
    const p = parties();
    const production = new Error(
      'VerifyRequestDelegationDeps.development is true while NODE_ENV is "production": development: true accepts a ' +
        'delegation from any issuer and must never run in production. Remove it, and set trustedRootIssuers to the ' +
        'DIDs allowed to grant authority, or resourceOwner to the DID that owns the resource; to accept any issuer ' +
        'anyway, set allowAnyRootIssuer: true.',
    );
    expect(() => requireDelegation(verifier(p, { development: true }))).toThrow(production);
    expect(() => requireDelegation(verifier(p, { development: true, trustedRootIssuers: [p.acme.did] }))).toThrow(production);
  });

  it('must be true or false', () => {
    expect(() => requireDelegation(verifier(parties(), { development: 'yes' as unknown as boolean }))).toThrow(
      new TypeError('VerifyRequestDelegationDeps.development must be true or false'),
    );
  });
});
