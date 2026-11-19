/**
 * A delegation chain may be any length: `verifyRequestDelegation` and `requireDelegation` put no
 * limit on it unless the host sets `maxChainLength`. Depth is not what a hostile presenter can
 * spend, because of the order the check keeps. The root must be one the host trusts before
 * anything is read; each hop's issuer is the party the hop before it, already verified, delegated
 * to; status lists are read only once every hop's proof holds; and the first failure ends the
 * walk. So nothing is fetched that a trusted root's own line of delegation did not vouch for, and a
 * delegate that adds hops naming other parties' hosts gets one of them asked, not all.
 *
 * What the hosts a chain's own signers run can still spend is time, by each answering just inside
 * its own deadline. One budget for the whole check, `totalTimeoutMs` (30 seconds by default),
 * ends that: the check is refused as `deadline_exceeded` and asks nothing more.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { REFUSED_TIMEOUTS, settledAfter, timeoutTypeError } from '../../__tests__/utils/deadlines.js';
import { codedAs } from '../../__tests__/utils/refusal-coding.js';
import { createDidKeyResolver, logger, type DIDResolver } from '../../index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateDelegationChain,
  evaluateRevocationChain,
  MAX_DELEGATION_DEPTH,
  readDelegationChain,
  requireDelegation,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type DelegationCredential,
  type SafeFetch,
  type VerifyRequestDelegationDeps,
} from '../index.js';
import { NOW_MS, RESOURCE, hop, identity, now, statusList, webIdentity, type TestIdentity } from './signed-chain-helpers.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** A chain over `signers`, root first, each delegating to the next, with a status entry at `listOf(k)` when given. */
function chainOver(signers: readonly TestIdentity[], listOf?: (hop: number) => string): DelegationCredential[] {
  return signers.slice(0, -1).map((issuer, k) =>
    hop({
      issuer,
      invoker: signers[k + 1]!.did,
      id: `urn:zcap:hop-${k}`,
      parentCapability: k === 0 ? RESOURCE : `urn:zcap:hop-${k - 1}`,
      allowedAction: ['orders.place'],
      ...(listOf === undefined ? {} : { statusIndex: k, statusListCredential: listOf(k) }),
    }),
  );
}

/** `count` new did:key parties. */
const keyParties = (count: number): TestIdentity[] => Array.from({ length: count }, identity);

/** What presents `chain` as its leaf delegate. */
const presenting = (chain: DelegationCredential[], leaf: TestIdentity) => ({
  meta: toDelegationChainMeta(chain),
  proofDid: leaf.did,
  action: 'orders.place',
});

const didKeys = createDidKeyResolver();
const clear = async () => ({ revoked: false, fresh: true });

/** The verifier's options for a chain under `root`, with `overrides`. */
const depsUnder = (root: TestIdentity, overrides: Partial<VerifyRequestDelegationDeps> = {}): VerifyRequestDelegationDeps => ({
  resource: RESOURCE,
  trustedRootIssuers: [root.did],
  verifyHopProof: createDelegationProofVerifier({ didResolver: didKeys }),
  checkRevocation: clear,
  now: () => NOW_MS,
  ...overrides,
});

describe('a carried chain of any length', () => {
  const DEEP = 60;

  it(`is accepted with no option set, ${DEEP} credentials deep`, async () => {
    expect(DEEP).toBeGreaterThan(MAX_DELEGATION_DEPTH);
    const signers = keyParties(DEEP + 1);
    const chain = chainOver(signers);
    const result = await verifyRequestDelegation(presenting(chain, signers[DEEP]!), depsUnder(signers[0]!));
    expect(result).toMatchObject({ ok: true, source: 'carried', depth: DEEP, responsibleParty: signers[0]!.did });
    expect(readDelegationChain(toDelegationChainMeta(chain))).toMatchObject({ carried: true, ok: true });
  });

  it('is refused past maxChainLength when the host sets one, before any credential is read', async () => {
    const signers = keyParties(5);
    const chain = chainOver(signers);
    const verifyHopProof = vi.fn(async () => true);
    const refused = await verifyRequestDelegation(presenting(chain, signers[4]!), depsUnder(signers[0]!, { maxChainLength: 3, verifyHopProof }));
    expect(refused).toMatchObject({
      ok: false,
      refusalCode: 'chain_invalid',
      reasons: ['carried delegation chain of 4 credentials exceeds the limit of 3'],
    });
    expect(verifyHopProof).not.toHaveBeenCalled();
    expect(await verifyRequestDelegation(presenting(chain, signers[4]!), depsUnder(signers[0]!, { maxChainLength: 4 }))).toMatchObject({ ok: true });
  });

  it.each([0, -1, 1.5, Number.NaN])('is refused as a configuration error under a maxChainLength of %s', (maxChainLength) => {
    const signers = keyParties(3);
    expect(readDelegationChain(toDelegationChainMeta(chainOver(signers)), { maxChainLength })).toMatchObject({
      carried: true,
      ok: false,
      refusalCode: 'configuration_error',
    });
  });
});

describe('what a long chain makes the verifier ask', () => {
  const HOPS = 40;
  const ROOT_LIST = 'https://root.example/status/1';
  const outside = (k: number) => `https://outside-${k}.example/status/1`;

  /** A root that delegates to `delegate`, who then signs `HOPS` hops of its own making. */
  const underDelegate = () => {
    const root = identity();
    const signers = [root, ...keyParties(HOPS + 1)];
    return { root, signers, leaf: signers[signers.length - 1]! };
  };

  /** A fetch that serves `bodies` and records every URL it is asked for. */
  const recording = (bodies: Record<string, Record<string, unknown>>): { fetch: SafeFetch; asked: string[] } => {
    const asked: string[] = [];
    const fetch: SafeFetch = async (url) => {
      asked.push(url);
      return Object.hasOwn(bodies, url)
        ? { ok: true, status: 200, json: () => Promise.resolve(bodies[url]) }
        : { ok: false, status: 503, json: () => Promise.resolve({}) };
    };
    return { fetch, asked };
  };

  it("one host that does not answer for the chain, however many other parties' hosts its hops name", async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { root, signers, leaf } = underDelegate();
    const chain = chainOver(signers, (k) => (k === 0 ? ROOT_LIST : outside(k)));
    const rootList = statusList(root, [], { id: ROOT_LIST, credentialSubject: { id: `${ROOT_LIST}#list` } });
    const { fetch, asked } = recording({ [ROOT_LIST]: rootList });
    const result = await verifyRequestDelegation(
      presenting(chain, leaf),
      depsUnder(root, {
        checkRevocation: createRevocationChecker({ fetch, now, verifyStatusList: createStatusListProofVerifier({ didResolver: didKeys }) }),
      }),
    );
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked', refusalCode: 'status_unavailable' });
    expect(asked).toEqual([ROOT_LIST, outside(1)]);
  });

  it("one DID document, when the hops' issuers are DIDs on other parties' hosts", async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const root = identity();
    const signers = [root, identity(), ...Array.from({ length: HOPS }, (_, k) => webIdentity(`did:web:outside-${k}.example`))];
    const resolved: string[] = [];
    const didResolver: DIDResolver = {
      resolve: async (did) => {
        if (did.startsWith('did:key:')) return didKeys.resolve(did);
        resolved.push(did);
        return null;
      },
    };
    const result = await verifyRequestDelegation(
      presenting(chainOver(signers), signers[signers.length - 1]!),
      depsUnder(root, { verifyHopProof: createDelegationProofVerifier({ didResolver }) }),
    );
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid' });
    expect(resolved).toEqual(['did:web:outside-0.example']);
  });

  it('nothing at all, when its root is not one the host trusts', async () => {
    const { signers, leaf } = underDelegate();
    const { fetch, asked } = recording({});
    const verifyHopProof = vi.fn(async () => true);
    const result = await verifyRequestDelegation(
      presenting(chainOver(signers, outside), leaf),
      depsUnder(identity(), { verifyHopProof, checkRevocation: createRevocationChecker({ fetch, now }) }),
    );
    expect(result).toMatchObject({ ok: false, refusalCode: 'untrusted_root' });
    expect(asked).toEqual([]);
    expect(verifyHopProof).not.toHaveBeenCalled();
  });
});

describe('the time a whole check may take', () => {
  const HOPS = 12;
  const LATE = codedAs('deadline_exceeded');
  /** A dependency that answers `value` after `ms`, counting how often it is asked. */
  const slow = <T>(ms: number, value: T) => vi.fn(() => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms)));

  const deepChain = () => {
    const signers = keyParties(HOPS + 1);
    return { root: signers[0]!, leaf: signers[HOPS]!, chain: chainOver(signers, (k) => `https://lists.example/status/${k}`) };
  };
  /** A hop proof verifier that answers at once: the clock here is faked, and a real signature check is not on it. */
  const verifyHopProof = async () => true;
  /** How a walk says the status of hop `k` could not be resolved, and `why`. */
  const unresolvable = (k: number, why: string) =>
    `revocation: hop ${k} (list "https://lists.example/status/${k}", index "${k}") is unresolvable: ${why}`;
  const OUT_OF_TIME = 'the delegation check did not finish within 30 seconds';

  it('is 30 seconds by default: status reads that each answer in 4 end the check there, and nothing more is asked', async () => {
    const { root, leaf, chain } = deepChain();
    const checkRevocation = slow(4_000, { revoked: false, fresh: true });
    const { value, ms } = await settledAfter(() =>
      verifyRequestDelegation(presenting(chain, leaf), depsUnder(root, { verifyHopProof, checkRevocation })),
    );
    expect(value).toEqual({
      ok: false,
      code: 'delegation_revoked',
      reasons: [unresolvable(7, OUT_OF_TIME)],
      source: 'carried',
      refusalCode: LATE.code,
      transient: LATE.transient,
    });
    expect(ms).toBe(30_000);
    expect(checkRevocation).toHaveBeenCalledTimes(8);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(checkRevocation).toHaveBeenCalledTimes(8);
  });

  it('covers the hop proofs and the status reads together', async () => {
    const { root, leaf, chain } = deepChain();
    const slowProofs = slow(2_000, true);
    const checkRevocation = slow(2_500, { revoked: false, fresh: true });
    const { value, ms } = await settledAfter(() =>
      verifyRequestDelegation(presenting(chain, leaf), depsUnder(root, { verifyHopProof: slowProofs, checkRevocation })),
    );
    expect(value).toMatchObject({ ok: false, refusalCode: 'deadline_exceeded', reasons: [unresolvable(2, OUT_OF_TIME)] });
    expect(ms).toBe(30_000);
    expect(slowProofs).toHaveBeenCalledTimes(HOPS);
    expect(checkRevocation).toHaveBeenCalledTimes(3);
  });

  it('ends a slow walk of hop proofs the same way', async () => {
    const { root, leaf, chain } = deepChain();
    const slowProofs = slow(4_000, true);
    const { value, ms } = await settledAfter(() =>
      verifyRequestDelegation(presenting(chain, leaf), depsUnder(root, { verifyHopProof: slowProofs })),
    );
    expect(value).toMatchObject({
      ok: false,
      code: 'delegation_invalid',
      refusalCode: 'deadline_exceeded',
      reasons: [`hop 7: ${OUT_OF_TIME}`],
    });
    expect(ms).toBe(30_000);
    expect(slowProofs).toHaveBeenCalledTimes(8);
  });

  it("covers the chain resolver's answer too, and ends its wait when the check is out of time", async () => {
    const { root, leaf, chain } = deepChain();
    const resolved = { meta: {}, proofDid: leaf.did, action: 'orders.place' };
    const checkRevocation = slow(4_000, { revoked: false, fresh: true });
    const walked = await settledAfter(() =>
      verifyRequestDelegation(resolved, depsUnder(root, { verifyHopProof, checkRevocation, resolveDelegationChain: slow(4_500, chain) })),
    );
    expect(walked.value).toMatchObject({ ok: false, source: 'resolved', refusalCode: 'deadline_exceeded', reasons: [unresolvable(6, OUT_OF_TIME)] });
    expect(walked.ms).toBe(30_000);
    expect(checkRevocation).toHaveBeenCalledTimes(7);
    vi.useRealTimers();
    const unanswered = await settledAfter(() =>
      verifyRequestDelegation(resolved, depsUnder(root, { resolveDelegationChain: () => new Promise<never>(() => undefined), totalTimeoutMs: 3_000 })),
    );
    expect(unanswered.value).toEqual({
      ok: false,
      code: 'delegation_unresolvable',
      reasons: ['delegation chain could not be resolved: the delegation check did not finish within 3 seconds'],
      source: 'resolved',
      refusalCode: LATE.code,
      transient: LATE.transient,
    });
    expect(unanswered.ms).toBe(3_000);
  });

  it('is the totalTimeoutMs the host sets: raised, the same chain passes; lowered, it ends sooner', async () => {
    const { root, leaf, chain } = deepChain();
    const run = (totalTimeoutMs: number) =>
      settledAfter(() =>
        requireDelegation(depsUnder(root, { verifyHopProof, checkRevocation: slow(4_000, { revoked: false, fresh: true }), totalTimeoutMs }))(
          presenting(chain, leaf),
        ),
      );
    const raised = await run(60_000);
    expect(raised.value).toMatchObject({ ok: true, depth: HOPS });
    expect(raised.ms).toBe(HOPS * 4_000);
    vi.useRealTimers();
    const lowered = await run(9_000);
    expect(lowered.value).toMatchObject({ ok: false, refusalCode: 'deadline_exceeded', transient: true });
    expect(lowered.ms).toBe(9_000);
  });

  it('still gives each dependency its own deadline inside it', async () => {
    const { root, leaf, chain } = deepChain();
    const checkRevocation = vi.fn(() => new Promise<never>(() => undefined));
    const { value, ms } = await settledAfter(() =>
      verifyRequestDelegation(presenting(chain, leaf), depsUnder(root, { verifyHopProof, checkRevocation })),
    );
    expect(value).toMatchObject({ ok: false, reasons: [unresolvable(0, 'the revocation checker did not answer within 5 seconds')] });
    expect(ms).toBe(5_000);
  });

  it('bounds evaluateDelegationChain and evaluateRevocationChain as it does a request', async () => {
    const { root, chain } = deepChain();
    const evaluated = await settledAfter(() =>
      evaluateDelegationChain(chain, slow(4_000, { revoked: false, fresh: true }), {
        resourceOwner: root.did,
        verifyHopProof,
        now: () => NOW_MS,
      }),
    );
    expect(evaluated.value).toMatchObject({ ok: false, ...LATE, reasons: [unresolvable(7, OUT_OF_TIME)] });
    expect(evaluated.ms).toBe(30_000);
    vi.useRealTimers();
    const entries = chain.map((credential) => credential.credentialStatus!);
    const walked = await settledAfter(() => evaluateRevocationChain(entries, slow(4_000, { revoked: false, fresh: true }), { totalTimeoutMs: 10_000 }));
    expect(walked.value).toMatchObject({ ok: false, ...LATE, reasons: [unresolvable(2, 'the revocation check did not finish within 10 seconds')] });
    expect(walked.ms).toBe(10_000);
  });

  it.each(REFUSED_TIMEOUTS)('throws a TypeError that names totalTimeoutMs for %s', async (_label, totalTimeoutMs, got) => {
    const { root, leaf, chain } = deepChain();
    const deps = depsUnder(root, { totalTimeoutMs: totalTimeoutMs as number });
    const mistyped = timeoutTypeError(got, '', 'totalTimeoutMs');
    expect(() => requireDelegation(deps)).toThrow(mistyped);
    await expect(verifyRequestDelegation(presenting(chain, leaf), deps)).rejects.toThrow(mistyped);
    await expect(evaluateDelegationChain(chain, clear, { now: () => NOW_MS, totalTimeoutMs: totalTimeoutMs as number })).rejects.toThrow(mistyped);
    await expect(evaluateRevocationChain([], clear, { totalTimeoutMs: totalTimeoutMs as number })).rejects.toThrow(mistyped);
  });
});
