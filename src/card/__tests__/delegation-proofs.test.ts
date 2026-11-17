/** Real signed chains exercise local checks, hop proofs and status reads in that order. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { logger } from '../../logging/index.js';
import { RefusalError } from '../../utils/refusal.js';
import { evaluateDelegationChain, validateDelegationChain, type DelegationCredential } from '../delegation.js';
import { createDelegationProofVerifier, type DelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker, type BitstringRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import {
  RESOURCE, STATUS_URL, hop, identity, now, parties, serve, signEddsaJcs2022, statusList, twoHopChain,
} from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();

function fixture() {
  const p = parties();
  const chain = twoHopChain(p);
  const fetch = vi.fn(serve(statusList(p.acme)));
  const check = vi.fn(createRevocationChecker({
    fetch, now, verifyStatusList: createStatusListProofVerifier({ didResolver }),
  }));
  const ctx = { resource: RESOURCE, resourceOwner: p.acme.did, now };
  return { p, chain, fetch, check, ctx };
}

/** Sign the complete credential with a different key, keeping the issuer it claims. */
function forge(credential: DelegationCredential): DelegationCredential {
  const unsigned = Object.fromEntries(Object.entries(credential).filter(([key]) => key !== 'proof'));
  return signEddsaJcs2022(unsigned, identity()) as DelegationCredential;
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('evaluateDelegationChain proofs before status', () => {
  it.each([0, 1])('refuses a forged hop %i before calling the checker or fetching any status', async (index) => {
    const { chain, check, fetch, ctx } = fixture();
    chain[index] = forge(chain[index]!);
    const result = await evaluateDelegationChain(chain, check, {
      ...ctx, verifyHopProof: createDelegationProofVerifier({ didResolver }),
    });
    expect(result).toMatchObject({
      ok: false, code: 'invalid_proof', transient: false, fresh: false,
      reasons: [`hop ${index}: proof did not verify`],
    });
    expect(check).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('stops proof verification at a forged middle hop of three', async () => {
    const { p, chain, check, fetch, ctx } = fixture();
    const last = hop({
      issuer: p.subAgent, invoker: identity().did, id: 'urn:zcap:last',
      parentCapability: chain[1].credentialSubject.id, allowedAction: ['orders.place'],
      caveats: chain[1].credentialSubject.caveats, statusIndex: 9,
    });
    const forged = forge(chain[1]);
    const verify = vi.fn(createDelegationProofVerifier({ didResolver }));
    expect(await evaluateDelegationChain([chain[0], forged, last], check, { ...ctx, verifyHopProof: verify }))
      .toMatchObject({ ok: false, code: 'invalid_proof', reasons: ['hop 1: proof did not verify'], fresh: false });
    expect(verify.mock.calls.map(([credential]) => credential)).toEqual([chain[0], forged]);
    expect(check).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['broken link', 'expired', 'malformed', 'attenuation', 'root', 'resource', 'depth'])(
    'refuses a local %s failure before any proof or status work', async (fault) => {
      const { chain, check, fetch, ctx } = fixture();
      if (fault === 'broken link') chain[1].credentialSubject.parentCapability = 'urn:zcap:elsewhere';
      if (fault === 'expired') chain.forEach((credential) => { credential.validUntil = '2020-01-01T00:00:00Z'; });
      if (fault === 'malformed') chain[1].validUntil = 'not a date';
      if (fault === 'attenuation') chain[1].credentialSubject.allowedAction = ['orders.delete'];
      const policy = {
        ...ctx,
        ...(fault === 'root' ? { resourceOwner: identity().did } : {}),
        ...(fault === 'resource' ? { resource: 'did:web:elsewhere.example' } : {}),
        ...(fault === 'depth' ? { maxChainLength: 1 } : {}),
      };
      const verify = vi.fn(createDelegationProofVerifier({ didResolver }));
      const structural = validateDelegationChain(chain, policy);
      expect(structural.ok).toBe(false);
      expect(await evaluateDelegationChain(chain, check, { ...policy, verifyHopProof: verify }))
        .toEqual({ ...structural, fresh: false });
      expect(verify).not.toHaveBeenCalled();
      expect(check).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each([true, false])('finishes proofs before sequential status reads, pinned root: %s', async (pinned) => {
    const { p, chain, ctx } = fixture();
    const events: string[] = [];
    const realVerify = createDelegationProofVerifier({ didResolver });
    let finishRoot!: () => void;
    const rootPending = new Promise<void>((resolve) => { finishRoot = resolve; });
    const verify: DelegationProofVerifier = async (credential) => {
      const index = chain.indexOf(credential as DelegationCredential);
      events.push(`proof ${index}`);
      if (index === 0) await rootPending;
      const verified = await realVerify(credential);
      events.push(`proved ${index}`);
      return verified;
    };
    let finishStatus!: () => void;
    const statusPending = new Promise<void>((resolve) => { finishStatus = resolve; });
    const check = vi.fn<BitstringRevocationChecker>(async (entry) => {
      events.push(`status ${entry?.statusListIndex}`);
      if (entry?.statusListIndex === '3') await statusPending;
      return { revoked: false, fresh: true };
    });
    const result = evaluateDelegationChain(chain, check, {
      ...ctx, resourceOwner: pinned ? p.acme.did : undefined, verifyHopProof: verify,
    });
    expect(events).toEqual(['proof 0']);
    finishRoot();
    await vi.waitFor(() => expect(events).toEqual(['proof 0', 'proved 0', 'proof 1', 'proved 1', 'status 3']));
    finishStatus();
    expect(await result).toMatchObject({ ok: true, fresh: true, reasons: [] });
    expect(events).toEqual(['proof 0', 'proved 0', 'proof 1', 'proved 1', 'status 3', 'status 7']);
    expect(check.mock.calls.map(([, context]) => context)).toEqual([p.acme, p.agent].map(({ did }) => ({
      credentialIssuer: did,
      ...(pinned ? { trustedRootIssuer: p.acme.did, trustedRootStatusList: STATUS_URL } : {}),
    })));
  });

  it('accepts a delegate on the pinned root list signed by that root', async () => {
    const { chain, check, fetch, ctx } = fixture();
    expect(await evaluateDelegationChain(chain, check, {
      ...ctx, verifyHopProof: createDelegationProofVerifier({ didResolver }),
    })).toMatchObject({ ok: true, fresh: true, reasons: [] });
    expect(check.mock.calls.map(([entry]) => entry?.statusListIndex)).toEqual(['3', '7']);
    expect(fetch).toHaveBeenCalled();
  });

  it.each(['revoked', 'unreadable'])('stops status reads at the first %s hop after proving the whole chain', async (fault) => {
    const { p, chain, ctx } = fixture();
    const fetch = vi.fn(serve(fault === 'revoked' ? statusList(p.acme, [3]) : undefined));
    const check = vi.fn(createRevocationChecker({
      fetch, now, verifyStatusList: createStatusListProofVerifier({ didResolver }),
    }));
    const verify = vi.fn(createDelegationProofVerifier({ didResolver }));
    expect(await evaluateDelegationChain(chain, check, { ...ctx, verifyHopProof: verify }))
      .toMatchObject({ ok: false, fresh: false });
    expect(verify).toHaveBeenCalledTimes(2);
    expect(check).toHaveBeenCalledTimes(1);
    expect(check.mock.calls[0]?.[0]?.statusListIndex).toBe('3');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('verifies the received credential with all its signed extension members', async () => {
    const { p, chain, check, ctx } = fixture();
    const unsigned = Object.fromEntries(Object.entries(chain[0]).filter(([key]) => key !== 'proof'));
    chain[0] = signEddsaJcs2022({
      ...unsigned, extension: { binding: 'signed' }, credentialStatus: { ...chain[0].credentialStatus, extension: 'signed' },
    }, p.acme) as DelegationCredential;
    const verify = vi.fn(createDelegationProofVerifier({ didResolver }));
    expect(await evaluateDelegationChain(chain, check, { ...ctx, verifyHopProof: verify })).toMatchObject({ ok: true });
    expect(verify.mock.calls[0]?.[0]).toBe(chain[0]);
  });

  it('gives an unanswered proof verifier the configured deadline without reading status', async () => {
    vi.useFakeTimers();
    const { chain, check, fetch, ctx } = fixture();
    const verify = vi.fn(() => new Promise<boolean>(() => {}));
    const result = evaluateDelegationChain(chain, check, { ...ctx, verifyHopProof: verify, dependencyTimeoutMs: 25 });
    await vi.advanceTimersByTimeAsync(25);
    expect(await result).toMatchObject({
      ok: false, code: 'deadline_exceeded', transient: true, fresh: false,
      reasons: ['hop 0: the hop proof verifier did not answer within 25 ms'],
    });
    expect(verify).toHaveBeenCalledTimes(1);
    expect(check).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    ['coded', () => { throw new RefusalError('host_refused', 'issuer host refused'); }, 'host_refused', 'issuer host refused'],
    ['unexpected', () => { throw new Error('private transport detail'); }, 'runtime_error', 'proof did not verify'],
    ['false', () => false, 'invalid_proof', 'proof did not verify'],
    ['DID outage', createDelegationProofVerifier({ didResolver: { resolve: async () => null } }), 'did_unavailable', undefined],
  ] as const)('keeps %s refusal codes in parity with verifyRequestDelegation', async (_name, verify, code, reason) => {
    const { p, chain, check, fetch, ctx } = fixture();
    const logged = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const evaluated = await evaluateDelegationChain(chain, check, { ...ctx, verifyHopProof: verify });
    const requested = await verifyRequestDelegation({
      meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place',
    }, { ...ctx, verifyHopProof: verify, checkRevocation: check });
    expect(evaluated).toMatchObject({ ok: false, code, fresh: false });
    expect(requested).toMatchObject({ ok: false, refusalCode: code, reasons: evaluated.reasons });
    if (reason !== undefined) expect(evaluated.reasons).toEqual([`hop 0: ${reason}`]);
    expect(JSON.stringify(evaluated.reasons)).not.toContain('private transport detail');
    if (code === 'runtime_error') expect(logged).toHaveBeenCalledWith(expect.stringContaining('private transport detail'));
    expect(check).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('preserves proof refusal precedence over the requested action', async () => {
    const { p, chain, check, ctx } = fixture();
    chain[1] = forge(chain[1]);
    const verify = createDelegationProofVerifier({ didResolver });
    const evaluated = await evaluateDelegationChain(chain, check, { ...ctx, verifyHopProof: verify });
    const requested = await verifyRequestDelegation({
      meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.delete',
    }, { ...ctx, verifyHopProof: verify, checkRevocation: check });
    expect(evaluated).toMatchObject({ ok: false, code: 'invalid_proof' });
    expect(requested).toMatchObject({ ok: false, code: 'delegation_invalid', refusalCode: evaluated.code });
    expect(check).not.toHaveBeenCalled();
  });
});
