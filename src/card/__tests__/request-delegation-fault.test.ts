/**
 * The request guards never throw on what a caller presents. Should the chain rules themselves fault,
 * or the comparison of the delegation a request proof states with the chain, as a value read past
 * the call stack would make them, `verifyRequestDelegation` and `requireDelegation` refuse the call
 * as `runtime_error`, which is transient, with a reason that says no more than that, and the
 * operator's log is told what was thrown.
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
} from '../index.js';
import { NOW_MS, RESOURCE, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

/** The part that faults in the test running, or none, and how: a stack run out, as no input can now make the real ones do. */
const faulting = vi.hoisted(() => ({
  at: undefined as 'chain rules' | 'request binding' | undefined,
  overflow: () => new RangeError('Maximum call stack size exceeded'),
}));

vi.mock('../delegation.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../delegation.js')>();
  return {
    ...actual,
    validateDelegationChain: (...given: Parameters<typeof actual.validateDelegationChain>) => {
      if (faulting.at === 'chain rules') throw faulting.overflow();
      return actual.validateDelegationChain(...given);
    },
  };
});

vi.mock('../request-binding.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../request-binding.js')>();
  return {
    ...actual,
    requestBindingRefusal: async (...given: Parameters<typeof actual.requestBindingRefusal>) => {
      if (faulting.at === 'request binding') throw faulting.overflow();
      return actual.requestBindingRefusal(...given);
    },
  };
});

afterEach(() => {
  faulting.at = undefined;
  vi.restoreAllMocks();
});

/** A carried two-hop chain the guards accept, with what they are given to check it. */
function request() {
  const p = parties();
  const didResolver = createDidKeyResolver();
  const now = () => NOW_MS;
  const deps = {
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: createRevocationChecker({ fetch: serve(statusList(p.acme)), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) }),
    now,
  };
  return { deps, input: { meta: toDelegationChainMeta(twoHopChain(p)), proofDid: p.subAgent.did, action: 'orders.place' } };
}

describe('a fault in checking a delegation', () => {
  it('is no fault where nothing faults: the chain is accepted', async () => {
    const { deps, input } = request();
    expect(await verifyRequestDelegation(input, deps)).toMatchObject({ ok: true });
  });

  it.each([
    ['chain rules', 'delegation chain could not be checked: the chain rules faulted'],
    ['request binding', 'the delegation the request proof states could not be compared with the chain'],
  ] as const)('in the %s is refused as runtime_error by verifyRequestDelegation and requireDelegation, never thrown', async (part, withheld) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    faulting.at = part;
    const { deps, input } = request();
    const reasons = [`${withheld}${WITHHELD_SUFFIX}`];
    expect(await verifyRequestDelegation(input, deps)).toEqual({
      ok: false,
      code: 'delegation_invalid',
      reasons,
      source: 'carried',
      refusalCode: 'runtime_error',
      transient: true,
    });
    expect(await requireDelegation(deps)(input)).toMatchObject({ ok: false, status: 403, error: { reasons }, refusalCode: 'runtime_error', transient: true });
    expect(warn).toHaveBeenCalledWith(`[kya-os] ${withheld}: Maximum call stack size exceeded`);
  });
});
