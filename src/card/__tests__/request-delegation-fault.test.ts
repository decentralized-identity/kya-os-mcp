/**
 * The request guards never throw on what a caller presents. Should the chain rules themselves fault,
 * as a value read past the call stack would make them, `verifyRequestDelegation` and
 * `requireDelegation` refuse the call as `runtime_error`, which is transient, with a reason that
 * says no more than that, and the operator's log is told what was thrown.
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

vi.mock('../delegation.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../delegation.js')>();
  // Chain rules that run out of stack, as no input can now make the real ones do.
  return {
    ...actual,
    validateDelegationChain: () => {
      throw new RangeError('Maximum call stack size exceeded');
    },
  };
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('a fault in the chain rules', () => {
  it('is refused as runtime_error by verifyRequestDelegation and requireDelegation, never thrown', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
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
    const input = { meta: toDelegationChainMeta(twoHopChain(p)), proofDid: p.subAgent.did, action: 'orders.place' };
    const reasons = ['delegation chain could not be checked: the chain rules faulted'];
    expect(await verifyRequestDelegation(input, deps)).toEqual({
      ok: false,
      code: 'delegation_invalid',
      reasons,
      source: 'carried',
      refusalCode: 'runtime_error',
      transient: true,
    });
    expect(await requireDelegation(deps)(input)).toMatchObject({ ok: false, status: 403, error: { reasons }, refusalCode: 'runtime_error', transient: true });
    expect(warn).toHaveBeenCalledWith('[kya-os] delegation chain could not be checked: the chain rules faulted: Maximum call stack size exceeded');
  });
});
