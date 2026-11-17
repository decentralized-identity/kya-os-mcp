/** Compatibility without a hop verifier, with one process-wide migration warning. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { logger } from '../../logging/index.js';
import { evaluateDelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { RESOURCE, now, parties, twoHopChain } from './signed-chain-helpers.js';

const warned = Symbol.for('@kya-os/mcp/delegation-proofs-warned');
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

describe('legacy evaluateDelegationChain', () => {
  it('keeps unverified results and warns once across module copies', async () => {
    const p = parties();
    const chain = twoHopChain(p);
    delete chain[0].proof;
    const check = vi.fn(async () => ({ revoked: false, fresh: true }));
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const ctx = { resource: RESOURCE, resourceOwner: p.acme.did, now };
    const expected = {
      ok: true, reasons: [], fresh: true, responsibleParty: p.acme.did, leafInvoker: p.subAgent.did,
      invocationTarget: RESOURCE, allowedAction: ['orders.place'], depth: 2,
    };
    expect(await evaluateDelegationChain(chain, check, ctx)).toEqual(expected);
    expect(await evaluateDelegationChain(chain, check, { ...ctx })).toEqual(expected);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/status.*without.*hop proofs.*verifyHopProof/));
    vi.resetModules();
    const reloaded = await import('../delegation.js');
    const logging = await import('../../logging/index.js');
    const reloadedWarn = vi.spyOn(logging.logger, 'warn').mockImplementation(() => {});
    expect(await reloaded.evaluateDelegationChain(chain, check, ctx)).toEqual(expected);
    expect(reloadedWarn).not.toHaveBeenCalled();
    expect(check).toHaveBeenCalledTimes(6);
  });

  it('does not warn when proofs are checked or local checks refuse before status', async () => {
    const chain = twoHopChain(parties());
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const check = vi.fn(async () => ({ revoked: false, fresh: true }));
    expect(await evaluateDelegationChain(chain, check, {
      now, verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
    })).toMatchObject({ ok: true });
    expect(await evaluateDelegationChain([], check, { now })).toMatchObject({ ok: false, fresh: false });
    expect(warn).not.toHaveBeenCalled();
  });
});
