/**
 * A delegated call that a wrapper standing outside the gate proves, from the
 * gate's answer rebuilt and without the call's context, is proved as before,
 * and its proof names no delegation (SPEC.md §7.8).
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import type { KyaOsToolHandler } from '../with-kya-os.js';
import { logger } from '../../logging/index.js';
import { makeUnserved } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party } from './helpers/delegating-party.js';
import { verifyReceived } from './helpers/received-proof.js';
import { delegationClaims } from './helpers/server-answers.js';

/** Another tool, which a gate of its own stands before. */
const OTHER = 'records.export';
const WINDOW = 60_000;

async function delegatedCall() {
  const made = await makeUnserved({}, { pendingProofTtlMs: WINDOW });
  const [user, agent] = await Promise.all([party(), party()]);
  const credential = await delegate(user, agent.did);
  const gate = made.kyaos.wrapWithDelegation(TOOL, CONSENT, made.kyaos.wrapWithProof(TOOL, released));
  // A gate stands before the other tool too, so both names are a gate's.
  made.kyaos.wrapWithDelegation(OTHER, CONSENT, made.kyaos.wrapWithProof(OTHER, released));
  return { ...made, credential, gate, args: { ...ARGS, _kyaos_delegation: credential } };
}

/** An outer wrapper that hands the call to `gate` and answers with a copy of its content only. */
const rebuilding = (gate: KyaOsToolHandler): KyaOsToolHandler => async (args, sessionId) => ({
  content: (await gate(args, sessionId)).content,
});

describe('a delegated call proved outside the gate without its context', () => {
  afterEach(() => vi.restoreAllMocks());

  it('is proved as before by a wrapper that rebuilds the gate’s answer, naming no delegation', async () => {
    vi.spyOn(logger, 'error').mockImplementation(() => {});
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    const { kyaos, wire, server, gate, args } = await delegatedCall();
    const outer = kyaos.wrapWithProof(TOOL, rebuilding(gate));

    const sent = await wire.call({ toolName: TOOL, args }, () => outer(args));

    expect(delegationClaims(sent)).toEqual({});
    expect(await verifyReceived(sent, { signer: server.did, toolName: TOOL, params: args, binds: 'content' }))
      .toEqual({ valid: true });
  });
});
