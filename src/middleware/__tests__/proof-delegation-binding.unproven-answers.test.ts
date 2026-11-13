/**
 * What an answer says when the proof of a delegated call is not made: why it
 * is unproven. A proof goes with the call it was left for, once.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { makeServer, makeUnserved, type Recorded } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { delegate, party } from './helpers/delegating-party.js';
import { threeHops } from './helpers/delegation-chains.js';
import { handshake, proofOf } from './helpers/received-proof.js';
import { UNPROVEN, delegationClaims, lifecycleOf, proofErrorOf } from './helpers/server-answers.js';

/** A trail's events in order, each with the code of its reason. */
const trailOf = (recorded: readonly Recorded[]): string[] =>
  recorded.map((event) => {
    const code = event.reason ?? (event.details.verificationCode as string | undefined);
    return code === undefined ? event.eventType : `${event.eventType} ${code}`;
  });

describe('an answer whose proof is not made', () => {
  afterEach(() => vi.restoreAllMocks());

  // A BigInt has no canonical JSON form, so the request has no hash and no
  // proof of it can be made. The answer says so, and the trail records the
  // proof as one that could not be made.
  it('answers a call whose arguments cannot be hashed unproven for that reason', async () => {
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});
    const { kyaos, wire, server, ancestors, recorded } = await makeUnserved();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const gate = kyaos.wrapWithDelegation(TOOL, CONSENT, released);
    const args = { recordId: 1n, _kyaos_delegation: leaf };

    const sent = await wire.call({ toolName: TOOL, args }, () => gate(args));

    expect(sent.content).toEqual([{ type: 'text', text: 'released 1' }]);
    expect(proofOf(sent)).toBeUndefined();
    expect(proofErrorOf(sent)).toBe(UNPROVEN);
    expect(error).toHaveBeenCalledWith('[kya-os] Proof generation failed', {
      tool: TOOL,
      error: expect.stringContaining('bigint'),
    });
    expect(trailOf(recorded)).toEqual(
      expect.arrayContaining(['tool.call.started', 'proof.rejected PROOF_GENERATION_FAILED']),
    );
  });

  it('answers the second of two delegated calls that share one result unproven: the proof goes with the call that made it', async () => {
    const { kyaos, recorded } = await makeServer();
    const [user, first, second] = await Promise.all([party(), party(), party()]);
    const [firstCredential, secondCredential] = await Promise.all([
      delegate(user, first.did),
      delegate(user, second.did),
    ]);
    const [sessionOne, sessionTwo] = [await handshake(kyaos), await handshake(kyaos)];
    // An idempotent read that answers identical calls in flight with one
    // result: the second caller gets the very object the first call produced.
    const proved = kyaos.wrapWithProof(TOOL, released);
    let inFlight: ReturnType<typeof proved> | undefined;
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, (args, sessionId, context) => {
      inFlight ??= held.then(() => proved(args, sessionId, context));
      return inFlight;
    });

    const one = handler({ ...ARGS, _kyaos_delegation: firstCredential }, sessionOne);
    const two = handler({ ...ARGS, _kyaos_delegation: secondCredential }, sessionTwo);
    release();
    const [resultOne, resultTwo] = await Promise.all([one, two]);

    // The proof was left under the first call, and goes with its answer, once.
    expect(proofOf(resultOne)!.meta.sessionId).toBe(sessionOne);
    expect(delegationClaims(resultOne)).toEqual({});
    // The second answer goes out without it and says so.
    expect(proofOf(resultTwo)).toBeUndefined();
    expect(proofErrorOf(resultTwo)).toBe(UNPROVEN);
    expect(resultTwo.content).toEqual(resultOne.content);
    const rejected = recorded.filter((event) => event.eventType === 'proof.rejected');
    expect(rejected.map((event) => [event.details.verificationCode, event.authorization?.delegationRef]))
      .toEqual([['PROOF_EXPIRED', firstCredential.id]]);
    // Only the call that made the result ran a wrapper, so only that call is
    // recorded started, and completed.
    expect(lifecycleOf(recorded)).toEqual([
      ['tool.call.started', firstCredential.id],
      ['tool.call.completed', firstCredential.id],
    ]);
  });
});
