/**
 * A wrapper around another, with no gate between them, proves the call
 * (SPEC.md §7.8): the wrapper outside proves it, and the proof the wrapper
 * inside left is replaced.
 */
import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest';
import { makeServer, type Recorded } from './helpers/delegation-gate-server.js';
import { ARGS, released } from './helpers/delegated-call.js';
import { verifyReceived } from './helpers/received-proof.js';
import { eventWithCode } from './helpers/server-answers.js';

const INNER = 'records.internal';
const OUTER = 'records.read';
/** How long a proof left waiting waits to be sent. */
const TTL = { pendingProofTtlMs: 60_000 };

/**
 * Every event, in order: what it records with the code it gives, the tool a
 * call event is about, and the credential it names.
 */
const trailOf = (recorded: readonly Recorded[]) =>
  recorded.map((event) => [eventWithCode(event), event.tool, event.authorization?.delegationRef]);

describe('a wrapper around another with no gate between them', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('proves the call by the wrapper outside, and closes the proof the wrapper inside left as never sent', async () => {
    const { kyaos, server, recorded } = await makeServer({}, {}, TTL);
    const result = await kyaos.wrapWithProof(OUTER, kyaos.wrapWithProof(INNER, released))(ARGS);
    await vi.advanceTimersByTimeAsync(TTL.pendingProofTtlMs);
    await vi.waitFor(() => expect(recorded).toHaveLength(6));

    // The proof the wrapper inside left is replaced, and closed as never sent
    // when its window passes.
    expect(trailOf(recorded)).toEqual([
      ['tool.call.started', OUTER, undefined],
      ['tool.call.started', INNER, undefined],
      ['proof.generated', undefined, undefined],
      ['tool.call.completed', OUTER, undefined],
      ['proof.rejected PROOF_NOT_SENT', undefined, undefined],
      ['tool.call.failed RESULT_NOT_SENT', INNER, undefined],
    ]);
    expect(await verifyReceived(result, { signer: server.did, toolName: OUTER, params: ARGS, binds: 'content' }))
      .toEqual({ valid: true });
  });
});
