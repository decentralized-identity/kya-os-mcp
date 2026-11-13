/**
 * A delegated call is proved and recorded as before however a server
 * arranges its wrappers: a bare handler, a gate inside wrapWithProof, a
 * wrapper given another name, or a wrapper outside the gate that cannot
 * record its call. No proof names a delegation (SPEC.md §7.8).
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import type { KyaOsToolHandler } from '../with-kya-os.js';
import { logger } from '../../logging/index.js';
import { KYA_OS_PROOF_META_KEY } from '../../proof/index.js';
import { makeServer, makeUnserved, withTimersHeld } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { threeHops } from './helpers/delegation-chains.js';
import { proofOf, verifyReceived } from './helpers/received-proof.js';
import { delegationClaims, delegationEvidence, lifecycleOf, proofErrorOf } from './helpers/server-answers.js';

describe('an allowed call', () => {
  it('leaves a bare handler to the transport exactly as before', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    // No wrapWithProof inside the gate, and a result that relays an upstream
    // server's proof members. The transport proves it as any tool's.
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, async (args) => ({
      ...(await released(args)),
      _meta: { traceparent: 'keep-me', 'org.kya-os/response-proof': { jws: 'relayed' }, proofError: 'relayed' },
    }));

    const args = { ...ARGS, _kyaos_delegation: leaf };
    const result = await handler(args);
    await handler(args);

    expect(result.isError).toBeUndefined();
    expect(proofOf(result)!.meta).not.toHaveProperty('scopeId');
    expect(delegationClaims(result)).toEqual({});
    expect(result._meta).toMatchObject({ traceparent: 'keep-me' });
    expect(result._meta).not.toHaveProperty('proofError');
    // Its own proof, over the arguments as sent, as on earlier releases.
    const verified = await verifyReceived(result, {
      signer: server.did,
      toolName: TOOL,
      params: args,
      binds: 'content',
    });
    expect(verified).toEqual({ valid: true });
    expect(recorded.filter((event) => event.eventType === 'tool.call.completed')).toHaveLength(2);
  });

  it('proves a gate inside wrapWithProof once, as before', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    // The reverse of the documented order: the proof wrapper is outside the
    // gate, so it is not handed the gate's context.
    const handler = kyaos.wrapWithProof(TOOL, kyaos.wrapWithDelegation(TOOL, CONSENT, released));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(result.isError).toBeUndefined();
    expect(proofOf(result)).toBeDefined();
    expect(proofOf(result)!.meta).not.toHaveProperty('delegationRef');
    // The wrapper outside the gate opens the call, and its proof closes it.
    expect(lifecycleOf(recorded)).toEqual([
      ['tool.call.started', undefined],
      ['tool.call.completed', undefined],
    ]);
    expect(recorded.filter((event) => event.eventType === 'proof.generated')).toHaveLength(1);
    expect(recorded.filter((event) => event.eventType === 'proof.rejected')).toHaveLength(0);
  });

  it('proves a gate inside wrapWithProof by the outer wrapper when the handler inside the gate is wrapped too, as before', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer({}, {}, { pendingProofTtlMs: 20 });
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithProof(
      TOOL,
      kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released)),
    );

    await withTimersHeld(async () => {
      const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

      // The outer wrapper's proof is sent, and names no delegation. The inner
      // wrapper's is never sent, and is closed as such once its window passes.
      expect(proofOf(result)!.meta).not.toHaveProperty('delegationRef');
      expect(lifecycleOf(recorded)).toEqual([
        ['tool.call.started', undefined],
        ['tool.call.started', leaf.id],
        ['tool.call.completed', undefined],
      ]);
      await vi.advanceTimersByTimeAsync(20);
      await vi.waitFor(() => expect(lifecycleOf(recorded)).toHaveLength(4));
      expect(lifecycleOf(recorded)[3]).toEqual(['tool.call.failed RESULT_NOT_SENT', leaf.id]);
    });
  });

  it('proves a gate inside a wrapper given another name by that wrapper, as before', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer({}, {}, { pendingProofTtlMs: 20 });
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithProof(
      'records.read',
      kyaos.wrapWithDelegation('records.internal', CONSENT, kyaos.wrapWithProof('records.internal', released)),
    );
    const args = { ...ARGS, _kyaos_delegation: leaf };

    await withTimersHeld(async () => {
      const result = await handler(args);
      await vi.advanceTimersByTimeAsync(20);

      // The outer wrapper's proof is sent, for the call it was given, and names
      // no delegation. The inner wrapper's is never sent, and is closed as such
      // once its window passes.
      expect(proofOf(result)!.meta).not.toHaveProperty('delegationRef');
      expect(await verifyReceived(result, { signer: server.did, toolName: 'records.read', params: args, binds: 'content' }))
        .toEqual({ valid: true });
      await vi.waitFor(() => expect(lifecycleOf(recorded)).toHaveLength(4));
      expect(lifecycleOf(recorded)).toEqual([
        ['tool.call.started', undefined],
        ['tool.call.started', leaf.id],
        ['tool.call.completed', undefined],
        ['tool.call.failed RESULT_NOT_SENT', leaf.id],
      ]);
      expect(recorded.filter((event) => event.eventType.startsWith('proof.')).map((event) => [event.eventType, event.details.verificationCode]))
        .toEqual([['proof.generated', undefined], ['proof.rejected', 'PROOF_NOT_SENT']]);
    });
  });

  it.each([
    ['a handler wrapped inside the gate', true],
    ['a handler passed to the gate bare', false],
  ])('sends the answer to a call of another tool than the gate was given unproven, as before, for %s', async (_name, wrapped) => {
    vi.spyOn(logger, 'warn').mockImplementation(() => {});
    vi.spyOn(logger, 'error').mockImplementation(() => {});
    const { kyaos, wire, server, ancestors, recorded } = await makeUnserved();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const gated = kyaos.wrapWithDelegation('records.internal', CONSENT, wrapped ? kyaos.wrapWithProof('records.internal', released) : released);
    const args = { ...ARGS, _kyaos_delegation: leaf };

    const unanswered = await gated(args);
    // A bare handler's result is the transport's to prove, for the tool it answers.
    const sent = await wire.send(unanswered, { toolName: 'records.read', args });

    if (wrapped) {
      expect(proofOf(sent)).toBeUndefined();
      expect(proofErrorOf(sent)).toMatch(/^Proof generation failed/);
      expect(recorded.filter((event) => event.eventType === 'proof.rejected').map((event) => event.details.verificationCode))
        .toEqual(['PROOF_TOOL_MISMATCH']);
      expect(lifecycleOf(recorded)).toEqual([
        ['tool.call.started', leaf.id],
        ['tool.call.failed RESULT_NOT_SENT', leaf.id],
      ]);
    } else {
      expect(proofOf(sent)!.meta).not.toHaveProperty('delegationRef');
      expect(lifecycleOf(recorded)).toEqual([
        ['tool.call.started', undefined],
        ['tool.call.completed', undefined],
      ]);
    }
  });

  it('records an error result of a gate inside wrapWithProof as failed by each wrapper', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const failing: KyaOsToolHandler = async () => ({ content: [{ type: 'text', text: 'upstream failed' }], isError: true });
    const handler = kyaos.wrapWithProof(
      TOOL,
      kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, failing)),
    );

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(result).toEqual({ content: [{ type: 'text', text: 'upstream failed' }], isError: true });
    expect(lifecycleOf(recorded)).toEqual([
      ['tool.call.started', undefined],
      ['tool.call.started', leaf.id],
      ['tool.call.failed HANDLER_ERROR_RESULT', leaf.id],
      ['tool.call.failed HANDLER_ERROR_RESULT', undefined],
    ]);
    expect(recorded.filter((event) => event.eventType.startsWith('proof.'))).toHaveLength(0);
  });

  it('sends a degraded answer with no proof at all, not even one its handler relayed, when the wrapper outside the gate cannot record its call completed', async () => {
    vi.spyOn(logger, 'error').mockImplementation(() => {});
    let completions = 0;
    const { kyaos, server, ancestors } = await makeServer(
      {},
      { refuse: (eventType) => eventType === 'tool.call.completed' && (completions += 1) === 1 },
    );
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const relaying: KyaOsToolHandler = async () => ({
      content: [{ type: 'text', text: 'relayed' }],
      _meta: { [KYA_OS_PROOF_META_KEY]: { jws: 'relayed.from.upstream', meta: { did: 'did:web:upstream.example' } } },
    });
    const handler = kyaos.wrapWithProof(
      TOOL,
      kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, relaying)),
    );

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(completions).toBe(1);
    expect(result.isError).toBe(true);
    expect(proofOf(result)).toBeUndefined();
  });

  it('audits a bare handler\u2019s error result once and leaves it unproven', async () => {
    vi.spyOn(logger, 'error').mockImplementation(() => {});
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf } = await threeHops(server.did);
    ancestors.push(root, middle);
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, async () => ({
      content: [{ type: 'text', text: 'upstream failed' }],
      isError: true,
    }));

    const result = await handler({ ...ARGS, _kyaos_delegation: leaf });

    expect(result).toEqual({ content: [{ type: 'text', text: 'upstream failed' }], isError: true });
    const lifecycle = recorded.filter((event) => event.eventType.startsWith('tool.call.'));
    expect(lifecycle.map((event) => event.eventType)).toEqual(['tool.call.started', 'tool.call.failed']);
    // The transport records it, as before, knowing only the tool and its
    // arguments.
    for (const event of lifecycle) {
      expect(delegationEvidence(event).delegationRef).toBeUndefined();
    }
    // No proof is made of an error result.
    expect(recorded.filter((event) => event.eventType.startsWith('proof.'))).toHaveLength(0);
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
