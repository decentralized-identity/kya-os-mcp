/**
 * A call that presents no delegation is proved as before, and its proof names
 * none (SPEC.md §7.8).
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import type { KyaOsCallContext, KyaOsToolResult } from '../with-kya-os.js';
import { digestDelegationChain } from '../../delegation/chain-digest.js';
import { logger } from '../../logging/index.js';
import { hash, makeServer, makeUnserved } from './helpers/delegation-gate-server.js';
import { ARGS, CONSENT, TOOL, released } from './helpers/delegated-call.js';
import { threeHops } from './helpers/delegation-chains.js';
import { handshake, proofOf, verifyReceived } from './helpers/received-proof.js';
import { delegationClaims, delegationEvidence, literalRequestHash } from './helpers/server-answers.js';

describe('a call that presents nothing', () => {
  it.each(['_kyaos_approvals', '_kyaos_delegation'])(
    'is proved by a wrapper outside any gate as it was received, %s and all',
    async (control) => {
      vi.spyOn(logger, 'warn').mockImplementation(() => {});
      const { kyaos } = await makeServer();
      const sent = { ...ARGS, [control]: 'as received' };

      const result = await kyaos.wrapWithProof(TOOL, released)(sent);

      const meta = proofOf(result)!.meta;
      expect(meta.requestHash).toBe(literalRequestHash(TOOL, sent));
      expect(meta.requestHash).not.toBe(literalRequestHash(TOOL, ARGS));
      expect(meta).not.toHaveProperty('delegationRef');
    },
  );

  it.each([
    ['the transport answers', async () => {
      const { kyaos } = await makeServer();
      return { kyaos, send: async (result: object) => result };
    }],
    // The gate proves its own outcome, and the result is sent apart from its call.
    ['no transport tracks', async () => {
      const { kyaos, wire } = await makeUnserved();
      return { kyaos, send: (result: KyaOsToolResult) => wire.send(result) };
    }],
  ])('names no delegation on the needs_authorization challenge of a call %s', async (_name, serve) => {
    const { kyaos, send } = await serve();
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, released));

    const result = await send(await handler({ ...ARGS }));

    const meta = proofOf(result)!.meta;
    expect(meta.outcome).toBe('needs_authorization');
    expect(meta).not.toHaveProperty('delegationRef');
    expect(meta).not.toHaveProperty('delegationChainDigest');
  });

  it('records the delegation a durable grant rests on when the retry is authorized by that grant, and its proof names none', async () => {
    const { kyaos, server, ancestors, recorded } = await makeServer();
    const { root, middle, leaf, chain } = await threeHops(server.did);
    ancestors.push(root, middle);
    const sessionId = await handshake(kyaos);
    const contexts: Array<KyaOsCallContext | undefined> = [];
    const handler = kyaos.wrapWithDelegation(TOOL, CONSENT, kyaos.wrapWithProof(TOOL, async (args, session, context) => {
      contexts.push(context);
      return released(args, session, context);
    }));

    const first = await handler({ ...ARGS, _kyaos_delegation: leaf }, sessionId);
    expect(first.isError).toBeUndefined();
    // The retry presents nothing. The grant re-verifies the chain it holds.
    const retry = await handler({ ...ARGS }, sessionId);

    expect(retry.isError).toBeUndefined();
    expect(retry.content[0]!.text).toBe('released r-1');
    expect(delegationClaims(retry)).toEqual({});
    // The audit trail says which delegation the grant stood for, by its reference and digests.
    const perHop = (await digestDelegationChain(chain, hash)).credentials;
    const used = recorded.find((event) => event.eventType === 'grant.used')!;
    expect(used.authorization).toMatchObject({
      source: 'grant',
      delegationRef: leaf.id,
      delegationChainDigests: perHop,
    });
    // As under a presented credential, the list is recorded once: the
    // handler and the retry's other events get the reference and the digest.
    const reference = { delegationRef: leaf.id, delegationCredentialDigest: perHop.at(-1) };
    expect(contexts[1]!.authorization).toMatchObject({ source: 'grant', ...reference });
    expect(contexts[1]!.authorization).not.toHaveProperty('delegationChainDigests');
    for (const event of recorded.slice(recorded.indexOf(used) + 1)) {
      expect(delegationEvidence(event)).toEqual(reference);
    }
    const verified = await verifyReceived(retry, {
      signer: server.did,
      toolName: TOOL,
      params: ARGS,
      binds: 'content',
    });
    expect(verified).toEqual({ valid: true });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
