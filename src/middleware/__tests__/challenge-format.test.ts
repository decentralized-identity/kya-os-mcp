/**
 * The delegation gate's `needs_authorization` challenge: what `formatChallenge`
 * may set on it, and what the gate sets by default.
 */
import { describe, it, expect, vi } from 'vitest';
import type { KyaOsChallengeFormatter, KyaOsMiddleware } from '../with-kya-os.js';
import { createKyaOsTransport, type JSONRPCMessage, type Transport } from '../kya-os-transport.js';
import { LIFECYCLE_STAMP_META_KEY } from '../with-kya-os.session.js';
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
} from '../../proof/generator.js';
import { logger } from '../../logging/index.js';
import type { PolicyEngine } from '../../policy/engine.js';
import { createMiddleware, handshake, proofOf, verifyReceived } from './helpers/received-proof.js';

const RESOURCE_METADATA = 'https://shop.example/.well-known/oauth-protected-resource';

function gate(kyaos: KyaOsMiddleware, formatChallenge?: KyaOsChallengeFormatter) {
  return kyaos.wrapWithDelegation(
    'checkout',
    {
      scopeId: 'cart:write',
      consentUrl: 'https://consent.example/authorize',
      ...(formatChallenge ? { formatChallenge } : {}),
    },
    async () => ({ content: [{ type: 'text', text: 'should not reach' }] }),
  );
}

/** A challenge result as an OAuth-protected server renders it for ChatGPT-style clients. */
const asErrorResult: KyaOsChallengeFormatter = (challenge) => ({
  content: [{ type: 'text', text: `Authorize at ${challenge.authorizationUrl}` }],
  structuredContent: {
    error: 'insufficient_scope',
    scope: challenge.scopes.join(' '),
    resource_metadata: RESOURCE_METADATA,
  },
  isError: true,
  _meta: {
    'mcp/www_authenticate': [`Bearer resource_metadata="${RESOURCE_METADATA}", scope="cart:write"`],
  },
});

describe('the delegation gate challenge', () => {
  it('is not an error result by default, while the policy gate step-up is (pinned)', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);
    const stepUp: PolicyEngine = {
      evaluate: async () => ({ decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' }),
    };

    const challenge = await gate(kyaos)({}, sessionId);
    const stepUpResult = await kyaos.withPolicyGate!(
      'wipe',
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      { engine: stepUp },
    )({}, sessionId);

    expect(Object.hasOwn(challenge, 'isError')).toBe(false);
    expect(stepUpResult.isError).toBe(true);
  });

  it('keeps the array form exactly: content alone', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await gate(kyaos, () => [{ type: 'text', text: 'Authorize, then retry.' }])({}, sessionId);

    expect(Object.keys(result)).toEqual(['content', '_meta']);
    expect(result.content).toEqual([{ type: 'text', text: 'Authorize, then retry.' }]);
  });

  it('takes a whole result from formatChallenge and signs all of it under the envelope profile', async () => {
    const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE });
    const sessionId = await handshake(kyaos);

    const result = await gate(kyaos, asErrorResult)({ item: 'x' }, sessionId);

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ resource_metadata: RESOURCE_METADATA });
    expect((result._meta as Record<string, unknown>)['mcp/www_authenticate']).toBeDefined();
    expect(proofOf(result)!.meta.outcome).toBe('needs_authorization');
    const expected = {
      signer: kyaos.identity.did, toolName: 'checkout', params: { item: 'x' }, binds: 'envelope' as const,
    };
    expect((await verifyReceived(result, expected)).valid).toBe(true);
    expect((await verifyReceived({ ...result, isError: false }, expected)).valid).toBe(false);
    expect((await verifyReceived({ ...result, structuredContent: {} }, expected)).valid).toBe(false);
  });

  it('signs only the content of a whole result under the body profile', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await gate(kyaos, asErrorResult)({ item: 'x' }, sessionId);

    expect(result.isError).toBe(true);
    expect((await verifyReceived(result, {
      signer: kyaos.identity.did, toolName: 'checkout', params: { item: 'x' }, binds: 'content',
    })).valid).toBe(true);
  });

  it('drops the reserved _meta members formatChallenge returns, and keeps the rest', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);
    const forged = { jws: 'forged', meta: {} };

    const result = await gate(kyaos, (challenge) => ({
      content: [{ type: 'text', text: challenge.authorizationUrl }],
      _meta: {
        traceparent: '00-abc-01',
        [KYA_OS_PROOF_META_KEY]: forged,
        [LEGACY_PROOF_META_KEY]: forged,
        'org.kya-os/proof': forged,
        proofError: 'forged',
        'org.kya-os/audit': { terminal: false },
        [LIFECYCLE_STAMP_META_KEY]: 'forged',
      },
    }))({}, sessionId);

    const meta = result._meta as Record<string, unknown>;
    expect(meta.traceparent).toBe('00-abc-01');
    expect(proofOf(result)!.meta.did).toBe(kyaos.identity.did);
    expect(meta[LEGACY_PROOF_META_KEY]).toEqual(proofOf(result));
    expect(Object.hasOwn(meta, 'org.kya-os/proof')).toBe(false);
    expect(Object.hasOwn(meta, 'proofError')).toBe(false);
    expect(meta['org.kya-os/audit']).toEqual({ terminal: true, outcome: 'needs_authorization' });
    expect(Object.hasOwn(meta, LIFECYCLE_STAMP_META_KEY)).toBe(false);
  });

  it('ignores result members of the wrong type', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await gate(kyaos, () => ({
      content: [{ type: 'text', text: 'Authorize first' }],
      structuredContent: ['not', 'an', 'object'],
      isError: 'yes',
      _meta: 'not an object',
    }) as never)({}, sessionId);

    expect(Object.keys(result)).toEqual(['content', '_meta']);
    expect(result.content).toEqual([{ type: 'text', text: 'Authorize first' }]);
    expect(proofOf(result)!.meta.outcome).toBe('needs_authorization');
  });

  it.each([
    ['a string', 'Authorize first'],
    ['an object without content', { text: 'Authorize first' }],
    ['null', null],
  ])('falls back to the default challenge when formatChallenge returns %s', async (_label, value) => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      const result = await gate(kyaos, () => value as never)({}, sessionId);

      expect(JSON.parse(result.content[0]!.text)).toMatchObject({ error: 'needs_authorization' });
      expect(Object.hasOwn(result, 'isError')).toBe(false);
      expect(proofOf(result)!.meta.outcome).toBe('needs_authorization');
      expect(error).toHaveBeenCalledWith(
        expect.stringContaining('formatChallenge'),
        expect.objectContaining({ tool: 'checkout' }),
      );
    } finally {
      error.mockRestore();
    }
  });

  it('passes an error-result challenge through the withKyaOs transport as proven', async () => {
    const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE });
    const sessionId = await handshake(kyaos);
    const sent: JSONRPCMessage[] = [];
    const inner: Transport = {
      start: async () => {},
      close: async () => {},
      send: async (message) => {
        sent.push(message);
      },
    };
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    inner.onmessage!({
      jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'checkout', arguments: { item: 'x' } },
    });

    const result = await gate(kyaos, asErrorResult)({ item: 'x' }, sessionId);
    await wrapper.send({ jsonrpc: '2.0', id: 4, result: structuredClone(result) });

    const received = (sent[0] as { result: Record<string, unknown> }).result;
    expect(received.isError).toBe(true);
    expect((await verifyReceived(received, {
      signer: kyaos.identity.did, toolName: 'checkout', params: { item: 'x' }, binds: 'envelope',
    })).valid).toBe(true);
  });
});
