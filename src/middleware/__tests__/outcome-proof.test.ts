/**
 * `proveOutcome`: application code proving the authorization outcomes it
 * decides itself (a challenge or a denial returned as a tool result) with the
 * proof the middleware's own gates attach to theirs.
 */
import { describe, it, expect } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { withKyaOs } from '../with-kya-os-server.js';
import { toMcpToolCallback } from '../mcp-tool-callback.js';
import { createKyaOsTransport, type JSONRPCMessage, type Transport } from '../kya-os-transport.js';
import type { KyaOsMiddleware, KyaOsOutcomeProofRequest, KyaOsToolResult } from '../with-kya-os.js';
import { LIFECYCLE_STAMP_META_KEY } from '../with-kya-os.session.js';
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_ENVELOPE,
} from '../../proof/generator.js';
import {
  auditEvents,
  createMiddleware,
  crypto,
  handshake,
  proofOf,
  verifyReceived,
} from './helpers/received-proof.js';

const RESOURCE_METADATA = 'https://api.example/.well-known/oauth-protected-resource';

/** An OAuth-style challenge as an MCP server enforcing scopes in-server returns it. */
function scopeChallenge(): KyaOsToolResult {
  return {
    content: [{ type: 'text', text: 'Sign in to see this report.' }],
    structuredContent: {
      error: 'insufficient_scope',
      scope: 'reports:read',
      resource_metadata: RESOURCE_METADATA,
    },
    isError: true,
    _meta: {
      'mcp/www_authenticate': [
        `Bearer resource_metadata="${RESOURCE_METADATA}", error="insufficient_scope", scope="reports:read"`,
      ],
    },
  };
}

function prove(kyaos: KyaOsMiddleware, request: KyaOsOutcomeProofRequest): Promise<KyaOsToolResult> {
  return kyaos.proveOutcome!(request);
}

describe('proveOutcome', () => {
  it('proves a challenge returned as an error result, binding its whole envelope under the envelope profile', async () => {
    const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE });
    const sessionId = await handshake(kyaos);

    const result = await prove(kyaos, {
      toolName: 'get_report',
      args: { report_id: 'r_1' },
      outcome: 'needs_authorization',
      reason: 'insufficient_scope',
      result: scopeChallenge(),
      sessionId,
    });

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toEqual(scopeChallenge().structuredContent);
    const meta = result._meta as Record<string, unknown>;
    expect(meta['mcp/www_authenticate']).toEqual(scopeChallenge()._meta!['mcp/www_authenticate']);
    expect(meta['org.kya-os/audit']).toEqual({ terminal: true, outcome: 'needs_authorization' });
    expect(proofOf(result)!.meta).toMatchObject({
      outcome: 'needs_authorization',
      reason: 'insufficient_scope',
      sessionId,
      prf: RESPONSE_PROOF_PROFILE_ENVELOPE,
    });
    const expected = {
      signer: kyaos.identity.did,
      toolName: 'get_report',
      params: { report_id: 'r_1' },
      binds: 'envelope' as const,
    };
    expect((await verifyReceived(result, expected)).valid).toBe(true);
    // isError and structuredContent are signed: neither can be changed in transit.
    expect((await verifyReceived({ ...result, isError: false }, expected)).valid).toBe(false);
    expect((await verifyReceived(
      { ...result, structuredContent: { ...result.structuredContent as object, resource_metadata: 'https://evil.example' } },
      expected,
    )).valid).toBe(false);
  });

  it('binds only the content of a challenge under the default body profile', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await prove(kyaos, {
      toolName: 'get_report',
      args: { report_id: 'r_1' },
      outcome: 'needs_authorization',
      reason: 'insufficient_scope',
      result: scopeChallenge(),
      sessionId,
    });

    expect(proofOf(result)!.meta.prf).toBeUndefined();
    expect((await verifyReceived(result, {
      signer: kyaos.identity.did, toolName: 'get_report', params: { report_id: 'r_1' }, binds: 'content',
    })).valid).toBe(true);
  });

  it.each(['denied', 'step_up_required'] as const)(
    'leaves a %s proof body-free, as the gates do',
    async (outcome) => {
      const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE });
      const sessionId = await handshake(kyaos);

      const result = await prove(kyaos, {
        toolName: 'get_report',
        args: { report_id: 'r_1' },
        outcome,
        reason: 'budget_exhausted',
        result: {
          content: [{ type: 'text', text: 'No more reports today.' }],
          structuredContent: { error: 'access_denied', reason: 'budget_exhausted' },
          isError: true,
        },
        sessionId,
      });

      expect(proofOf(result)!.meta).toMatchObject({ outcome, reason: 'budget_exhausted' });
      expect(proofOf(result)!.meta.responseHash).toBeUndefined();
      expect((await verifyReceived(result, {
        signer: kyaos.identity.did, toolName: 'get_report', params: { report_id: 'r_1' }, binds: 'nothing',
      })).valid).toBe(true);
    },
  );

  it('places the proof under the same _meta keys as a gate outcome', async () => {
    for (const emitLegacyProofKey of [true, false]) {
      const kyaos = await createMiddleware({ emitLegacyProofKey });
      const sessionId = await handshake(kyaos);
      const gate = await kyaos.wrapWithDelegation(
        'checkout',
        { scopeId: 'cart:write', consentUrl: 'https://consent.example' },
        async () => ({ content: [{ type: 'text', text: 'ran' }] }),
      )({}, sessionId);

      const own = await prove(kyaos, {
        toolName: 'checkout', args: {}, outcome: 'needs_authorization', reason: 'r', result: scopeChallenge(), sessionId,
      });

      const proofKeys = (result: KyaOsToolResult) =>
        Object.keys(result._meta as object).filter((key) => key !== 'mcp/www_authenticate').sort();
      expect(proofKeys(own)).toEqual(proofKeys(gate));
      expect(Object.keys(proofOf(own)!.meta).sort()).toEqual(Object.keys(proofOf(gate)!.meta).sort());
    }
  });

  it('records the audit events the delegation gate records for its own challenge', async () => {
    const gateAudit = auditEvents();
    const gateKyaos = await createMiddleware({ audit: { record: gateAudit.record } });
    await gateKyaos.wrapWithDelegation(
      'checkout',
      { scopeId: 'cart:write', consentUrl: 'https://consent.example' },
      async () => ({ content: [{ type: 'text', text: 'ran' }] }),
    )({}, await handshake(gateKyaos));
    const ownAudit = auditEvents();
    const ownKyaos = await createMiddleware({ audit: { record: ownAudit.record } });
    const sessionId = await handshake(ownKyaos);
    const sessionEvents = ownAudit.events.length;

    await prove(ownKyaos, {
      toolName: 'checkout', args: {}, outcome: 'needs_authorization', reason: 'r', result: scopeChallenge(), sessionId,
    });

    expect(ownAudit.events).toEqual(gateAudit.events);
    expect(ownAudit.events.slice(sessionEvents)).toEqual([
      'authorization.step_up_required:challenged',
      'tool.call.challenged:challenged',
      'proof.generated:succeeded',
    ]);
  });

  it('records a denial as the policy gate records its own', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ audit: { record } });
    const sessionId = await handshake(kyaos);
    const before = events.length;

    await prove(kyaos, {
      toolName: 'wipe', args: {}, outcome: 'denied', reason: 'blocked',
      result: { content: [{ type: 'text', text: 'no' }], isError: true }, sessionId,
    });

    expect(events.slice(before)).toEqual([
      'authorization.denied:denied',
      'tool.call.denied:denied',
      'proof.generated:succeeded',
    ]);
  });

  it('leaves the reserved _kyaos* arguments out of the signed request, as the gates do', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await prove(kyaos, {
      toolName: 'get_report',
      args: { report_id: 'r_1', _kyaos_delegation: 'vc', _kyaos_proof: 'p' },
      outcome: 'denied',
      reason: 'r',
      result: { content: [{ type: 'text', text: 'no' }], isError: true },
      sessionId,
    });

    expect((await verifyReceived(result, {
      signer: kyaos.identity.did, toolName: 'get_report', params: { report_id: 'r_1' }, binds: 'nothing',
    })).valid).toBe(true);
  });

  it('drops the reserved _meta members the application set, and keeps the rest', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);
    const forged = { jws: 'forged', meta: {} };

    const result = await prove(kyaos, {
      toolName: 'wipe',
      args: {},
      outcome: 'denied',
      reason: 'r',
      result: {
        content: [{ type: 'text', text: 'no' }],
        isError: true,
        _meta: {
          traceparent: '00-abc-01',
          [KYA_OS_PROOF_META_KEY]: forged,
          [LEGACY_NAMESPACED_PROOF_META_KEY]: forged,
          [LEGACY_PROOF_META_KEY]: forged,
          proofError: 'forged',
          'org.kya-os/audit': { terminal: true, outcome: 'forged' },
          [LIFECYCLE_STAMP_META_KEY]: 'forged',
        },
      },
      sessionId,
    });

    const meta = result._meta as Record<string, unknown>;
    expect(meta.traceparent).toBe('00-abc-01');
    expect(proofOf(result)!.meta.did).toBe(kyaos.identity.did);
    expect(meta[LEGACY_PROOF_META_KEY]).toEqual(proofOf(result));
    expect(Object.hasOwn(meta, LEGACY_NAMESPACED_PROOF_META_KEY)).toBe(false);
    expect(Object.hasOwn(meta, 'proofError')).toBe(false);
    expect(meta['org.kya-os/audit']).toEqual({ terminal: true, outcome: 'denied' });
    expect(Object.hasOwn(meta, LIFECYCLE_STAMP_META_KEY)).toBe(false);
  });

  it('does not modify the result it was given', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);
    const given = scopeChallenge();
    const snapshot = structuredClone(given);

    await prove(kyaos, {
      toolName: 'get_report', args: {}, outcome: 'needs_authorization', reason: 'r', result: given, sessionId,
    });

    expect(given).toEqual(snapshot);
  });

  it('needs no session from the application, and opens none of its own', async () => {
    const kyaos = await createMiddleware({ autoSession: true });

    const challenge = await prove(kyaos, {
      toolName: 'get_report', args: {}, outcome: 'needs_authorization', reason: 'r', result: scopeChallenge(),
    });
    const allowed = await kyaos.wrapWithProof('get_report', async () => ({
      content: [{ type: 'text', text: 'report' }],
    }))({});

    expect(proofOf(challenge)?.meta.outcome).toBe('needs_authorization');
    // The auto session the challenge was proved under still proves the next allow.
    expect(proofOf(allowed)?.meta.sessionId).toBe(proofOf(challenge)!.meta.sessionId);
    expect(kyaos.sessionManager.getStats().activeSessions).toBe(1);
  });

  it('refuses an outcome it does not know', async () => {
    const kyaos = await createMiddleware();

    await expect(prove(kyaos, {
      toolName: 'wipe',
      args: {},
      outcome: 'allowed' as never,
      reason: 'r',
      result: { content: [{ type: 'text', text: 'ok' }] },
    })).rejects.toThrow(TypeError);
  });

  it('passes through the withKyaOs transport untouched, less the private stamp', async () => {
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
      jsonrpc: '2.0', id: 9, method: 'tools/call',
      params: { name: 'get_report', arguments: { report_id: 'r_1' } },
    });

    const result = await prove(kyaos, {
      toolName: 'get_report',
      args: { report_id: 'r_1' },
      outcome: 'needs_authorization',
      reason: 'insufficient_scope',
      result: scopeChallenge(),
      sessionId,
    });
    await wrapper.send({ jsonrpc: '2.0', id: 9, result: structuredClone(result) });

    const { [LIFECYCLE_STAMP_META_KEY]: stamp, ...meta } = result._meta as Record<string, unknown>;
    expect(stamp).toEqual(expect.any(String));
    const received = (sent[0] as { result: Record<string, unknown> }).result;
    expect(received).toEqual({ ...result, _meta: meta });
    expect((await verifyReceived(received, {
      signer: kyaos.identity.did, toolName: 'get_report', params: { report_id: 'r_1' }, binds: 'envelope',
    })).valid).toBe(true);
  });

  it('keeps its outcome proof inside wrapWithProof, which never re-signs it as allowed', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await kyaos.wrapWithProof('checkout', async (args, threaded) => prove(kyaos, {
      toolName: 'checkout',
      args,
      outcome: 'needs_authorization',
      reason: 'r',
      result: { content: [{ type: 'text', text: 'Authorize first.' }] },
      ...(threaded === undefined ? {} : { sessionId: threaded }),
    }))({ item: 'x' }, sessionId);

    expect(proofOf(result)?.meta.outcome).toBe('needs_authorization');
    expect((await verifyReceived(result, {
      signer: kyaos.identity.did, toolName: 'checkout', params: { item: 'x' }, binds: 'content',
    })).valid).toBe(true);
  });
});

describe('proveOutcome on an McpServer behind withKyaOs', () => {
  it('reaches the client proven, and verifies against what the client received', async () => {
    const server = new McpServer({ name: 'outcome-proofs', version: '1.0.0' });
    const kyaos = await withKyaOs(server, {
      crypto,
      responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE,
      handshakeExposure: 'none',
    });
    server.registerTool(
      'get_report',
      { inputSchema: { report_id: z.string() } },
      toMcpToolCallback(async (args) => prove(kyaos, {
        toolName: 'get_report',
        args,
        outcome: 'needs_authorization',
        reason: 'insufficient_scope',
        result: scopeChallenge(),
      })),
    );
    const client = new Client({ name: 'outcome-proofs-client', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    try {
      const received = await client.callTool({ name: 'get_report', arguments: { report_id: 'r_1' } });

      expect(received.isError).toBe(true);
      expect(received.structuredContent).toEqual(scopeChallenge().structuredContent);
      expect(JSON.stringify(received)).not.toContain(LIFECYCLE_STAMP_META_KEY);
      expect((await verifyReceived(received, {
        signer: kyaos.identity.did, toolName: 'get_report', params: { report_id: 'r_1' }, binds: 'envelope',
      })).valid).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
