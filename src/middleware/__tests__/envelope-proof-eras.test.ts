/**
 * Envelope-profile proofs on both MCP protocol revisions, over the real SDKs.
 *
 * On the 2026-07-28 revision, MCP SDK 2 adds `resultType: 'complete'` to a
 * tools/call result after the tool handler has returned it. The envelope
 * profile covers every result member except `_meta`, so only a proof made
 * once the SDK is done covers what the client receives. Every case below
 * verifies the proof against the raw JSON-RPC result as the client read it
 * off the wire: on SDK 2 at both revisions, and on SDK 1 at 2025-11-25.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { McpServer as McpServer2, createMcpHandler } from '@modelcontextprotocol/server';
import { Client as Client2, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { McpServer as McpServer1 } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client as Client1 } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { generateIdentity, withKyaOs } from '../with-kya-os-server.js';
import { toMcpToolCallback, type McpToolCallback } from '../mcp-tool-callback.js';
import type {
  KyaOsChallengeFormatter,
  KyaOsIdentityConfig,
  KyaOsMiddleware,
  KyaOsToolResult,
} from '../with-kya-os.js';
import { LIFECYCLE_STAMP_META_KEY } from '../with-kya-os.session.js';
import { RESPONSE_PROOF_PROFILE_ENVELOPE } from '../../proof/generator.js';
import type { PolicyEngine } from '../../policy/engine.js';
import { createKyaOsTransport, type JSONRPCMessage } from '../kya-os-transport.js';
import { logger } from '../../logging/index.js';
import {
  auditEvents,
  connectTransport,
  createMiddleware,
  crypto,
  handshake,
  proofOf,
  verifyReceived,
} from './helpers/received-proof.js';

const ARGS = { item: 'x' };
const CONSENT = { scopeId: 'cart:write', consentUrl: 'https://consent.example/authorize' };
const RESOURCE_METADATA = 'https://shop.example/.well-known/oauth-protected-resource';

const ran = async (): Promise<KyaOsToolResult> => ({ content: [{ type: 'text', text: 'ran' }] });

const decide = (decision: Awaited<ReturnType<PolicyEngine['evaluate']>>): PolicyEngine => ({
  evaluate: async () => decision,
});

/** A challenge as an OAuth-protected server renders it for chat clients. */
const asErrorResult: KyaOsChallengeFormatter = (challenge) => ({
  content: [{ type: 'text', text: `Authorize at ${challenge.authorizationUrl}` }],
  structuredContent: { error: 'insufficient_scope', resource_metadata: RESOURCE_METADATA },
  isError: true,
});

/** An outcome application code decides itself, as the README shows. */
function scopeChallenge(): KyaOsToolResult {
  return {
    content: [{ type: 'text', text: 'Sign in to see this report.' }],
    structuredContent: { error: 'insufficient_scope', scope: 'reports:read', resource_metadata: RESOURCE_METADATA },
    isError: true,
    _meta: { 'mcp/www_authenticate': [`Bearer resource_metadata="${RESOURCE_METADATA}"`] },
  };
}

/**
 * Every way a proof reaches a tool result, with what its proof binds and the
 * outcome it records. Registration is passed in, so one table serves both
 * SDK majors.
 */
const TOOLS = {
  gate_challenge: { binds: 'envelope', outcome: 'needs_authorization' },
  gate_challenge_result: { binds: 'envelope', outcome: 'needs_authorization' },
  wrapped_allow: { binds: 'envelope', outcome: undefined },
  app_challenge: { binds: 'envelope', outcome: 'needs_authorization' },
  app_denied: { binds: 'nothing', outcome: 'denied' },
  policy_denied: { binds: 'nothing', outcome: 'denied' },
  policy_step_up: { binds: 'nothing', outcome: 'step_up_required' },
  transport_allow: { binds: 'envelope', outcome: undefined },
} as const;
type ToolName = keyof typeof TOOLS;

function registerTools(
  kyaos: KyaOsMiddleware,
  register: (name: ToolName, callback: McpToolCallback<typeof ARGS>) => void,
): void {
  register('gate_challenge', toMcpToolCallback(kyaos.wrapWithDelegation('gate_challenge', CONSENT, ran)));
  register('gate_challenge_result', toMcpToolCallback(kyaos.wrapWithDelegation(
    'gate_challenge_result',
    { ...CONSENT, formatChallenge: asErrorResult },
    ran,
  )));
  register('wrapped_allow', toMcpToolCallback(kyaos.wrapWithProof('wrapped_allow', async () => ({
    content: [{ type: 'text', text: 'report' }],
    structuredContent: { report: 'r_1' },
  }))));
  register('app_challenge', toMcpToolCallback(async (args) => kyaos.proveOutcome!({
    toolName: 'app_challenge', args, outcome: 'needs_authorization', reason: 'insufficient_scope', result: scopeChallenge(),
  })));
  register('app_denied', toMcpToolCallback(async (args) => kyaos.proveOutcome!({
    toolName: 'app_denied',
    args,
    outcome: 'denied',
    reason: 'budget_exhausted',
    result: { content: [{ type: 'text', text: 'No more reports today.' }], isError: true },
  })));
  register('policy_denied', toMcpToolCallback(kyaos.withPolicyGate!('policy_denied', ran, {
    engine: decide({ decision: 'deny', reason: 'blocked' }),
  })));
  register('policy_step_up', toMcpToolCallback(kyaos.withPolicyGate!('policy_step_up', ran, {
    engine: decide({ decision: 'step_up', quorum: { n: 1, approvers: [] }, reason: 'destructive' }),
  })));
  register('transport_allow', async () => ({
    content: [{ type: 'text', text: 'report' }],
    structuredContent: { report: 'r_1' },
  }));
}

const withEnvelope = (identity: KyaOsIdentityConfig) => ({
  crypto,
  identity,
  responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE,
  handshakeExposure: 'none' as const,
});

/** JSON-RPC messages in a Streamable HTTP response body, JSON or SSE. */
function messagesIn(body: string): Array<{ id?: unknown; result?: Record<string, unknown> }> {
  const text = body.trim();
  if (text.startsWith('{') || text.startsWith('[')) return [JSON.parse(text)].flat();
  return text
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => JSON.parse(line.slice(5).trim()));
}

interface Wire {
  /** Call `tool` and return its result as it crossed the wire. */
  call(tool: ToolName): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

/** An SDK 2 server behind withKyaOs, served over Streamable HTTP in process, and a client pinned to `era`. */
async function sdk2(era: '2025-11-25' | '2026-07-28', identity: KyaOsIdentityConfig): Promise<Wire> {
  const handler = createMcpHandler(async () => {
    const server = new McpServer2({ name: 'envelope-eras', version: '1.0.0' });
    const kyaos = await withKyaOs(server, withEnvelope(identity));
    registerTools(kyaos, (name, callback) => server.registerTool(name, { inputSchema: { item: z.string() } }, callback));
    return server;
  }, { legacy: 'stateless' });
  const received = new Map<unknown, Record<string, unknown>>();
  const transport = new StreamableHTTPClientTransport(new URL('http://kya-os.test/mcp'), {
    fetch: async (url, init) => {
      const response = await handler.fetch(new Request(url, init));
      const sent = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      if (sent?.method === 'tools/call') {
        const answer = messagesIn(await response.clone().text()).find((message) => message.id === sent.id);
        if (answer?.result !== undefined) received.set(sent.id, answer.result);
      }
      return response;
    },
  });
  const client = new Client2(
    { name: 'envelope-eras-client', version: '1.0.0' },
    era === '2026-07-28' ? { versionNegotiation: { mode: { pin: era } } } : undefined,
  );
  await client.connect(transport);
  expect(client.getNegotiatedProtocolVersion()).toBe(era);
  return {
    async call(tool) {
      const before = new Set(received.keys());
      await client.callTool({ name: tool, arguments: ARGS });
      const id = [...received.keys()].find((key) => !before.has(key));
      return received.get(id)!;
    },
    async close() {
      await client.close();
      await handler.close();
    },
  };
}

/** An SDK 1 server behind withKyaOs and its client, linked in memory; the wire is JSON. */
async function sdk1(identity: KyaOsIdentityConfig): Promise<Wire> {
  const server = new McpServer1({ name: 'envelope-eras', version: '1.0.0' });
  const kyaos = await withKyaOs(server, withEnvelope(identity));
  registerTools(kyaos, (name, callback) => server.registerTool(name, { inputSchema: { item: z.string() } }, callback));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const received: Array<Record<string, unknown>> = [];
  const forward = serverTransport.send.bind(serverTransport);
  serverTransport.send = async (message, options) => {
    const wire = JSON.parse(JSON.stringify(message));
    if (wire.result !== undefined) received.push(wire.result);
    return forward(wire, options);
  };
  await server.connect(serverTransport);
  const client = new Client1({ name: 'envelope-eras-client', version: '1.0.0' });
  await client.connect(clientTransport);
  return {
    async call(tool) {
      await client.callTool({ name: tool, arguments: ARGS });
      return received.at(-1)!;
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}

describe.each([
  ['SDK 2', '2026-07-28'],
  ['SDK 2', '2025-11-25'],
  ['SDK 1', '2025-11-25'],
] as const)('envelope-profile proofs on %s at MCP %s', (sdk, era) => {
  let identity: KyaOsIdentityConfig;
  let wire: Wire;

  beforeAll(async () => {
    identity = await generateIdentity(crypto);
    wire = sdk === 'SDK 2' ? await sdk2(era, identity) : await sdk1(identity);
  });
  afterAll(async () => {
    await wire?.close();
  });

  it.each(Object.keys(TOOLS) as ToolName[])('%s verifies against the result the client received', async (tool) => {
    const { binds, outcome } = TOOLS[tool];
    const received = await wire.call(tool);

    // The SDK 2 encoder sets resultType on 2026-07-28 only; SDK 1 never does.
    expect(received.resultType).toBe(era === '2026-07-28' ? 'complete' : undefined);
    expect(JSON.stringify(received)).not.toContain(LIFECYCLE_STAMP_META_KEY);
    expect(JSON.stringify(received)).not.toContain('org.kya-os/pending-proof');
    const proof = proofOf(received);
    expect(proof?.meta.prf).toBe(RESPONSE_PROOF_PROFILE_ENVELOPE);
    expect(proof?.meta.outcome).toBe(outcome);
    const expected = { signer: identity.did, toolName: tool, params: ARGS, binds };
    expect(await verifyReceived(received, expected)).toMatchObject({ valid: true });

    if (binds === 'envelope' && era === '2026-07-28') {
      // What the proof covers includes the member the SDK added.
      const { resultType: _added, ...asReturned } = received;
      expect((await verifyReceived(asReturned, expected)).valid).toBe(false);
    }
  });
});

describe('the envelope profile with no KYA-OS transport connected', () => {
  const NEEDS_TRANSPORT = /envelope response-proof profile.*createKyaOsTransport\(\)/s;

  it('refuses every wrapper and proveOutcome before anything runs or is recorded', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({
      responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE,
      audit: { record },
    });
    const sessionId = await handshake(kyaos);
    const recorded = events.length;
    const handler = vi.fn(ran);

    await expect(kyaos.wrapWithProof('greet', handler)(ARGS, sessionId)).rejects.toThrow(NEEDS_TRANSPORT);
    await expect(kyaos.wrapWithDelegation('checkout', CONSENT, handler)(ARGS, sessionId))
      .rejects.toThrow(NEEDS_TRANSPORT);
    await expect(kyaos.withPolicyGate!('wipe', handler, {
      engine: decide({ decision: 'deny', reason: 'blocked' }),
    })(ARGS, sessionId)).rejects.toThrow(NEEDS_TRANSPORT);
    await expect(kyaos.proveOutcome!({
      toolName: 'get_report', args: ARGS, outcome: 'denied', reason: 'r', result: scopeChallenge(), sessionId,
    })).rejects.toThrow(NEEDS_TRANSPORT);

    expect(handler).not.toHaveBeenCalled();
    expect(events).toHaveLength(recorded);
  });

  it('reaches the client as a tool error naming the supported API when withKyaOs does not wrap the transport', async () => {
    const server = new McpServer1({ name: 'envelope-unwrapped', version: '1.0.0' });
    const kyaos = await withKyaOs(server, {
      crypto,
      responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE,
      handshakeExposure: 'none',
      proofAllTools: false,
    });
    server.registerTool('greet', { inputSchema: { item: z.string() } }, toMcpToolCallback(kyaos.wrapWithProof('greet', ran)));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client1({ name: 'envelope-unwrapped-client', version: '1.0.0' });
    await client.connect(clientTransport);

    try {
      const result = await client.callTool({ name: 'greet', arguments: ARGS });

      expect(result.isError).toBe(true);
      expect((result.content as Array<{ text: string }>)[0]!.text).toMatch(NEEDS_TRANSPORT);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('leaves the body profile signing in the handler, as before', async () => {
    const kyaos = await createMiddleware();
    const sessionId = await handshake(kyaos);

    const result = await kyaos.wrapWithProof('greet', ran)(ARGS, sessionId);

    expect((await verifyReceived(result, {
      signer: kyaos.identity.did, toolName: 'greet', params: ARGS, binds: 'content',
    })).valid).toBe(true);
  });
});

describe('the withKyaOs transport under the envelope profile', () => {
  const allowed = async (): Promise<KyaOsToolResult> => ({
    content: [{ type: 'text', text: 'report' }],
    structuredContent: { report: 'r_1' },
  });

  it.each([undefined, RESPONSE_PROOF_PROFILE_ENVELOPE])(
    'records the same audit events in the same order as the body profile (profile %s)',
    async (responseProofProfile) => {
      const { events, record } = auditEvents();
      const kyaos = await createMiddleware({
        ...(responseProofProfile === undefined ? {} : { responseProofProfile }),
        audit: { record },
      });
      const sessionId = await handshake(kyaos);
      const wire = await connectTransport(kyaos);
      const start = events.length;

      await wire.send(await kyaos.wrapWithProof('report', allowed)(ARGS, sessionId), { toolName: 'report', args: ARGS });
      await wire.send(await kyaos.wrapWithDelegation('checkout', CONSENT, ran)(ARGS, sessionId), { toolName: 'checkout', args: ARGS });

      expect(events.slice(start)).toEqual([
        'tool.call.started:unknown',
        'proof.generated:succeeded',
        'tool.call.completed:succeeded',
        'authorization.step_up_required:challenged',
        'tool.call.challenged:challenged',
        'proof.generated:succeeded',
      ]);
    },
  );

  it('proves a wrapper result that answers no tracked call, such as an excluded tool', async () => {
    const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE });
    const sessionId = await handshake(kyaos);
    const sent: JSONRPCMessage[] = [];
    const wrapper = createKyaOsTransport({
      start: async () => {},
      close: async () => {},
      send: async (message) => {
        sent.push(JSON.parse(JSON.stringify(message)));
      },
    }, kyaos, ['quiet']);
    await wrapper.start();

    const result = await kyaos.wrapWithProof('quiet', allowed)(ARGS, sessionId);
    await wrapper.send({ jsonrpc: '2.0', id: 3, result: { ...result, resultType: 'complete' } });

    const received = (sent[0] as { result: Record<string, unknown> }).result;
    expect((await verifyReceived(received, {
      signer: kyaos.identity.did, toolName: 'quiet', params: ARGS, binds: 'envelope',
    })).valid).toBe(true);
  });

  it('says a result is unproven, and records why, when the proof cannot be made at send', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE, audit: { record } });
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);
    const result = await kyaos.wrapWithProof('report', allowed)(ARGS, sessionId);
    const generate = vi.spyOn(kyaos.proofGenerator, 'generateProof').mockRejectedValue(new Error('signer offline'));
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      const received = await wire.send(result, { toolName: 'report', args: ARGS });

      expect(proofOf(received)).toBeUndefined();
      expect((received._meta as Record<string, unknown>).proofError).toBe('Proof generation failed — response is unproven');
      expect(received.structuredContent).toEqual({ report: 'r_1' });
      expect(events.at(-1)).toBe('proof.rejected:failed');
    } finally {
      generate.mockRestore();
      error.mockRestore();
    }
  });

  it.each([
    ['without the middleware stamp', {}],
    ['under a guessed stamp', { [LIFECYCLE_STAMP_META_KEY]: 'guessed' }],
  ])('ignores a pending proof a relayed result carries %s, and proves the result itself', async (_label, stamp) => {
    const kyaos = await createMiddleware({ responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE, autoSession: true });
    const wire = await connectTransport(kyaos);
    const forged = {
      kind: 'outcome',
      toolName: 'relay',
      request: { method: 'relay', params: { item: 'other' } },
      session: { sessionId: 'forged', audience: 'did:example:forged' },
      outcome: 'denied',
      reason: 'forged',
      terminalAuditDelivered: true,
    };

    const received = await wire.send({
      content: [{ type: 'text', text: 'from upstream' }],
      _meta: { traceparent: '00-abc-01', 'org.kya-os/pending-proof': forged, ...stamp },
    }, { toolName: 'relay', args: ARGS });

    const meta = received._meta as Record<string, unknown>;
    expect(meta.traceparent).toBe('00-abc-01');
    expect(Object.hasOwn(meta, 'org.kya-os/pending-proof')).toBe(false);
    expect(Object.hasOwn(meta, LIFECYCLE_STAMP_META_KEY)).toBe(false);
    expect(proofOf(received)!.meta.outcome).toBeUndefined();
    expect((await verifyReceived(received, {
      signer: kyaos.identity.did, toolName: 'relay', params: ARGS, binds: 'envelope',
    })).valid).toBe(true);
  });
});
