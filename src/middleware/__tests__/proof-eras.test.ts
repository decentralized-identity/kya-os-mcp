/**
 * Response proofs on both MCP protocol revisions, over the real SDKs, under
 * both response-proof profiles.
 *
 * The MCP SDK changes a tools/call result after the tool handler has returned
 * it. On the 2026-07-28 revision SDK 2 adds `resultType: 'complete'`, which
 * the envelope profile covers. Both SDKs fill in a missing `content`, and SDK
 * 2 appends a text item to `content` when `structuredContent` is not an object
 * and no text item is there; the body profile covers `content`. Only a proof
 * made once the SDK is done covers what the client receives, so every proof is
 * made at the withKyaOs transport. Every case below verifies the proof against
 * the raw JSON-RPC result as the client read it off the wire: on SDK 2 at both
 * revisions, and on SDK 1 at 2025-11-25.
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
import { RESPONSE_PROOF_PROFILE_ENVELOPE, type ResponseProofProfile } from '../../proof/generator.js';
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

/** Each profile, and what its proof of a result covers. */
const PROFILES = {
  body: { responseProofProfile: undefined, binds: 'content' },
  envelope: { responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE, binds: 'envelope' },
} as const satisfies Record<string, { responseProofProfile: ResponseProofProfile | undefined; binds: 'content' | 'envelope' }>;
type ProfileName = keyof typeof PROFILES;
const PROFILE_NAMES = Object.keys(PROFILES) as ProfileName[];

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
 * Every way a proof reaches a tool result, with whether its proof binds the
 * result (as the profile covers it) or nothing, and the outcome it records.
 * The last two are results the SDK reshapes: `text_fallback` gets a text item
 * from SDK 2, which SDK 1 refuses to send at all, and `content_default` gets
 * an empty `content` from both. Registration is passed in, so one table
 * serves both SDK majors.
 */
const TOOLS = {
  gate_challenge: { binds: 'result', outcome: 'needs_authorization' },
  gate_challenge_result: { binds: 'result', outcome: 'needs_authorization' },
  wrapped_allow: { binds: 'result', outcome: undefined },
  app_challenge: { binds: 'result', outcome: 'needs_authorization' },
  app_denied: { binds: 'nothing', outcome: 'denied' },
  policy_denied: { binds: 'nothing', outcome: 'denied' },
  policy_step_up: { binds: 'nothing', outcome: 'step_up_required' },
  transport_allow: { binds: 'result', outcome: undefined },
  text_fallback: { binds: 'result', outcome: undefined },
  content_default: { binds: 'result', outcome: undefined },
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
  register('text_fallback', toMcpToolCallback(kyaos.wrapWithProof('text_fallback', async () => ({
    content: [],
    structuredContent: [1, 2],
  }))));
  // A handler that leaves `content` out, as plain JavaScript can.
  register('content_default', toMcpToolCallback(kyaos.wrapWithProof('content_default', async () => ({
    structuredContent: { report: 'r_1' },
  }) as unknown as KyaOsToolResult)));
}

const options = (identity: KyaOsIdentityConfig, profile: ProfileName) => ({
  crypto,
  identity,
  ...(PROFILES[profile].responseProofProfile === undefined
    ? {}
    : { responseProofProfile: PROFILES[profile].responseProofProfile }),
  handshakeExposure: 'none' as const,
});

/** JSON-RPC messages in a Streamable HTTP response body, JSON or SSE. */
function messagesIn(body: string): Array<{ id?: unknown; result?: Record<string, unknown>; error?: unknown }> {
  const text = body.trim();
  if (text.startsWith('{') || text.startsWith('[')) return [JSON.parse(text)].flat();
  return text
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => JSON.parse(line.slice(5).trim()));
}

/** A tools/call answer as it crossed the wire: a result, or a JSON-RPC error. */
interface Answer {
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

interface Wire {
  /** Call `tool` and return its answer as it crossed the wire. */
  call(tool: ToolName): Promise<Answer>;
  close(): Promise<void>;
}

/** An SDK 2 server behind withKyaOs, served over Streamable HTTP in process, and a client pinned to `era`. */
async function sdk2(
  era: '2025-11-25' | '2026-07-28',
  identity: KyaOsIdentityConfig,
  profile: ProfileName,
): Promise<Wire> {
  const handler = createMcpHandler(async () => {
    const server = new McpServer2({ name: 'proof-eras', version: '1.0.0' });
    const kyaos = await withKyaOs(server, options(identity, profile));
    registerTools(kyaos, (name, callback) => server.registerTool(name, { inputSchema: { item: z.string() } }, callback));
    return server;
  }, { legacy: 'stateless' });
  const received = new Map<unknown, Answer>();
  const transport = new StreamableHTTPClientTransport(new URL('http://kya-os.test/mcp'), {
    fetch: async (url, init) => {
      const response = await handler.fetch(new Request(url, init));
      const sent = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
      if (sent?.method === 'tools/call') {
        const answer = messagesIn(await response.clone().text()).find((message) => message.id === sent.id);
        if (answer !== undefined) received.set(sent.id, answer as Answer);
      }
      return response;
    },
  });
  const client = new Client2(
    { name: 'proof-eras-client', version: '1.0.0' },
    era === '2026-07-28' ? { versionNegotiation: { mode: { pin: era } } } : undefined,
  );
  await client.connect(transport);
  expect(client.getNegotiatedProtocolVersion()).toBe(era);
  return {
    async call(tool) {
      const before = new Set(received.keys());
      await client.callTool({ name: tool, arguments: ARGS }).catch(() => undefined);
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
async function sdk1(identity: KyaOsIdentityConfig, profile: ProfileName): Promise<Wire> {
  const server = new McpServer1({ name: 'proof-eras', version: '1.0.0' });
  const kyaos = await withKyaOs(server, options(identity, profile));
  registerTools(kyaos, (name, callback) => server.registerTool(name, { inputSchema: { item: z.string() } }, callback));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const received: Answer[] = [];
  const forward = serverTransport.send.bind(serverTransport);
  serverTransport.send = async (message, sendOptions) => {
    const wire = JSON.parse(JSON.stringify(message));
    if (wire.result !== undefined || wire.error !== undefined) received.push(wire);
    return forward(wire, sendOptions);
  };
  await server.connect(serverTransport);
  const client = new Client1({ name: 'proof-eras-client', version: '1.0.0' });
  await client.connect(clientTransport);
  return {
    async call(tool) {
      await client.callTool({ name: tool, arguments: ARGS }).catch(() => undefined);
      return received.at(-1)!;
    },
    async close() {
      await client.close();
      await server.close();
    },
  };
}

const RUNS = [
  ['SDK 2', '2026-07-28'],
  ['SDK 2', '2025-11-25'],
  ['SDK 1', '2025-11-25'],
] as const;

describe.each(PROFILE_NAMES.flatMap((profile) => RUNS.map(([sdk, era]) => [profile, sdk, era] as const)))(
  '%s-profile proofs on %s at MCP %s',
  (profile, sdk, era) => {
    let identity: KyaOsIdentityConfig;
    let wire: Wire;

    beforeAll(async () => {
      identity = await generateIdentity(crypto);
      wire = sdk === 'SDK 2' ? await sdk2(era, identity, profile) : await sdk1(identity, profile);
    });
    afterAll(async () => {
      await wire?.close();
    });

    it.each(Object.keys(TOOLS) as ToolName[])('%s verifies against the result the client received', async (tool) => {
      const { binds, outcome } = TOOLS[tool];
      const answer = await wire.call(tool);

      if (tool === 'text_fallback' && sdk === 'SDK 1') {
        // SDK 1 sends no such result: it rejects non-object structuredContent.
        expect(answer).toMatchObject({ error: { code: -32602 } });
        expect(answer.result).toBeUndefined();
        return;
      }
      const received = answer.result!;
      // The SDK 2 encoder sets resultType on 2026-07-28 only; SDK 1 never does.
      expect(received.resultType).toBe(era === '2026-07-28' ? 'complete' : undefined);
      if (tool === 'text_fallback') {
        // SDK 2 appended a text item the handler never returned.
        expect(received.content).toEqual([{ type: 'text', text: '[1,2]' }]);
      }
      if (tool === 'content_default') {
        // The SDK filled in the content the handler left out.
        expect(received.content).toEqual([]);
      }
      expect(JSON.stringify(received)).not.toContain(LIFECYCLE_STAMP_META_KEY);
      expect(JSON.stringify(received)).not.toContain('org.kya-os/pending-proof');
      const proof = proofOf(received);
      expect(proof?.meta.prf).toBe(PROFILES[profile].responseProofProfile);
      expect(proof?.meta.outcome).toBe(outcome);
      const expected = {
        signer: identity.did,
        toolName: tool,
        params: ARGS,
        binds: binds === 'result' ? PROFILES[profile].binds : binds,
      } as const;
      expect(await verifyReceived(received, expected)).toMatchObject({ valid: true });

      if (binds === 'result' && profile === 'envelope' && era === '2026-07-28') {
        // What the proof covers includes the member the SDK added.
        const { resultType: _added, ...asReturned } = received;
        expect((await verifyReceived(asReturned, expected)).valid).toBe(false);
      }
      if (tool === 'text_fallback') {
        // ...and the content the SDK appended to.
        expect((await verifyReceived({ ...received, content: [] }, expected)).valid).toBe(false);
      }
    });
  },
);

describe.each(PROFILE_NAMES)('the %s profile with no KYA-OS transport connected', (profile) => {
  const NEEDS_TRANSPORT = /response proof is made where the KYA-OS transport sends.*createKyaOsTransport\(\)/s;
  const { responseProofProfile } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('refuses every wrapper and proveOutcome before anything runs or is recorded', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ ...config, audit: { record } });
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
    const server = new McpServer1({ name: 'unwrapped', version: '1.0.0' });
    const kyaos = await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none', proofAllTools: false });
    server.registerTool('greet', { inputSchema: { item: z.string() } }, toMcpToolCallback(kyaos.wrapWithProof('greet', ran)));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client1({ name: 'unwrapped-client', version: '1.0.0' });
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
});

describe.each(PROFILE_NAMES)('the withKyaOs transport under the %s profile', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  const allowed = async (): Promise<KyaOsToolResult> => ({
    content: [{ type: 'text', text: 'report' }],
    structuredContent: { report: 'r_1' },
  });

  it('records the audit events in the order the handler-side proof recorded them', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ ...config, audit: { record } });
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
  });

  it('proves a wrapper result that answers no tracked call, such as an excluded tool', async () => {
    const kyaos = await createMiddleware(config);
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
      signer: kyaos.identity.did, toolName: 'quiet', params: ARGS, binds,
    })).valid).toBe(true);
  });

  it('says a result is unproven, and records why, when the proof cannot be made at send', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ ...config, audit: { record } });
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
    const kyaos = await createMiddleware({ ...config, autoSession: true });
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
      signer: kyaos.identity.did, toolName: 'relay', params: ARGS, binds,
    })).valid).toBe(true);
  });
});
