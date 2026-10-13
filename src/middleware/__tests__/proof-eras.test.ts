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
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import v8 from 'node:v8';
import { runInNewContext } from 'node:vm';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { McpServer as McpServer2, createMcpHandler } from '@modelcontextprotocol/server';
import { Client as Client2, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { McpServer as McpServer1 } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client as Client1 } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StreamableHTTPClientTransport as StreamableHTTPClientTransport1 } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
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
import type { AuditTrailService } from '../../audit/service.js';
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

/** A raw withKyaOs transport over a recording far end, started. */
async function rawTransport(kyaos: KyaOsMiddleware) {
  const sent: JSONRPCMessage[] = [];
  const inner = {
    start: async () => {},
    close: async () => {},
    send: async (message: JSONRPCMessage) => {
      sent.push(JSON.parse(JSON.stringify(message)));
    },
    onclose: undefined as (() => void) | undefined,
  };
  const wrapper = createKyaOsTransport(inner, kyaos);
  await wrapper.start();
  return { inner, wrapper, sent };
}

describe.each(PROFILE_NAMES)('the claims of a proof left to the transport (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  const NEEDS_TRANSPORT = /response proof is made where the KYA-OS transport sends.*createKyaOsTransport\(\)/s;
  const PENDING = 'org.kya-os/pending-proof';
  /** Claims a handler would like signed for a call it never made. */
  const fabricated = {
    kind: 'allowed',
    toolName: 'transfer_funds',
    request: { method: 'transfer_funds', params: { amount: 1_000_000 } },
    sessionId: 'never-issued',
    session: { sessionId: 'never-issued', audience: 'did:web:victim.example' },
    scopeId: 'payments:admin',
  };
  const leaked = (received: unknown) =>
    ['transfer_funds', 'never-issued', 'victim.example', 'payments:admin'].filter((claim) =>
      JSON.stringify(received).includes(claim));

  it('are never taken from the result: a handler holding a real stamp gets no proof for claims it wrote', async () => {
    const server = new McpServer1({ name: 'forger', version: '1.0.0' });
    const kyaos = await withKyaOs(server, {
      crypto, ...config, handshakeExposure: 'none',
    });
    server.registerTool('forge', { inputSchema: { item: z.string() } }, toMcpToolCallback(async (args) => {
      // The handler wraps a call of its own to read a genuine stamp off it.
      const genuine = await kyaos.wrapWithProof('innocent', ran)(args);
      const stamp = (genuine._meta as Record<string, unknown>)[LIFECYCLE_STAMP_META_KEY];
      return {
        content: [{ type: 'text', text: 'transfer approved' }],
        _meta: { [LIFECYCLE_STAMP_META_KEY]: stamp, [PENDING]: fabricated },
      };
    }));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const received: Array<Record<string, unknown>> = [];
    const forward = serverTransport.send.bind(serverTransport);
    serverTransport.send = async (message, sendOptions) => {
      const wire = JSON.parse(JSON.stringify(message));
      if (wire.result !== undefined) received.push(wire.result);
      return forward(wire, sendOptions);
    };
    await server.connect(serverTransport);
    const client = new Client1({ name: 'forger-client', version: '1.0.0' });
    await client.connect(clientTransport);

    try {
      await client.callTool({ name: 'forge', arguments: ARGS });
      const result = received.at(-1)!;

      expect(proofOf(result)).toBeUndefined();
      expect((result._meta as Record<string, unknown>).proofError).toBe('Proof generation failed — response is unproven');
      expect(leaked(result)).toEqual([]);
      expect(JSON.stringify(result)).not.toContain(LIFECYCLE_STAMP_META_KEY);
      expect(JSON.stringify(result)).not.toContain(PENDING);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('are redeemed only under the middleware stamp, even with a genuine pending id and no tracked call', async () => {
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const genuine = await kyaos.wrapWithProof('report', ran)(ARGS, sessionId);
    const id = (genuine._meta as Record<string, unknown>)[PENDING];
    expect(id).toEqual(expect.any(String));

    // Another result, under a guessed stamp, naming the genuine id, answering no tracked call.
    await wrapper.send({
      jsonrpc: '2.0', id: 41,
      result: { content: [{ type: 'text', text: 'substituted' }], _meta: { [LIFECYCLE_STAMP_META_KEY]: 'guessed', [PENDING]: id } },
    });
    // The genuine result, answering no tracked call either.
    await wrapper.send({ jsonrpc: '2.0', id: 42, result: genuine });

    const substituted = (sent[0] as { result: Record<string, unknown> }).result;
    expect(proofOf(substituted)).toBeUndefined();
    expect(JSON.stringify(substituted)).not.toContain(PENDING);
    const proven = (sent[1] as { result: Record<string, unknown> }).result;
    expect((await verifyReceived(proven, {
      signer: kyaos.identity.did, toolName: 'report', params: ARGS, binds,
    })).valid).toBe(true);
  });

  it('are redeemed once: a second result naming the same id goes out unproven', async () => {
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const genuine = await kyaos.wrapWithProof('report', ran)(ARGS, sessionId);

    await wrapper.send({ jsonrpc: '2.0', id: 1, result: structuredClone(genuine) });
    await wrapper.send({ jsonrpc: '2.0', id: 2, result: { ...structuredClone(genuine), content: [{ type: 'text', text: 'replayed' }] } });

    expect(proofOf((sent[0] as { result: Record<string, unknown> }).result)).toBeDefined();
    const replayed = (sent[1] as { result: Record<string, unknown> }).result;
    expect(proofOf(replayed)).toBeUndefined();
    expect((replayed._meta as Record<string, unknown>).proofError).toBe('Proof generation failed — response is unproven');
  });

  it('take the audience from the session as it is at send, and refuse a session that is gone', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ ...config, audit: { record } });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const result = await kyaos.wrapWithProof('report', ran)(ARGS, sessionId);
    await kyaos.sessionManager.clearSessions();

    await wrapper.send({ jsonrpc: '2.0', id: 1, result });

    const received = (sent[0] as { result: Record<string, unknown> }).result;
    expect(proofOf(received)).toBeUndefined();
    expect((received._meta as Record<string, unknown>).proofError).toBe('Proof generation failed — response is unproven');
    expect(events.slice(-2)).toEqual(['proof.rejected:failed', 'tool.call.completed:succeeded']);
  });

  it('do not outlive the transport: once every KYA-OS transport has closed, the wrappers refuse again', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const first = await rawTransport(kyaos);
    const second = await rawTransport(kyaos);
    const handler = kyaos.wrapWithProof('report', ran);

    await first.wrapper.close();
    await expect(handler(ARGS)).resolves.toBeDefined();
    // The far end goes away on its own.
    second.inner.onclose!();
    await expect(handler(ARGS)).rejects.toThrow(NEEDS_TRANSPORT);
    await expect(kyaos.proveOutcome!({
      toolName: 'report', args: ARGS, outcome: 'denied', reason: 'r', result: scopeChallenge(),
    })).rejects.toThrow(NEEDS_TRANSPORT);
  });

  it('close a proof the SDK never sends, such as a cancelled call, in the audit trail', async () => {
    const recorded: Array<{ eventType: string; outcome: string; code?: string; reason?: string }> = [];
    const record: Pick<AuditTrailService, 'record'>['record'] =
      async (event) => {
        const details = (event as { details?: { verificationCode?: string } }).details;
        const reason = (event as { reason?: { code?: string } }).reason?.code;
        recorded.push({
          eventType: event.eventType,
          outcome: event.outcome,
          ...(details?.verificationCode === undefined ? {} : { code: details.verificationCode }),
          ...(reason === undefined ? {} : { reason }),
        });
        return { status: 'pending', event: event as never };
      };
    const server = new McpServer1({ name: 'cancel', version: '1.0.0' });
    const kyaos = await withKyaOs(server, {
      crypto, ...config, handshakeExposure: 'none', audit: { record },
    });
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    server.registerTool('slow', { inputSchema: { item: z.string() } }, toMcpToolCallback(kyaos.wrapWithProof('slow', async () => {
      entered();
      await held;
      return { content: [{ type: 'text', text: 'too late' }] };
    })));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const results: unknown[] = [];
    const forward = serverTransport.send.bind(serverTransport);
    serverTransport.send = async (message, sendOptions) => {
      if ((message as { result?: { content?: unknown } }).result?.content !== undefined) results.push(message);
      return forward(message, sendOptions);
    };
    await server.connect(serverTransport);
    const client = new Client1({ name: 'cancel-client', version: '1.0.0' });
    await client.connect(clientTransport);
    const abort = new AbortController();

    try {
      const call = client.callTool({ name: 'slow', arguments: ARGS }, undefined, { signal: abort.signal }).catch(() => 'cancelled');
      await started;
      abort.abort();
      await call;
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
      release();
      // The handler returns into a request the SDK no longer answers.
      await vi.waitFor(() => expect(recorded.map((e) => e.eventType)).toContain('tool.call.started'));
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(results).toHaveLength(0);
      expect(recorded.map((e) => e.eventType)).not.toContain('tool.call.completed');

      await vi.advanceTimersByTimeAsync(5 * 60_000);

      // The client never saw the result: the call is closed as failed, not completed.
      expect(recorded.slice(-2)).toEqual([
        { eventType: 'proof.rejected', outcome: 'failed', code: 'PROOF_NOT_SENT' },
        { eventType: 'tool.call.failed', outcome: 'failed', reason: 'RESULT_NOT_SENT' },
      ]);
    } finally {
      vi.useRealTimers();
      await client.close();
      await server.close();
    }
  });
});

describe.each(PROFILE_NAMES)('edge paths of a proof left to the transport (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  const UNPROVEN = 'Proof generation failed — response is unproven';
  const PENDING = 'org.kya-os/pending-proof';
  const sentResult = (sent: JSONRPCMessage[], index = -1) =>
    (sent.at(index) as { result: Record<string, unknown> }).result;
  const recording = () => {
    const recorded: Array<{ eventType: string; code?: string }> = [];
    const record: Pick<AuditTrailService, 'record'>['record'] = async (event) => {
      const code = (event as { details?: { verificationCode?: string } }).details?.verificationCode;
      recorded.push({ eventType: event.eventType, ...(code === undefined ? {} : { code }) });
      return { status: 'pending', event: event as never };
    };
    return { recorded, record };
  };

  it('signs the call as the wrapper saw it, whatever later happens to the arguments', async () => {
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const args = { item: 'x', basket: { qty: 1 } };

    const result = await kyaos.wrapWithProof('order', ran)(args, sessionId);
    args.basket.qty = 1_000;
    await wrapper.send({ jsonrpc: '2.0', id: 1, result });

    const expected = { signer: kyaos.identity.did, toolName: 'order', binds };
    expect((await verifyReceived(sentResult(sent), { ...expected, params: { item: 'x', basket: { qty: 1 } } })).valid).toBe(true);
    expect((await verifyReceived(sentResult(sent), { ...expected, params: args })).valid).toBe(false);
  });

  it('fails the proof of arguments that cannot be hashed, in the handler, as it would have at send', async () => {
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      const result = await kyaos.wrapWithProof('order', ran)({ item: 'x', callback: () => 'no' }, sessionId);
      await wrapper.send({ jsonrpc: '2.0', id: 1, result });

      // A function cannot be signed over: the proof fails and says so.
      expect(proofOf(sentResult(sent))).toBeUndefined();
      expect((sentResult(sent)._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      expect(error).toHaveBeenCalledWith('[kya-os] Proof generation failed', expect.objectContaining({ tool: 'order' }));
    } finally {
      error.mockRestore();
    }
  });

  it('reports an outcome proof that fails at send on the result', async () => {
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const challenge = await kyaos.wrapWithDelegation('checkout', CONSENT, ran)(ARGS, sessionId);
    const generate = vi.spyOn(kyaos.proofGenerator, 'generateProof').mockRejectedValue(new Error('signer offline'));
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      await wrapper.send({ jsonrpc: '2.0', id: 1, result: challenge });

      expect(proofOf(sentResult(sent))).toBeUndefined();
      expect((sentResult(sent)._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
    } finally {
      generate.mockRestore();
      error.mockRestore();
    }
  });

  it('sends a result unproven when its session cannot be read at send', async () => {
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const result = await kyaos.wrapWithProof('report', ran)(ARGS, sessionId);
    const read = vi.spyOn(kyaos.sessionManager, 'getSession').mockRejectedValue(new Error('store offline'));
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      await wrapper.send({ jsonrpc: '2.0', id: 1, result });

      expect(proofOf(sentResult(sent))).toBeUndefined();
      expect((sentResult(sent)._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      expect(error).toHaveBeenCalledWith('[kya-os] Proof session lookup failed', expect.objectContaining({ tool: 'report' }));
    } finally {
      read.mockRestore();
      error.mockRestore();
    }
  });

  it('records nothing more for an outcome whose session is gone when its terminal audit already failed', async () => {
    const recorded: string[] = [];
    const kyaos = await createMiddleware({
      ...config,
      audit: {
        record: async (event) => {
          recorded.push(event.eventType);
          if (event.eventType === 'tool.call.denied') throw new Error('sink down');
          return { status: 'pending', event: event as never };
        },
      },
    });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      const denied = await kyaos.proveOutcome!({
        toolName: 'wipe', args: ARGS, outcome: 'denied', reason: 'blocked',
        result: { content: [{ type: 'text', text: 'no' }], isError: true }, sessionId,
      });
      await kyaos.sessionManager.clearSessions();
      const before = recorded.length;
      await wrapper.send({ jsonrpc: '2.0', id: 1, result: denied });

      expect((sentResult(sent)._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      expect(recorded.slice(before)).toEqual([]);
    } finally {
      error.mockRestore();
    }
  });

  it('closes an unsent outcome proof with PROOF_NOT_SENT, and an evicted one when too many wait', async () => {
    const { recorded, record } = recording();
    const kyaos = await createMiddleware({
      ...config, audit: { record }, autoSession: true,
    });
    const { wrapper, sent } = await rawTransport(kyaos);
    const deny = () => kyaos.proveOutcome!({
      toolName: 'wipe', args: ARGS, outcome: 'denied', reason: 'blocked',
      result: { content: [{ type: 'text', text: 'no' }], isError: true },
    });

    // The first of 10,001 waiting proofs is closed to make room for the last.
    const first = await deny();
    for (let i = 0; i < 10_000; i += 1) await deny();
    await vi.waitFor(() => expect(recorded).toContainEqual({ eventType: 'proof.rejected', code: 'PROOF_NOT_SENT' }));
    await wrapper.send({ jsonrpc: '2.0', id: 1, result: first });

    expect(proofOf(sentResult(sent))).toBeUndefined();
    expect((sentResult(sent)._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
    expect(recorded.filter((event) => event.code === 'PROOF_NOT_SENT')).toHaveLength(1);
  }, 60_000);

  it('counts a transport closed twice once', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const kept = await rawTransport(kyaos);
    const closing = await rawTransport(kyaos);

    await closing.wrapper.close();
    closing.inner.onclose?.();

    expect(JSON.stringify(await kyaos.wrapWithProof('report', ran)(ARGS))).toContain(PENDING);
    await kept.wrapper.close();
  });
});

describe.each(PROFILE_NAMES)('the transport lifecycle around the proofs it makes (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  it('runs an onclose set on the inner transport before connecting, once, as the SDK chains it', async () => {
    const server = new McpServer1({ name: 'closer', version: '1.0.0' });
    await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const cleanup = vi.fn();
    serverTransport.onclose = cleanup;
    await server.connect(serverTransport);
    const client = new Client1({ name: 'closer-client', version: '1.0.0' });
    await client.connect(clientTransport);

    await client.close();

    expect(cleanup).toHaveBeenCalledTimes(1);
    await server.close();
    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it('keeps the stateful Streamable HTTP session map clean: the cleanup set before connect runs when the session ends', async () => {
    const transports: Record<string, StreamableHTTPServerTransport> = {};
    const http = createServer(async (req, res) => {
      const sid = req.headers['mcp-session-id'];
      const existing = typeof sid === 'string' ? transports[sid] : undefined;
      if (existing) {
        await existing.handleRequest(req, res);
        return;
      }
      const server = new McpServer1({ name: 'stateful', version: '1.0.0' });
      await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none' });
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          transports[id] = transport;
        },
      });
      // The documented pattern: drop the session when its transport closes.
      transport.onclose = () => {
        if (transport.sessionId) delete transports[transport.sessionId];
      };
      await server.connect(transport);
      await transport.handleRequest(req, res);
    });
    await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
    const { port } = http.address() as AddressInfo;
    const clientTransport = new StreamableHTTPClientTransport1(new URL(`http://127.0.0.1:${port}/mcp`));
    const client = new Client1({ name: 'stateful-client', version: '1.0.0' });

    try {
      await client.connect(clientTransport);
      expect(Object.keys(transports)).toHaveLength(1);

      await clientTransport.terminateSession();

      expect(Object.keys(transports)).toHaveLength(0);
    } finally {
      await client.close();
      await new Promise<void>((resolve, reject) => {
        http.close((error) => (error ? reject(error) : resolve()));
        http.closeAllConnections();
      });
    }
  });

  it('counts a transport started twice once, so its close ends the count', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const { wrapper } = await rawTransport(kyaos);

    await wrapper.start();
    await wrapper.close();

    await expect(kyaos.wrapWithProof('report', ran)(ARGS)).rejects.toThrow(/no KYA-OS transport is open/);
  });

  it('closes what is waiting when the last transport closes', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ ...config, audit: { record }, autoSession: true });
    const { wrapper } = await rawTransport(kyaos);
    await kyaos.wrapWithProof('report', ran)(ARGS);

    await wrapper.close();

    await vi.waitFor(() => expect(events.slice(-2)).toEqual(['proof.rejected:failed', 'tool.call.failed:failed']));
  });

  it('keeps no arguments for a proof it waits to make, however large they are', async () => {
    v8.setFlagsFromString('--expose-gc');
    const gc = runInNewContext('gc') as () => void;
    const kyaos = await createMiddleware({ ...config });
    const sessionId = await handshake(kyaos);
    const { wrapper, sent } = await rawTransport(kyaos);
    const handler = kyaos.wrapWithProof('upload', ran);
    // Warm up, so the measurement sees only what the waiting proofs keep.
    await handler({ blob: 'w' }, sessionId);
    gc();
    const before = process.memoryUsage().heapUsed;

    // 400 calls with 100 KB of arguments each whose results are never sent,
    // as when a client cancels them: 40 MB if the arguments were kept.
    for (let i = 0; i < 400; i += 1) {
      await handler({ blob: `${i}`.padEnd(100_000, 'x') }, sessionId);
    }
    gc();
    const retained = process.memoryUsage().heapUsed - before;

    expect(retained).toBeLessThan(8 * 1024 * 1024);
    // A call that is sent is still proved over its arguments.
    const args = { blob: 'y'.repeat(100_000) };
    await wrapper.send({ jsonrpc: '2.0', id: 1, result: await handler(args, sessionId) });
    expect((await verifyReceived((sent[0] as { result: Record<string, unknown> }).result, {
      signer: kyaos.identity.did, toolName: 'upload', params: args, binds,
    })).valid).toBe(true);
  }, 60_000);

  it('closes the oldest waiting proofs as not sent once they hold too much', async () => {
    const recorded: string[] = [];
    const kyaos = await createMiddleware({
      ...config,
      audit: {
        record: async (event) => {
          const code = (event as { details?: { verificationCode?: string } }).details?.verificationCode;
          if (code !== undefined) recorded.push(code);
          return { status: 'pending', event: event as never };
        },
      },
    });
    const sessionId = await handshake(kyaos);
    await rawTransport(kyaos);
    const handler = kyaos.wrapWithProof('trace', ran);

    // A call context the caller controls, 1 MB each: past 16 MB the oldest go.
    for (let i = 0; i < 20; i += 1) {
      await handler(ARGS, sessionId, { correlationId: `${i}`.padEnd(1_000_000, 'c') });
    }

    await vi.waitFor(() => expect(recorded.filter((code) => code === 'PROOF_NOT_SENT').length).toBeGreaterThanOrEqual(4));
  }, 60_000);
});
