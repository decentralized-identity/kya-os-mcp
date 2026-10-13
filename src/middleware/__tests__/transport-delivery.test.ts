/**
 * How results reach the client through the withKyaOs transport, beyond a
 * prompt tools/call answer: results delivered later (MCP tasks), results
 * nested in other results, the SDK's per-request context the transport
 * carries, and the in-process helper. Under both response-proof profiles.
 */
import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  McpServer as McpServer2,
  WebStandardStreamableHTTPServerTransport,
  createMcpHandler,
  requireScopes,
} from '@modelcontextprotocol/server';
import { Client as Client2, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { McpServer as McpServer1 } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client as Client1 } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StreamableHTTPClientTransport as StreamableHTTPClientTransport1 } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InMemoryTaskStore } from '@modelcontextprotocol/sdk/experimental/tasks/stores/in-memory.js';
import {
  CallToolResultSchema,
  CreateTaskResultSchema,
  LoggingMessageNotificationSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { withKyaOs } from '../with-kya-os-server.js';
import { serveInProcess } from '../serve-in-process.js';
import { createKyaOsTransport, type JSONRPCMessage } from '../kya-os-transport.js';
import { createKyaOsMiddleware, type KyaOsToolResult } from '../with-kya-os.js';
import { LIFECYCLE_STAMP_META_KEY } from '../with-kya-os.session.js';
import { RESPONSE_PROOF_PROFILE_ENVELOPE, type ResponseProofProfile } from '../../proof/generator.js';
import { logger } from '../../logging/index.js';
import type { AuditTrailService } from '../../audit/service.js';
import {
  connectTransport,
  createMiddleware,
  crypto,
  handshake,
  proofOf,
  verifyReceived,
} from './helpers/received-proof.js';

const ARGS = { item: 'x' };
const PROFILES = {
  body: { responseProofProfile: undefined, binds: 'content' },
  envelope: { responseProofProfile: RESPONSE_PROOF_PROFILE_ENVELOPE, binds: 'envelope' },
} as const satisfies Record<string, { responseProofProfile: ResponseProofProfile | undefined; binds: 'content' | 'envelope' }>;
type ProfileName = keyof typeof PROFILES;
const PROFILE_NAMES = Object.keys(PROFILES) as ProfileName[];
const UNPROVEN = 'Proof generation failed — response is unproven';

const ran = async (): Promise<KyaOsToolResult> => ({ content: [{ type: 'text', text: 'done' }] });

/** Audit verification codes and tool reasons, in order. */
function codes() {
  const recorded: string[] = [];
  const record: Pick<AuditTrailService, 'record'>['record'] = async (event) => {
    const code = (event as { details?: { verificationCode?: string } }).details?.verificationCode;
    const reason = (event as { reason?: { code?: string } }).reason?.code;
    if (code !== undefined) recorded.push(code);
    if (reason !== undefined) recorded.push(reason);
    return { status: 'pending', event: event as never };
  };
  return { recorded, record };
}

describe.each(PROFILE_NAMES)('results delivered later, as MCP tasks (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  /** An SDK 1 server whose task tool stores a wrapped result, and a client fetching it. */
  async function taskServer(options: { pendingProofTtlMs?: number; record?: Pick<AuditTrailService, 'record'>['record'] } = {}) {
    const taskStore = new InMemoryTaskStore();
    const server = new McpServer1(
      { name: 'tasks', version: '1.0.0' },
      { capabilities: { tasks: { requests: { tools: { call: {} } } } }, taskStore } as never,
    );
    const kyaos = await withKyaOs(server, {
      crypto,
      ...config,
      handshakeExposure: 'none',
      ...(options.pendingProofTtlMs === undefined ? {} : { pendingProofTtlMs: options.pendingProofTtlMs }),
      ...(options.record === undefined ? {} : { audit: { record: options.record } }),
    });
    const wrapped = kyaos.wrapWithProof('report', ran);
    server.experimental.tasks.registerToolTask(
      'report',
      { inputSchema: { item: z.string() }, execution: { taskSupport: 'required' } } as never,
      {
        createTask: async (args: Record<string, unknown>, extra: { taskStore: { createTask(p: object): Promise<{ taskId: string }>; storeTaskResult(id: string, status: string, result: unknown): Promise<void> } }) => {
          const task = await extra.taskStore.createTask({ ttl: 60 * 60_000 });
          await extra.taskStore.storeTaskResult(task.taskId, 'completed', await wrapped(args));
          return { task };
        },
        getTask: async (_args: unknown, extra: { taskId: string; taskStore: { getTask(id: string): Promise<unknown> } }) => extra.taskStore.getTask(extra.taskId),
        getTaskResult: async (_args: unknown, extra: { taskId: string; taskStore: { getTaskResult(id: string): Promise<unknown> } }) => extra.taskStore.getTaskResult(extra.taskId),
      } as never,
    );
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const results: Array<Record<string, unknown>> = [];
    const forward = serverTransport.send.bind(serverTransport);
    serverTransport.send = async (message, sendOptions) => {
      const wire = JSON.parse(JSON.stringify(message));
      if (wire.result !== undefined) results.push(wire.result);
      return forward(wire, sendOptions);
    };
    await server.connect(serverTransport);
    const client = new Client1({ name: 'tasks-client', version: '1.0.0' }, { capabilities: { tasks: {} } } as never);
    await client.connect(clientTransport);
    const created = await client.request(
      { method: 'tools/call', params: { name: 'report', arguments: ARGS, task: { ttl: 60 * 60_000 } } } as never,
      CreateTaskResultSchema,
    );
    const taskId = (created as { task: { taskId: string } }).task.taskId;
    return {
      kyaos,
      async fetch(): Promise<Record<string, unknown>> {
        await client.request({ method: 'tasks/result', params: { taskId } } as never, CallToolResultSchema);
        return results.at(-1)!;
      },
      async close() {
        await client.close();
        await server.close();
      },
    };
  }

  it('proves a result fetched within the window, once, and records PROOF_EXPIRED for a second fetch', async () => {
    const { recorded, record } = codes();
    const tasks = await taskServer({ record });

    try {
      const first = await tasks.fetch();
      expect((await verifyReceived(first, {
        signer: tasks.kyaos.identity.did, toolName: 'report', params: ARGS, binds,
      })).valid).toBe(true);

      const second = await tasks.fetch();
      expect(proofOf(second)).toBeUndefined();
      expect((second._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      expect(recorded.at(-1)).toBe('PROOF_EXPIRED');
      expect(JSON.stringify(second)).not.toContain(LIFECYCLE_STAMP_META_KEY);
    } finally {
      await tasks.close();
    }
  });

  it('proves a result fetched later when pendingProofTtlMs allows it, and not past the window', async () => {
    const { recorded, record } = codes();
    const short = await taskServer({ pendingProofTtlMs: 50, record });
    const long = await taskServer({ pendingProofTtlMs: 60 * 60_000 });

    try {
      await new Promise((resolve) => setTimeout(resolve, 150));

      const late = await short.fetch();
      expect(proofOf(late)).toBeUndefined();
      expect((late._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      // Closed when the window ended, then refused at the actual send.
      expect(recorded.slice(-3)).toEqual(['PROOF_NOT_SENT', 'RESULT_NOT_SENT', 'PROOF_EXPIRED']);

      const held = await long.fetch();
      expect((await verifyReceived(held, {
        signer: long.kyaos.identity.did, toolName: 'report', params: ARGS, binds,
      })).valid).toBe(true);
    } finally {
      await short.close();
      await long.close();
    }
  });
});

describe('pendingProofTtlMs', () => {
  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 31])('refuses %s', async (pendingProofTtlMs) => {
    const keys = await crypto.generateKeyPair();
    expect(() => createKyaOsMiddleware({
      identity: { did: 'did:example:server', kid: 'did:example:server#k', ...keys },
      pendingProofTtlMs,
    }, crypto)).toThrow(/pendingProofTtlMs .*at most 2147483647/);
  });

  it('accepts the longest timer a runtime keeps', async () => {
    const keys = await crypto.generateKeyPair();
    expect(() => createKyaOsMiddleware({
      identity: { did: 'did:example:server', kid: 'did:example:server#k', ...keys },
      pendingProofTtlMs: 2_147_483_647,
    }, crypto)).not.toThrow();
  });
});

describe.each(PROFILE_NAMES)('a wrapped result nested in another result (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('never carries the private members to the wire, at any depth', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const wire = await connectTransport(kyaos);
    const inner = await kyaos.wrapWithProof('inner', ran)(ARGS);

    const received = await wire.send({
      content: [{ type: 'text', text: 'relayed' }],
      structuredContent: { relayed: inner, history: [{ step: { result: inner } }] },
    }, { toolName: 'outer', args: ARGS });

    expect(JSON.stringify(received)).not.toContain(LIFECYCLE_STAMP_META_KEY);
    expect(JSON.stringify(received)).not.toContain('org.kya-os/pending-proof');
    expect((await verifyReceived(received, {
      signer: kyaos.identity.did, toolName: 'outer', params: ARGS, binds,
    })).valid).toBe(true);
  });
});

describe.each(PROFILE_NAMES)('a wrapped result nested deeply, or serialized into a string (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('never carries the private members to the wire, however deep', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const wire = await connectTransport(kyaos);
    const inner = await kyaos.wrapWithProof('inner', ran)(ARGS);
    let nested: Record<string, unknown> = { result: inner };
    for (let depth = 0; depth < 200; depth += 1) nested = { level: nested };

    const received = await wire.send({
      content: [{ type: 'text', text: 'relayed' }],
      structuredContent: nested,
    }, { toolName: 'outer', args: ARGS });

    expect(JSON.stringify(received)).not.toContain(LIFECYCLE_STAMP_META_KEY);
    expect(JSON.stringify(received)).not.toContain('org.kya-os/pending-proof');
    expect((await verifyReceived(received, {
      signer: kyaos.identity.did, toolName: 'outer', params: ARGS, binds,
    })).valid).toBe(true);
  });

  it('does not sign a result that carries the stamp in a string, and voids the waiting proofs named there', async () => {
    const { recorded, record } = codes();
    const kyaos = await createMiddleware({ ...config, autoSession: true, audit: { record } });
    const wire = await connectTransport(kyaos);
    const inner = await kyaos.wrapWithProof('inner', ran)(ARGS);
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      const outer = await kyaos.wrapWithProof('outer', async () => ({
        content: [{ type: 'text', text: JSON.stringify(inner) }],
      }))(ARGS);
      const received = await wire.send(outer, { toolName: 'outer', args: ARGS });

      expect(proofOf(received)).toBeUndefined();
      expect((received._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      expect(recorded).toContain('PRIVATE_MEMBER_IN_RESULT');
      // The serialized inner result's proof can no longer be redeemed.
      const redeemed = await wire.send(inner, { toolName: 'inner', args: ARGS });
      expect(proofOf(redeemed)).toBeUndefined();
      await vi.waitFor(() => expect(recorded).toContain('PROOF_NOT_SENT'));
      expect(recorded.at(-1)).toBe('PROOF_EXPIRED');
    } finally {
      error.mockRestore();
    }
  });
});

describe.each(PROFILE_NAMES)('the SDK request context through the transport (%s profile)', (profile) => {
  const { responseProofProfile } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('SDK 1: a tool still sees the session id, authInfo and requestInfo, and its related notifications arrive', async () => {
    const transports: Record<string, StreamableHTTPServerTransport> = {};
    const seen: Array<Record<string, unknown>> = [];
    const http = createServer(async (req, res) => {
      // No standalone SSE stream, so a notification sent without the call's
      // relatedRequestId has nowhere to go: the test then fails, not races.
      if (req.method === 'GET') {
        res.writeHead(405, { Allow: 'POST, DELETE' }).end();
        return;
      }
      (req as IncomingMessage & { auth?: unknown }).auth = { token: 'tok-1', clientId: 'client-1', scopes: ['reports:read'] };
      const sid = req.headers['mcp-session-id'];
      const existing = typeof sid === 'string' ? transports[sid] : undefined;
      if (existing) {
        await existing.handleRequest(req, res);
        return;
      }
      const server = new McpServer1({ name: 'context', version: '1.0.0' }, { capabilities: { logging: {} } });
      await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none' });
      server.registerTool('whoami', { inputSchema: { item: z.string() } }, async (_args, extra) => {
        seen.push({
          sessionId: extra.sessionId,
          token: extra.authInfo?.token,
          hasRequestInfo: extra.requestInfo !== undefined,
        });
        await extra.sendNotification({ method: 'notifications/message', params: { level: 'info', data: 'working' } });
        return { content: [{ type: 'text' as const, text: 'ok' }] };
      });
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          transports[id] = transport;
        },
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    });
    await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
    const { port } = http.address() as AddressInfo;
    const clientTransport = new StreamableHTTPClientTransport1(new URL(`http://127.0.0.1:${port}/mcp`));
    const client = new Client1({ name: 'context-client', version: '1.0.0' });
    const notes: unknown[] = [];
    client.setNotificationHandler(LoggingMessageNotificationSchema, (note) => {
      notes.push(note.params.data);
    });

    try {
      await client.connect(clientTransport);
      const result = await client.callTool({ name: 'whoami', arguments: ARGS });

      expect(proofOf(result as Record<string, unknown>)).toBeDefined();
      expect(seen).toEqual([{ sessionId: clientTransport.sessionId, token: 'tok-1', hasRequestInfo: true }]);
      // Sent with the request's relatedRequestId, so it rode that request's stream.
      expect(notes).toEqual(['working']);
    } finally {
      await client.close();
      await new Promise<void>((resolve, reject) => {
        http.close((error) => (error ? reject(error) : resolve()));
        http.closeAllConnections();
      });
    }
  });

  it.each(['2025-11-25', '2026-07-28'] as const)('SDK 2 at MCP %s: a tool still sees authInfo', async (era) => {
    const seen: unknown[] = [];
    const handler = createMcpHandler(async () => {
      const server = new McpServer2({ name: 'context', version: '1.0.0' });
      await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none' });
      server.registerTool('whoami', { inputSchema: { item: z.string() } }, async (_args, ctx) => {
        seen.push((ctx as { http?: { authInfo?: { token?: string } } }).http?.authInfo?.token);
        return { content: [{ type: 'text' as const, text: 'ok' }] };
      });
      return server;
    }, { legacy: 'stateless' });
    const transport = new StreamableHTTPClientTransport(new URL('http://kya-os.test/mcp'), {
      fetch: (url, init) => handler.fetch(new Request(url, init), {
        authInfo: { token: 'tok-2', clientId: 'client-2', scopes: [] },
      }),
    });
    const client = new Client2(
      { name: 'context-client', version: '1.0.0' },
      era === '2026-07-28' ? { versionNegotiation: { mode: { pin: era } } } : undefined,
    );

    try {
      await client.connect(transport);
      await client.callTool({ name: 'whoami', arguments: ARGS });

      expect(seen).toEqual(['tok-2']);
    } finally {
      await client.close();
      await handler.close();
    }
  });
});

describe.each(PROFILE_NAMES)('what a proof records of the call (%s profile)', (profile) => {
  const { responseProofProfile } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('takes the scope from the call as the wrapper received it, whatever the handler does to its context', async () => {
    const kyaos = await createMiddleware(config);
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);

    const result = await kyaos.wrapWithProof('report', async (_args, _sid, context) => {
      // The context object the handler is handed is the wrapper's own.
      context!.scopeId = 'payments:admin';
      return { content: [{ type: 'text', text: 'done' }] };
    })(ARGS, sessionId, { scopeId: 'reports:read' });
    const received = await wire.send(result, { toolName: 'report', args: ARGS });

    expect(proofOf(received)!.meta.scopeId).toBe('reports:read');
  });

  it('keeps the audit context as the wrapper received it, whatever the handler does to it', async () => {
    const events: Array<{ eventType: string; actor?: { did?: string } }> = [];
    const kyaos = await createMiddleware({
      ...config,
      audit: {
        record: async (event) => {
          events.push(event as never);
          return { status: 'pending', event: event as never };
        },
      },
    });
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);
    const actor = { kind: 'pairwise_did' as const, did: 'did:example:agent' };

    const result = await kyaos.wrapWithProof('report', async (_args, _sid, context) => {
      // A deep change, to an object the context only refers to.
      (context!.actor as { did: string }).did = 'did:example:evil';
      return { content: [{ type: 'text', text: 'done' }] };
    })(ARGS, sessionId, { actor });
    await wire.send(result, { toolName: 'report', args: ARGS });

    const completed = events.find((event) => event.eventType === 'tool.call.completed');
    expect(completed?.actor?.did).toBe('did:example:agent');
    expect(JSON.stringify(events)).not.toContain('did:example:evil');
  });

  it('records PROOF_EXPIRED against the call the late result belongs to', async () => {
    const events: Array<{ eventType: string; correlationId?: string; details?: { verificationCode?: string } }> = [];
    const kyaos = await createMiddleware({
      ...config,
      audit: {
        record: async (event) => {
          events.push(event as never);
          return { status: 'pending', event: event as never };
        },
      },
    });
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);
    const result = await kyaos.wrapWithProof('report', ran)(ARGS, sessionId, { correlationId: 'corr-1' });
    await wire.send(result, { toolName: 'report', args: ARGS });

    await wire.send(result, { toolName: 'report', args: ARGS });

    const expired = events.at(-1)!;
    expect(expired.details?.verificationCode).toBe('PROOF_EXPIRED');
    expect(expired.correlationId).toBeDefined();
  });

  it('leaves _meta where it was among the result members, or adds it at the end', async () => {
    const kyaos = await createMiddleware(config);
    const sessionId = await handshake(kyaos);
    const wire = await connectTransport(kyaos);

    // SDK 1 re-creates a result with `_meta` first; here it holds only the
    // middleware's private members until the proof replaces them.
    const wrapped = await kyaos.wrapWithProof('report', ran)(ARGS, sessionId);
    const first = await wire.send({ _meta: wrapped._meta, content: wrapped.content }, { toolName: 'report', args: ARGS });
    const last = await wire.send(await kyaos.wrapWithProof('report', ran)(ARGS, sessionId), { toolName: 'report', args: ARGS });

    expect(Object.keys(first)).toEqual(['_meta', 'content']);
    expect(proofOf(first)).toBeDefined();
    expect(Object.keys(last)).toEqual(['content', '_meta']);
  });
});

describe.each(PROFILE_NAMES)('serveInProcess (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('answers a wrapped handler as a server would, proof included, until it is closed', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const local = serveInProcess(kyaos);
    const report = local.tool('report', kyaos.wrapWithProof('report', ran));

    const [a, b] = await Promise.all([report(ARGS), report({ item: 'y' })]);

    expect((await verifyReceived(a, { signer: kyaos.identity.did, toolName: 'report', params: ARGS, binds })).valid).toBe(true);
    expect((await verifyReceived(b, { signer: kyaos.identity.did, toolName: 'report', params: { item: 'y' }, binds })).valid).toBe(true);
    await local.close();
    await expect(report(ARGS)).rejects.toThrow(/closed/);
    await expect(kyaos.wrapWithProof('report', ran)(ARGS)).rejects.toThrow(/no KYA-OS transport is open/);
  });

  it('answers a throwing handler with an error, rethrows it, and serves the next call', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const local = serveInProcess(kyaos);
    let fail = true;
    const flaky = local.tool('flaky', kyaos.wrapWithProof('flaky', async () => {
      if (fail) throw new Error('upstream down');
      return { content: [{ type: 'text', text: 'ok' }] };
    }));

    await expect(flaky(ARGS)).rejects.toThrow('upstream down');
    fail = false;
    const next = await flaky(ARGS);

    expect((await verifyReceived(next, { signer: kyaos.identity.did, toolName: 'flaky', params: ARGS, binds })).valid).toBe(true);
    await local.close();
  });

  it('serves a tool that calls another served tool', async () => {
    const kyaos = await createMiddleware({ ...config, autoSession: true });
    const local = serveInProcess(kyaos);
    const inner = local.tool('inner', kyaos.wrapWithProof('inner', ran));
    const outer = local.tool('outer', kyaos.wrapWithProof('outer', async () => {
      const nested = await inner(ARGS);
      return { content: [{ type: 'text', text: `inner proved: ${proofOf(nested) !== undefined}` }] };
    }));

    const result = await outer(ARGS);

    expect((result.content[0] as { text: string }).text).toBe('inner proved: true');
    expect(proofOf(result)).toBeDefined();
    await local.close();
  });
});


describe.each(PROFILE_NAMES)('SDK 2 per-tool OAuth scope challenges under withKyaOs (%s profile)', (profile) => {
  const { responseProofProfile } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  const AUTH = { token: 'tok-read', clientId: 'client-1', scopes: ['read'] };

  /** A server whose `pay` tool requires a scope the caller's token lacks. */
  async function payServer(runs: { count: number }) {
    const server = new McpServer2({ name: 'scoped', version: '1.0.0' });
    await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none' });
    server.registerTool(
      'pay',
      { inputSchema: { item: z.string() }, scopeChallenge: requireScopes('payments:write') },
      async () => {
        runs.count += 1;
        return { content: [{ type: 'text' as const, text: 'paid' }] };
      },
    );
    return server;
  }

  /** A client of `serve`, recording the HTTP status of each tools/call. */
  async function callPay(
    serve: (request: Request) => Promise<Response>,
    era: '2025-11-25' | '2026-07-28',
  ): Promise<number[]> {
    const statuses: number[] = [];
    const transport = new StreamableHTTPClientTransport(new URL('http://kya-os.test/mcp'), {
      fetch: async (url, init) => {
        const response = await serve(new Request(url, init));
        const sent = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
        if (sent?.method === 'tools/call') statuses.push(response.status);
        return response;
      },
    });
    const client = new Client2(
      { name: 'scoped-client', version: '1.0.0' },
      era === '2026-07-28' ? { versionNegotiation: { mode: { pin: era } } } : undefined,
    );
    try {
      await client.connect(transport);
      await client.callTool({ name: 'pay', arguments: ARGS }).catch(() => undefined);
    } finally {
      await client.close();
    }
    return statuses;
  }

  it.each(['2025-11-25', '2026-07-28'] as const)('createMcpHandler at MCP %s: answers 403 and never runs the tool', async (era) => {
    const runs = { count: 0 };
    const handler = createMcpHandler(() => payServer(runs), { legacy: 'stateless' });

    try {
      const statuses = await callPay((request) => handler.fetch(request, { authInfo: AUTH }), era);

      expect(statuses).toEqual([403]);
      expect(runs.count).toBe(0);
    } finally {
      await handler.close();
    }
  });

  it('a self-managed stateful WebStandardStreamableHTTPServerTransport: answers 403 and never runs the tool', async () => {
    const runs = { count: 0 };
    const server = await payServer(runs);
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
    await server.connect(transport);

    try {
      const statuses = await callPay((request) => transport.handleRequest(request, { authInfo: AUTH }), '2025-11-25');

      expect(statuses).toEqual([403]);
      expect(runs.count).toBe(0);
    } finally {
      await server.close();
    }
  });
});

describe.each(PROFILE_NAMES)('private members in messages other than results (%s profile)', (profile) => {
  const { responseProofProfile, binds } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };
  const STAMP_KEY = LIFECYCLE_STAMP_META_KEY;
  const PENDING_KEY = 'org.kya-os/pending-proof';

  it('SDK 1: a wrapped result logged in a notification leaves no stamp or id, so a relay cannot forge a proof with them', async () => {
    const { recorded, record } = codes();
    const server = new McpServer1({ name: 'logger', version: '1.0.0' }, { capabilities: { logging: {} } });
    const kyaos = await withKyaOs(server, { crypto, ...config, handshakeExposure: 'none', audit: { record } });
    server.registerTool('outer', { inputSchema: { item: z.string() } }, async (args, extra) => {
      const inner = await kyaos.wrapWithProof('inner', ran)(args);
      await extra.sendNotification({ method: 'notifications/message', params: { level: 'info', data: inner } });
      return { content: [{ type: 'text' as const, text: 'logged' }] };
    });
    // A tool that relays caller-controlled _meta into its own result.
    server.registerTool('relay', { inputSchema: { meta: z.record(z.string(), z.unknown()) } }, async (args) => ({
      content: [{ type: 'text' as const, text: 'ATTACKER CONTENT' }],
      _meta: args.meta,
    }));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const wire: unknown[] = [];
    const forward = serverTransport.send.bind(serverTransport);
    serverTransport.send = async (message, sendOptions) => {
      const copy = JSON.parse(JSON.stringify(message));
      wire.push(copy);
      return forward(copy, sendOptions);
    };
    await server.connect(serverTransport);
    const client = new Client1({ name: 'logger-client', version: '1.0.0' });
    const logged: Array<Record<string, unknown>> = [];
    client.setNotificationHandler(LoggingMessageNotificationSchema, (note) => {
      logged.push(note.params.data as Record<string, unknown>);
    });
    await client.connect(clientTransport);

    try {
      await client.callTool({ name: 'outer', arguments: ARGS });
      await vi.waitFor(() => expect(logged).toHaveLength(1));
      expect(JSON.stringify(wire)).not.toContain(STAMP_KEY);
      expect(JSON.stringify(wire)).not.toContain(PENDING_KEY);
      // The id was closed: its result was never sent as itself.
      await vi.waitFor(() => expect(recorded).toContain('PROOF_NOT_SENT'));

      // Whatever the client relays, the relay is proved as the relay's own answer.
      const relayed = await client.callTool({ name: 'relay', arguments: { meta: (logged[0]!._meta ?? {}) as Record<string, unknown> } });
      expect((relayed.content as Array<{ text: string }>)[0]!.text).toBe('ATTACKER CONTENT');
      expect((await verifyReceived(relayed as Record<string, unknown>, {
        signer: kyaos.identity.did, toolName: 'inner', params: ARGS, binds,
      })).valid).toBe(false);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('removes them from an error data payload, and closes the proof named there', async () => {
    const { recorded, record } = codes();
    const kyaos = await createMiddleware({ ...config, autoSession: true, audit: { record } });
    const sent: JSONRPCMessage[] = [];
    const inner = {
      start: async () => {},
      close: async () => {},
      send: async (message: JSONRPCMessage) => {
        sent.push(JSON.parse(JSON.stringify(message)));
      },
    };
    const wrapper = createKyaOsTransport(inner, kyaos);
    await wrapper.start();
    const wrapped = await kyaos.wrapWithProof('inner', ran)(ARGS);

    await wrapper.send({ jsonrpc: '2.0', id: 9, error: { code: -32603, message: 'failed', data: { partial: wrapped } } });

    expect(JSON.stringify(sent)).not.toContain(STAMP_KEY);
    expect(JSON.stringify(sent)).not.toContain(PENDING_KEY);
    expect((sent[0] as { error: { data: { partial: { content: unknown } } } }).error.data.partial.content).toEqual(wrapped.content);
    await vi.waitFor(() => expect(recorded).toContain('PROOF_NOT_SENT'));
  });

  it('refuses to redeem, on the answer to one tool, a proof left for another', async () => {
    const { recorded, record } = codes();
    const kyaos = await createMiddleware({ ...config, autoSession: true, audit: { record } });
    const wire = await connectTransport(kyaos);
    const genuine = await kyaos.wrapWithProof('inner', ran)({ item: 'secret-request' });
    const error = vi.spyOn(logger, 'error').mockImplementation(() => {});

    try {
      // A relay answering its own call with the inner result's stamp and id.
      const forged = await wire.send(
        { content: [{ type: 'text', text: 'ATTACKER CONTENT' }], _meta: genuine._meta },
        { toolName: 'relay', args: ARGS },
      );

      expect(proofOf(forged)).toBeUndefined();
      expect((forged._meta as Record<string, unknown>).proofError).toBe(UNPROVEN);
      expect(recorded).toContain('PROOF_TOOL_MISMATCH');
      // The proof is gone: the genuine result cannot redeem it afterwards either.
      const late = await wire.send(genuine, { toolName: 'inner', args: { item: 'secret-request' } });
      expect(proofOf(late)).toBeUndefined();
    } finally {
      error.mockRestore();
    }
  });
});

describe('the record of proofs no longer waiting', () => {
  it('keeps what it holds within a byte budget, forgetting the oldest first', async () => {
    const events: Array<{ correlationId?: string; details?: { verificationCode?: string } }> = [];
    const kyaos = await createMiddleware({
      autoSession: true,
      audit: {
        record: async (event) => {
          events.push(event as never);
          return { status: 'pending', event: event as never };
        },
      },
    });
    const wire = await connectTransport(kyaos);
    const handler = kyaos.wrapWithProof('report', ran);
    const results: KyaOsToolResult[] = [];
    // 400 sent calls with 15 KB of audit context each: 6 MB, past the 4 MB budget.
    for (let i = 0; i < 400; i += 1) {
      const result = await handler(ARGS, undefined, { correlationId: `${i}`.padEnd(15_000, 'c') });
      results.push(structuredClone(result));
      await wire.send(result);
    }
    const expiredContext = async (result: KyaOsToolResult) => {
      await wire.send(result);
      const expired = events.at(-1)!;
      expect(expired.details?.verificationCode).toBe('PROOF_EXPIRED');
      return expired.correlationId;
    };

    // The oldest call's context was forgotten; the newest is still known.
    expect(await expiredContext(results[0]!)).toBeUndefined();
    expect(await expiredContext(results.at(-1)!)).toBeDefined();
  }, 60_000);
});
