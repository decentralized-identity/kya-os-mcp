/**
 * How results reach the client through the withKyaOs transport, beyond a
 * prompt tools/call answer: results delivered later (MCP tasks), results
 * nested in other results, the SDK's per-request context the transport
 * carries, and the in-process helper. Under both response-proof profiles.
 */
import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { McpServer as McpServer2, createMcpHandler } from '@modelcontextprotocol/server';
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
import { createKyaOsMiddleware, type KyaOsToolResult } from '../with-kya-os.js';
import { LIFECYCLE_STAMP_META_KEY } from '../with-kya-os.session.js';
import { RESPONSE_PROOF_PROFILE_ENVELOPE, type ResponseProofProfile } from '../../proof/generator.js';
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
  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('refuses %s', async (pendingProofTtlMs) => {
    const keys = await crypto.generateKeyPair();
    expect(() => createKyaOsMiddleware({
      identity: { did: 'did:example:server', kid: 'did:example:server#k', ...keys },
      pendingProofTtlMs,
    }, crypto)).toThrow(/pendingProofTtlMs/);
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

describe.each(PROFILE_NAMES)('the SDK request context through the transport (%s profile)', (profile) => {
  const { responseProofProfile } = PROFILES[profile];
  const config = responseProofProfile === undefined ? {} : { responseProofProfile };

  it('SDK 1: a tool still sees the session id, authInfo and requestInfo, and its related notifications arrive', async () => {
    const transports: Record<string, StreamableHTTPServerTransport> = {};
    const seen: Array<Record<string, unknown>> = [];
    const http = createServer(async (req, res) => {
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

