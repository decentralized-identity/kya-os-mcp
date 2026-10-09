/**
 * A result whose call threads no session is proved under the single
 * established session. When several sessions are live the middleware refuses
 * to pick one (it might be another client's), and the allow result goes out
 * unproven. It must say so, rather than look like a server that never proves.
 */
import { describe, it, expect, vi } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { withKyaOs } from '../with-kya-os-server.js';
import type { KyaOsMiddleware } from '../with-kya-os.js';
import { logger } from '../../logging/index.js';
import { auditEvents, createMiddleware, crypto, handshake, proofOf } from './helpers/received-proof.js';

const greet = async () => ({
  content: [{ type: 'text', text: 'Hello!' }],
  _meta: { traceparent: '00-abc-01' },
});

/** Open a session the way application code reaching into the middleware does. */
async function openAnotherSession(kyaos: KyaOsMiddleware): Promise<void> {
  const opened = await kyaos.sessionManager.validateHandshake({
    nonce: `app-${Math.random().toString(36).slice(2)}`,
    audience: kyaos.identity.did,
    timestamp: Math.floor(Date.now() / 1000),
  });
  expect(opened.success).toBe(true);
}

describe('an allow result the session fallback cannot attribute', () => {
  it('is marked unproven when a second live session makes the fallback ambiguous', async () => {
    const { events, record } = auditEvents();
    const kyaos = await createMiddleware({ autoSession: true, audit: { record } });
    const handler = kyaos.wrapWithProof('greet', greet);
    expect(proofOf(await handler({}))).toBeDefined();
    await openAnotherSession(kyaos);
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});

    try {
      const before = events.length;
      const result = await handler({});

      expect(proofOf(result)).toBeUndefined();
      expect(result.isError).toBeUndefined();
      expect(result.content).toEqual([{ type: 'text', text: 'Hello!' }]);
      const meta = result._meta as Record<string, unknown>;
      expect(meta.proofError).toMatch(/ambiguous.*unproven/i);
      expect(meta.traceparent).toBe('00-abc-01');
      expect(events.slice(before)).toEqual([
        'tool.call.started:unknown', 'proof.rejected:failed', 'tool.call.completed:succeeded',
      ]);
      expect(warn).toHaveBeenCalledWith(expect.stringContaining('Multiple sessions active'));
    } finally {
      warn.mockRestore();
    }
  });

  it('reaches a withKyaOs client with the marker', async () => {
    const server = new McpServer({ name: 'fallback', version: '1.0.0' });
    const kyaos = await withKyaOs(server, { crypto, handshakeExposure: 'none' });
    server.registerTool('greet', { description: 'Say hello' }, greet);
    const client = new Client({ name: 'fallback-client', version: '1.0.0' });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => {});

    try {
      expect(proofOf(await client.callTool({ name: 'greet', arguments: {} }))).toBeDefined();
      await openAnotherSession(kyaos);

      const received = await client.callTool({ name: 'greet', arguments: {} });

      expect(proofOf(received)).toBeUndefined();
      expect(received.isError).toBeUndefined();
      expect((received._meta as Record<string, unknown>).proofError).toMatch(/ambiguous/i);
    } finally {
      warn.mockRestore();
      await client.close();
      await server.close();
    }
  });

  it('is left as it was when there is no session at all', async () => {
    const kyaos = await createMiddleware();

    const result = await kyaos.wrapWithProof('greet', greet)({});

    expect(result).toEqual(await greet());
  });

  it('is proved under a threaded session whatever else is live', async () => {
    const kyaos = await createMiddleware({ autoSession: true });
    const sessionId = await handshake(kyaos);
    await openAnotherSession(kyaos);

    const result = await kyaos.wrapWithProof('greet', greet)({}, sessionId);

    expect(proofOf(result)?.meta.sessionId).toBe(sessionId);
    expect(Object.hasOwn(result._meta as object, 'proofError')).toBe(false);
  });
});
