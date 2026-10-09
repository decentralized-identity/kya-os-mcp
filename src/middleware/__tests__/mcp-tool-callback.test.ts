/**
 * `toMcpToolCallback`: registering a middleware-wrapped handler with the MCP
 * SDK's `registerTool`, without a cast and without the SDK's request context
 * reaching the handler as its KYA-OS session id.
 */
import { describe, it, expect } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { withKyaOs } from '../with-kya-os-server.js';
import { toMcpToolCallback } from '../mcp-tool-callback.js';
import type { KyaOsToolHandler } from '../with-kya-os.js';
import { typeErrors } from '../../__tests__/utils/type-errors.js';
import { crypto, proofOf, verifyReceived } from './helpers/received-proof.js';

async function connected(register: (server: McpServer, kyaos: Awaited<ReturnType<typeof withKyaOs>>) => void) {
  const server = new McpServer({ name: 'callbacks', version: '1.0.0' });
  const kyaos = await withKyaOs(server, { crypto, handshakeExposure: 'none' });
  register(server, kyaos);
  const client = new Client({ name: 'callbacks-client', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return {
    kyaos,
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

describe('toMcpToolCallback', () => {
  it('hands the handler the arguments alone, so its proof is made under the session', async () => {
    const calls: unknown[][] = [];
    const { kyaos, client, close } = await connected((server, kyaos) => {
      server.registerTool(
        'greet',
        { inputSchema: { name: z.string() } },
        toMcpToolCallback(kyaos.wrapWithProof('greet', async (...received) => {
          calls.push(received);
          return { content: [{ type: 'text', text: `Hello, ${String(received[0].name)}!` }] };
        })),
      );
    });

    try {
      const received = await client.callTool({ name: 'greet', arguments: { name: 'DIF' } });

      expect(calls).toEqual([[{ name: 'DIF' }, undefined, undefined]]);
      expect(proofOf(received)).toBeDefined();
      expect((await verifyReceived(received, {
        signer: kyaos.identity.did, toolName: 'greet', params: { name: 'DIF' }, binds: 'content',
      })).valid).toBe(true);
    } finally {
      await close();
    }
  });

  it('replaces a cast that passed the request context as the session id', async () => {
    const sessions: unknown[] = [];
    const { client, close } = await connected((server, kyaos) => {
      server.registerTool(
        'greet',
        { inputSchema: { name: z.string() } },
        kyaos.wrapWithProof('greet', async (_args, sessionId) => {
          sessions.push(sessionId);
          return { content: [{ type: 'text', text: 'Hello!' }] };
        }) as never,
      );
    });

    try {
      const received = await client.callTool({ name: 'greet', arguments: { name: 'DIF' } });

      // The control: the SDK's request context arrives where the session id
      // belongs, no session matches it, and the result goes out unproven.
      expect(typeof sessions[0]).toBe('object');
      expect(proofOf(received)).toBeUndefined();
    } finally {
      await close();
    }
  });

  // The type asks for an inputSchema (an empty one for a tool without
  // arguments); this is the plain-JavaScript registration without one.
  it('hands a tool registered without an inputSchema empty arguments, not the request context', async () => {
    const calls: unknown[] = [];
    const { client, close } = await connected((server, kyaos) => {
      server.registerTool(
        'ping',
        { description: 'no arguments' },
        toMcpToolCallback(kyaos.wrapWithProof('ping', async (args) => {
          calls.push(args);
          return { content: [{ type: 'text', text: 'pong' }] };
        })) as never,
      );
    });

    try {
      const received = await client.callTool({ name: 'ping', arguments: {} });

      expect(calls).toEqual([{}]);
      expect(proofOf(received)).toBeDefined();
    } finally {
      await close();
    }
  });

  it('returns what the handler returns, unchanged', async () => {
    const result = {
      content: [{ type: 'text', text: 'denied' }],
      structuredContent: { error: 'access_denied' },
      isError: true,
      _meta: { traceparent: '00-abc-01' },
    };
    const handler: KyaOsToolHandler = async () => result;

    expect(await toMcpToolCallback(handler)({}, { signal: new AbortController().signal })).toBe(result);
  });

  it('type-checks against registerTool without a cast', () => {
    const at = new URL('../mcp-tool-callback-compatibility.ts', import.meta.url);
    const preamble = `
      import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
      import { z } from 'zod';
      import { createKyaOsMiddleware, toMcpToolCallback } from './index.js';
      declare const kyaos: ReturnType<typeof createKyaOsMiddleware>;
      const server = new McpServer({ name: 'typed', version: '1.0.0' });
    `;

    expect(typeErrors(`${preamble}
      server.registerTool('greet', { inputSchema: { name: z.string() } }, toMcpToolCallback(
        kyaos.wrapWithProof('greet', async (args) => ({ content: [{ type: 'text', text: String(args.name) }] })),
      ));
      server.registerTool('checkout', { inputSchema: { item: z.string() } }, toMcpToolCallback(
        kyaos.wrapWithDelegation('checkout', { scopeId: 'cart:write', consentUrl: 'https://consent.example' },
          kyaos.wrapWithProof('checkout', async () => ({ content: [{ type: 'text', text: 'ordered' }] }))),
      ));
      server.registerTool('report', { inputSchema: { id: z.string() } }, toMcpToolCallback(
        async (args) => kyaos.proveOutcome!({
          toolName: 'report', args, outcome: 'denied', reason: 'no',
          result: { content: [{ type: 'text', text: 'no' }], isError: true },
        }),
      ));
      server.registerTool('typed', { inputSchema: { n: z.number() } }, toMcpToolCallback<{ n: number }>(
        async ({ n }) => ({ content: [{ type: 'text', text: String(n + 1) }] }),
      ));
    `, at)).toBe('');

    // The control: the same registration without the adapter is the error
    // that the cast used to silence.
    expect(typeErrors(`${preamble}
      server.registerTool('greet', { inputSchema: { name: z.string() } },
        kyaos.wrapWithProof('greet', async () => ({ content: [{ type: 'text', text: 'hi' }] })));
    `, at)).toContain("Types of parameters 'sessionId' and 'extra' are incompatible");
  }, 60_000);
});
