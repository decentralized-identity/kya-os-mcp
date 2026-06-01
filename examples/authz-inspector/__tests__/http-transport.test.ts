/**
 * Verifies the demo works over the modern Streamable HTTP `/mcp` transport,
 * not only stdio. Boots the HTTP server on an ephemeral port, drives it with
 * the SDK's StreamableHTTPClientTransport (the same transport MCP Inspector
 * uses for `/mcp`), and asserts the protected tool is listed and returns the
 * needs_authorization challenge. Deterministic and network-free (in-memory IdP).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createOauthInspectorMcpServer } from '../src/server.js';

let server: http.Server;
let baseUrl: string;

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const { server: mcp } = createOauthInspectorMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => void transport.close());
      await mcp.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  baseUrl = `http://localhost:${port}/mcp`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function connectedClient(): Promise<Client> {
  const client = new Client({ name: 'http-test-client', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(baseUrl)));
  return client;
}

describe('authz-inspector over Streamable HTTP /mcp', () => {
  it('lists read_vault over the /mcp transport', async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain('read_vault');
    await client.close();
  });

  it('returns the needs_authorization challenge over /mcp', async () => {
    const client = await connectedClient();
    const result = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
    };
    const text = result.content.map((c) => c.text ?? '').join('\n');
    expect(text).toContain('requires authorization');
    expect(text).toContain('code_challenge_method=S256');
    await client.close();
  });
});
