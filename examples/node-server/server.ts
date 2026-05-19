#!/usr/bin/env npx tsx
/**
 * KYA-OS Example Server (Low-Level Server API)
 *
 * This example uses the low-level `Server` API with `createKyaOsMiddleware`
 * for manual request handler patterns. For most servers, prefer the
 * simpler `withKyaOs()` adapter — see examples/context7-with-kya-os/ for
 * a 2-line integration with the high-level `McpServer` API.
 *
 * Demonstrates the KYA-OS protocol:
 *   1. greet           — open tool with signed proof (via _meta)
 *   2. restricted_greet — protected tool requiring a W3C Delegation Credential
 *
 * Sessions are created automatically — no manual handshake needed.
 * In production, KYA-OS-aware clients handle the handshake transparently.
 *
 * Full demo flow:
 *   1. Start server:
 *        npx tsx examples/node-server/server.ts
 *   2. Issue a delegation VC:
 *        npx tsx examples/node-server/issue-delegation.ts > delegation.json
 *   3. Connect MCP Inspector to http://localhost:3001/sse
 *   4. Call `restricted_greet` with `_kyaos_delegation` = contents of delegation.json
 *   5. Watch it verify the VC and return the greeting with a signed proof
 */

import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createKyaOsMiddleware } from '../../src/middleware/with-kya-os.js';
import { generateDidKeyFromBase64 } from '../../src/utils/did-helpers.js';
import { NodeCryptoProvider } from './node-crypto.js';

function createMcpServer(kyaos: ReturnType<typeof createKyaOsMiddleware>) {
  const server = new Server(
    { name: 'kya-os-example', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  // ── Tool handlers ───────────────────────────────────────────────

  const greetHandler = kyaos.wrapWithProof('greet', async (args) => ({
    content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}!` }],
  }));

  // restricted_greet: verify delegation VC, then attach proof on success
  const restrictedGreetHandler = kyaos.wrapWithDelegation(
    'restricted_greet',
    {
      scopeId: 'greeting:restricted',
      consentUrl: 'https://example.com/consent?scope=greeting:restricted',
    },
    kyaos.wrapWithProof('restricted_greet', async (args) => ({
      content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}! (delegation verified)` }],
    })),
  );

  // ── Request handlers ────────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      kyaos.kyaOsTool,
      {
        name: 'greet',
        description: 'Returns a greeting with a signed Ed25519 proof',
        inputSchema: {
          type: 'object' as const,
          properties: {
            name: { type: 'string', description: 'Name to greet' },
          },
        },
      },
      {
        name: 'restricted_greet',
        description: 'A protected greeting that requires delegation (scope: greeting:restricted)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            name: { type: 'string', description: 'Name to greet' },
            _kyaos_delegation: {
              type: 'object',
              description: 'W3C Delegation Credential granting scope greeting:restricted',
            },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    // ── KYA-OS protocol operations ────────────────────────────────
    if (name === '_kyaos') {
      return kyaos.handleKyaOs(args as Record<string, unknown>);
    }

    // ── Open tools ──────────────────────────────────────────────
    if (name === 'greet') {
      return greetHandler(args as Record<string, unknown>);
    }

    // ── Protected tools (delegation required) ───────────────────
    if (name === 'restricted_greet') {
      return restrictedGreetHandler(args as Record<string, unknown>);
    }

    return {
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
      isError: true,
    };
  });

  return server;
}

async function main() {
  const useStdio = process.argv.includes('--stdio');

  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();

  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  console.error(`[kya-os] Agent DID: ${did}`);

  const kyaos = createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey },
      session: { sessionTtlMinutes: 60 },
      autoSession: true,
    },
    crypto
  );

  if (useStdio) {
    const server = createMcpServer(kyaos);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('[kya-os] Server running on stdio');
  } else {
    const PORT = parseInt(process.env['PORT'] ?? '3001', 10);
    let sseTransport: SSEServerTransport | null = null;

    const httpServer = http.createServer(async (req, res) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

      if (url.pathname === '/sse' && req.method === 'GET') {
        const server = createMcpServer(kyaos);
        sseTransport = new SSEServerTransport('/messages', res);
        await server.connect(sseTransport);
        console.error('[kya-os] SSE client connected');
        return;
      }

      if (url.pathname === '/messages' && req.method === 'POST') {
        if (!sseTransport) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No SSE connection. Connect to /sse first.' }));
          return;
        }
        await sseTransport.handlePostMessage(req, res);
        return;
      }

      if (url.pathname === '/' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          name: 'kya-os-example',
          did,
          transport: 'sse',
          connect: `http://localhost:${PORT}/sse`,
        }));
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    });

    httpServer.listen(PORT, () => {
      console.error(`[kya-os] SSE server: http://localhost:${PORT}`);
      console.error(`[kya-os] Connect Inspector to: http://localhost:${PORT}/sse`);
    });
  }
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
