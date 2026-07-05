#!/usr/bin/env npx tsx
/**
 * Durable Consent — two MCP server instances sharing one file-backed GrantStore
 * + PendingFlowStore and one identity.
 *
 * Boots a consent server plus TWO MCP instances (ports A and B), both with
 * holder-of-key enforcement. The agent presents a per-request `_kyaos_proof` in
 * the `checkout` arguments; the first call returns needs_authorization, the user
 * approves (binding an agent-anchored grant to the shared store), and a retry on
 * EITHER instance — or after a restart — succeeds with no re-paste. It works
 * over the stateless HTTP transport precisely because authorization rides on the
 * holder-of-key proof, not on a shared server session: each instance re-proves
 * possession of the agent's key per request and resolves the grant via
 * getByAgent. No per-process Map, no sticky sessions.
 *
 * The deterministic, headless proof lives in scripts/scenario-cross-instance.ts
 * and scripts/scenario-restart.ts (they mint the `_kyaos_proof` the way a
 * KYA-OS-aware client would).
 *
 * Transports: Streamable HTTP (POST /mcp), per instance.
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { createInstance, createStores, loadIdentity, type Instance } from './instance.js';
import { startConsentServer } from './consent-server.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function createMcpServer(instance: Instance): Server {
  const server = new Server(
    { name: `consent-persistence-${instance.label}`, version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      instance.middleware.kyaOsTool,
      {
        name: 'checkout',
        description: 'Complete a purchase (requires delegation with scope: cart:write)',
        inputSchema: {
          type: 'object' as const,
          properties: { item: { type: 'string', description: 'Item to purchase' } },
          required: ['item'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    if (name === '_kyaos') return instance.middleware.handleKyaOs(args as Record<string, unknown>);
    if (name === 'checkout') return instance.checkout(args as Record<string, unknown>);
    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  });

  return server;
}

function startHttpInstance(instance: Instance, port: number, did: string): http.Server {
  const httpServer = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, MCP-Session-Id');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', `http://localhost:${port}`);

    if (url.pathname === '/mcp' && req.method === 'POST') {
      const server = createMcpServer(instance);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    // The mcp-inspector opens a server->client SSE stream with GET /mcp. This server is stateless
    // POST-only (sessionIdGenerator: undefined), so per the Streamable HTTP spec it MUST answer a
    // GET with 405 Method Not Allowed (NOT 400) — that lets the inspector degrade gracefully to
    // POST-only and connect, instead of treating it as a fatal "Bad Request". NOTE: the full
    // persistence flow is holder-of-key, so the retry needs a real per-request `_kyaos_proof` the
    // inspector cannot mint — run the scenario scripts to see it end-to-end.
    if (url.pathname === '/mcp') {
      res.writeHead(405, { 'Content-Type': 'application/json', Allow: 'POST' });
      res.end(
        JSON.stringify({
          error: 'method_not_allowed',
          message:
            'consent-persistence uses stateless POST-only Streamable HTTP (no server->client SSE ' +
            'stream). The inspector connects fine for tools; the full holder-of-key persistence ' +
            'flow needs a per-request _kyaos_proof — run:  npm run scenario:cross-instance  and  npm run scenario:restart.',
        }),
      );
      return;
    }

    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          instance: instance.label,
          did,
          mcp: `http://localhost:${port}/mcp`,
          note: 'Holder-of-key + scenario-script-driven; NOT mcp-inspector-interactive. See README and npm run scenario:*.',
        }),
      );
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  httpServer.listen(port, () => {
    process.stderr.write(`[consent-persistence] instance ${instance.label}: http://localhost:${port}/mcp\n`);
  });
  return httpServer;
}

async function main() {
  const identity = await loadIdentity();
  const dataDir = path.resolve(__dirname, '..', '.data');
  const stores = createStores(dataDir); // ONE file-backed store, shared by both instances

  const consentPort = parseInt(process.env['CONSENT_PORT'] ?? '3015', 10);
  const portA = parseInt(process.env['PORT_A'] ?? process.env['PORT'] ?? '3005', 10);
  const portB = parseInt(process.env['PORT_B'] ?? '3006', 10);

  const consent = await startConsentServer({ port: consentPort, identity, grantStore: stores.grantStore });
  const consentUrl = `${consent.url}/consent`;

  const instanceA = createInstance({ label: 'A', identity, grantStore: stores.grantStore, consentUrl });
  const instanceB = createInstance({ label: 'B', identity, grantStore: stores.grantStore, consentUrl });

  startHttpInstance(instanceA, portA, identity.did);
  startHttpInstance(instanceB, portB, identity.did);

  process.stderr.write(`[consent-persistence] consent page: ${consentUrl}\n`);
  process.stderr.write(`[consent-persistence] agent DID: ${identity.did}\n`);
  process.stderr.write(`[consent-persistence] shared store dir: ${dataDir}\n`);
  process.stderr.write(
    `[consent-persistence] NOTE: holder-of-key + scenario-script-driven — NOT mcp-inspector-interactive ` +
      `(the inspector can't mint the per-request _kyaos_proof). Run: npm run scenario:cross-instance / scenario:restart.\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err}\n`);
  process.exit(1);
});
