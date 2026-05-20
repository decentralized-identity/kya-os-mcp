#!/usr/bin/env npx tsx
/**
 * MCP Server with Consent-Based Delegation
 *
 * Demonstrates two tools:
 *   - browse   (public)    — executes freely, proof attached
 *   - checkout (protected) — requires a W3C Delegation Credential with scope cart:write
 *
 * The consent UI is served by consent-server.ts (the @kya-os/consent showcase).
 * This file is MCP server infrastructure — identical in structure to consent-basic.
 *
 * Architecture note:
 *   This example uses the low-level SDK `Server` API with `createKyaOsMiddleware`
 *   instead of the 2-line `withKyaOs(server, { crypto })` pattern (see examples/
 *   context7-with-kya-os for that). The reason: delegation-protected tools receive
 *   `_kyaos_delegation` as a tool argument. McpServer.registerTool validates args
 *   against zod schemas and strips unknown keys — so the delegation VC would be
 *   silently dropped before the handler sees it. The low-level Server API passes
 *   args through without schema validation, which delegation requires.
 *
 * Transports: stdio (default), sse, mcp (Streamable HTTP)
 *
 * Related Spec: KYA-OS §4 (Delegation), §5 (Proof), §6 (Authorization)
 */

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  createKyaOsMiddleware,
  generateIdentity,
  type KyaOsMiddleware,
  type KyaOsIdentityConfig,
} from '../../../src/middleware/index.js';
import { NodeCryptoProvider } from '../../../src/providers/node-crypto.js';
import { startConsentServer } from './consent-server.js';
import { createDelegationIssuerFromIdentity } from './delegation-issuer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDENTITY_PATH = path.resolve(__dirname, '..', '.kya-os', 'identity.json');

// ── Application-Level Types ─────────────────────────────────────────
// These are example-specific patterns for the resume_token consent flow,
// not part of the KYA-OS protocol itself.

export interface ServerConfig {
  consentUrl: string;
  delegationStore?: DelegationStore;
}

/**
 * In-memory store mapping resume_token -> approved delegation VC.
 *
 * When a user approves on the consent page, the VC is stored here keyed
 * by resume_token. On the next tool call, the server checks this store
 * and automatically injects the delegation.
 */
export class DelegationStore {
  private store = new Map<string, { vc: unknown; expiresAt: number }>();

  set(resumeToken: string, vc: unknown, ttlSeconds = 300): void {
    this.store.set(resumeToken, { vc, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  get(resumeToken: string): unknown | undefined {
    const entry = this.store.get(resumeToken);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(resumeToken);
      return undefined;
    }
    return entry.vc;
  }

  /** Find any pending delegation for a given tool (checks all entries). */
  findByTool(toolName: string): { resumeToken: string; vc: unknown } | undefined {
    for (const [token, entry] of this.store) {
      if (Date.now() > entry.expiresAt) {
        this.store.delete(token);
        continue;
      }
      const vc = entry.vc as Record<string, unknown> | undefined;
      const metadata = (vc?.credentialSubject as Record<string, unknown>)
        ?.delegation as Record<string, unknown> | undefined;
      if (metadata?.metadata && (metadata.metadata as Record<string, unknown>).tool === toolName) {
        this.store.delete(token); // consume it
        return { resumeToken: token, vc: entry.vc };
      }
    }
    return undefined;
  }
}

/**
 * Intercept needs_authorization responses and reformat as a clickable
 * consent link with URL params (tool, scopes, agent_did, resume_token).
 *
 * Also checks the DelegationStore for previously approved delegations
 * and auto-injects them on retry.
 */
function formatAsConsentLink(
  toolName: string,
  consentBaseUrl: string,
  agentDid: string,
  delegationStore: DelegationStore | undefined,
  handler: (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>,
): (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult> {
  return async (args, sessionId) => {
    // Check the delegation store for a previously approved VC (resume token flow).
    if (!args['_kyaos_delegation'] && delegationStore) {
      const pending = delegationStore.findByTool(toolName);
      if (pending) {
        process.stderr.write(`[server] Auto-applying delegation from consent approval (token: ${pending.resumeToken})\n`);
        return handler({ ...args, _kyaos_delegation: pending.vc }, sessionId);
      }
    }

    const result = await handler(args, sessionId);

    // Intercept needs_authorization JSON and reformat as markdown link
    const text = result.content?.[0]?.text;
    if (text && !result.isError) {
      try {
        const parsed = JSON.parse(text) as {
          error?: string;
          scopes?: string[];
          resumeToken?: string;
        };
        if (parsed.error === 'needs_authorization') {
          const url = new URL(consentBaseUrl);
          url.searchParams.set('tool', toolName);
          url.searchParams.set('scopes', (parsed.scopes ?? []).join(','));
          url.searchParams.set('agent_did', agentDid);
          if (parsed.resumeToken) {
            url.searchParams.set('resume_token', parsed.resumeToken);
          }

          return {
            content: [{
              type: 'text' as const,
              text: `Authorization required.\n\n[Authorize ${toolName}](${url.toString()})\n\nRetry after authorizing.`,
            }],
            isError: false,
          };
        }
      } catch {
        // Not JSON — pass through
      }
    }

    return result;
  };
}

export interface ToolResult {
  content: Array<{ type: string; text: string; [key: string]: unknown }>;
  isError?: boolean;
  _meta?: { proof?: { jws: string; meta: Record<string, unknown> } };
  [key: string]: unknown;
}

// ── MCP Server Factory ──────────────────────────────────────────────
// Protocol integration: createKyaOsMiddleware provides wrapWithProof (§5)
// and wrapWithDelegation (§4). We use the low-level Server API because
// delegation requires raw args — see architecture note at top of file.

export function createConsentFullMcpServer(
  kyaos: KyaOsMiddleware,
  config: ServerConfig,
) {
  const server = new Server(
    { name: 'consent-full-example', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // browse: public tool — §5 proof attached via wrapWithProof
  const browseHandler = kyaos.wrapWithProof('browse', async (args) => ({
    content: [{
      type: 'text',
      text: `Browsing category: ${args['category'] ?? 'all'}. Found 3 items.`,
    }],
  }));

  // checkout: protected tool — §4 delegation with scope cart:write
  // wrapWithDelegation checks _kyaos_delegation in args (why we need raw args)
  const rawCheckoutHandler = kyaos.wrapWithDelegation(
    'checkout',
    { scopeId: 'cart:write', consentUrl: config.consentUrl },
    kyaos.wrapWithProof('checkout', async (args) => ({
      content: [{
        type: 'text',
        text: `Order confirmed for item: ${args['item'] ?? 'unknown'}. Thank you!`,
      }],
    })),
  );
  const checkoutHandler = formatAsConsentLink(
    'checkout',
    config.consentUrl,
    kyaos.identity.did,
    config.delegationStore,
    rawCheckoutHandler as (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>,
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      kyaos.kyaOsTool,
      {
        name: 'browse',
        description: 'Browse product categories (public — no delegation required)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            category: { type: 'string', description: 'Product category to browse' },
          },
        },
      },
      {
        name: 'checkout',
        description: 'Complete a purchase (requires delegation with scope: cart:write)',
        inputSchema: {
          type: 'object' as const,
          properties: {
            item: { type: 'string', description: 'Item to purchase' },
          },
          required: ['item'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    if (name === '_kyaos') {
      return kyaos.handleKyaOs(args as Record<string, unknown>);
    }

    if (name === 'browse') {
      return browseHandler(args as Record<string, unknown>);
    }

    if (name === 'checkout') {
      return checkoutHandler(args as Record<string, unknown>);
    }

    return {
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
      isError: true,
    };
  });

  return server;
}

// ── Identity + Middleware Setup ──────────────────────────────────────

/**
 * Load identity from .kya-os/identity.json or generate an ephemeral one,
 * then create KYA-OS middleware with session + proof + delegation support.
 */
export async function loadKyaOsMiddleware() {
  const crypto = new NodeCryptoProvider();

  let identity: KyaOsIdentityConfig;
  if (fs.existsSync(IDENTITY_PATH)) {
    identity = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as KyaOsIdentityConfig;
    process.stderr.write(`[server] Loaded identity from ${IDENTITY_PATH}\n`);
  } else {
    identity = await generateIdentity(crypto);
    process.stderr.write(`[server] Generated ephemeral identity (run 'npm run generate-identity' to persist)\n`);
  }

  return createKyaOsMiddleware(
    { identity, session: { sessionTtlMinutes: 60 }, autoSession: true },
    crypto,
  );
}

// ── HTTP Transport Boilerplate ───────────────────────────────────────
// Standard MCP transport setup — not specific to consent or delegation.

function setCorsHeaders(res: http.ServerResponse) {
  // EXAMPLE ONLY — restrict to your application origin in production
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, MCP-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'MCP-Session-Id');
}

/** Start the MCP server with SSE + Streamable HTTP transports. */
async function startHttpServer(kyaos: KyaOsMiddleware, consentUrl: string, port: number, delegationStore?: DelegationStore) {
  let sseTransport: SSEServerTransport | null = null;

  const httpServer = http.createServer(async (req, res) => {
    setCorsHeaders(res);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? '/', `http://localhost:${port}`);

    // SSE transport: GET /sse + POST /messages
    if (url.pathname === '/sse' && req.method === 'GET') {
      const server = createConsentFullMcpServer(kyaos, { consentUrl, delegationStore });
      sseTransport = new SSEServerTransport('/messages', res);
      await server.connect(sseTransport);
      process.stderr.write('[server] SSE client connected\n');
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

    // Streamable HTTP transport: POST /mcp
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const server = createConsentFullMcpServer(kyaos, { consentUrl, delegationStore });
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    // Info endpoint
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: 'consent-full-example',
        did: kyaos.identity.did,
        transports: {
          sse: `http://localhost:${port}/sse`,
          mcp: `http://localhost:${port}/mcp`,
        },
      }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });

  httpServer.listen(port, () => {
    process.stderr.write(`[server] HTTP server: http://localhost:${port}\n`);
    process.stderr.write(`[server]   SSE:  http://localhost:${port}/sse\n`);
    process.stderr.write(`[server]   MCP:  http://localhost:${port}/mcp\n`);
    process.stderr.write(`[server] Agent DID: ${kyaos.identity.did}\n`);
  });
}

// ── Entrypoint ──────────────────────────────────────────────────────

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const transport = process.argv.includes('--stdio') ? 'stdio'
    : process.argv.includes('--sse') ? 'sse'
    : process.argv.includes('--mcp') ? 'mcp'
    : 'sse'; // default to HTTP (SSE + /mcp) for Inspector compatibility

  const port = parseInt(process.env['PORT'] ?? '3002', 10);
  const consentPort = transport === 'stdio'
    ? 0
    : parseInt(process.env['CONSENT_PORT'] ?? '3001', 10);

  loadKyaOsMiddleware().then(async (kyaos) => {
    const cryptoProvider = new NodeCryptoProvider();
    const factory = createDelegationIssuerFromIdentity(cryptoProvider, {
      did: kyaos.identity.did,
      kid: kyaos.identity.kid,
      privateKey: kyaos.identity.privateKey,
      publicKey: kyaos.identity.publicKey,
    });
    // Shared delegation store — consent server writes, MCP server reads
    const delegationStore = new DelegationStore();
    const consentServer = await startConsentServer({ port: consentPort, factory, delegationStore });
    const consentUrl = `${consentServer.url}/consent`;

    if (transport === 'stdio') {
      process.stderr.write(`[server] Agent DID: ${kyaos.identity.did}\n`);
      const server = createConsentFullMcpServer(kyaos, { consentUrl, delegationStore });
      await server.connect(new StdioServerTransport());
      process.stderr.write('[server] MCP server running on stdio\n');
    } else {
      await startHttpServer(kyaos, consentUrl, port, delegationStore);
    }
  }).catch((err) => {
    process.stderr.write(`Fatal: ${err}\n`);
    process.exit(1);
  });
}
