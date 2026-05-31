#!/usr/bin/env npx tsx
/**
 * MCP Server with Consent-Based Delegation
 *
 * Demonstrates two tools:
 *   - browse   (public)    — executes without delegation, proof attached
 *   - checkout (protected) — requires a W3C Delegation Credential with scope cart:write
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
import { createKyaOsMiddleware, NodeCryptoProvider, generateDidKeyFromBase64, type KyaOsMiddleware } from '@kya-os/mcp';
import { startConsentServer } from './consent-server.js';
import { createDelegationIssuerFromIdentity } from './delegation-issuer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDENTITY_PATH = path.resolve(__dirname, '..', '.kya-os', 'identity.json');

export interface ServerConfig {
  consentUrl: string;
  delegationStore?: DelegationStore;
}

/**
 * In-memory store mapping resume_token → approved delegation VC.
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
 * Auto-inject a previously approved delegation on retry (resume-token flow via
 * the DelegationStore).
 *
 * The needs_authorization challenge presentation — the clickable markdown consent
 * link — is produced by the `formatChallenge` hook passed to `wrapWithDelegation`
 * (see createConsentMcpServer), NOT here. Rendering the link before signing lets
 * the challenge proof bind a `responseHash` over the link itself, keeping the
 * authorizationUrl tamper-evident; rewriting the response after signing (as this
 * wrapper used to) would have broken that binding.
 */
function formatAsConsentLink(
  toolName: string,
  delegationStore: DelegationStore | undefined,
  handler: (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult>,
): (args: Record<string, unknown>, sessionId?: string) => Promise<ToolResult> {
  return async (args, sessionId) => {
    // Resume-token flow: inject a previously approved VC on retry.
    if (!args['_kyaos_delegation'] && delegationStore) {
      const pending = delegationStore.findByTool(toolName);
      if (pending) {
        process.stderr.write(`[server] Auto-applying delegation from consent approval (token: ${pending.resumeToken})\n`);
        return handler({ ...args, _kyaos_delegation: pending.vc }, sessionId);
      }
    }
    return handler(args, sessionId);
  };
}

interface ToolResult {
  content: Array<{ type: string; text: string; [key: string]: unknown }>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

export function createConsentMcpServer(
  kyaos: KyaOsMiddleware,
  config: ServerConfig,
) {
  const server = new Server(
    { name: 'consent-basic-example', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  // browse: public tool — proof attached via wrapWithProof
  const browseHandler = kyaos.wrapWithProof('browse', async (args) => ({
    content: [{
      type: 'text',
      text: `Browsing category: ${args['category'] ?? 'all'}. Found 3 items.`,
    }],
  }));

  // checkout: protected tool — requires delegation with scope cart:write
  const rawCheckoutHandler = kyaos.wrapWithDelegation(
    'checkout',
    {
      scopeId: 'cart:write',
      consentUrl: config.consentUrl,
      // Render the challenge as a clickable markdown consent link BEFORE signing,
      // so the challenge proof binds a responseHash over the rendered link
      // (tamper-evident authorizationUrl). LLM / chat-style MCP clients render it.
      formatChallenge: (challenge) => {
        const url = new URL(config.consentUrl);
        url.searchParams.set('tool', 'checkout');
        url.searchParams.set('scopes', challenge.scopes.join(','));
        url.searchParams.set('agent_did', kyaos.identity.did);
        url.searchParams.set('resume_token', challenge.resumeToken);
        return [{
          type: 'text' as const,
          text: `Authorization required.\n\n[Authorize checkout](${url.toString()})\n\nRetry after authorizing.`,
        }];
      },
    },
    kyaos.wrapWithProof('checkout', async (args) => ({
      content: [{
        type: 'text',
        text: `Order confirmed for item: ${args['item'] ?? 'unknown'}. Thank you!`,
      }],
    })),
  );
  const checkoutHandler = formatAsConsentLink(
    'checkout',
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

/**
 * Load identity from .kya-os/identity.json if it exists,
 * otherwise generate an ephemeral one.
 */
export async function loadKyaOsMiddleware() {
  const crypto = new NodeCryptoProvider();
  let did: string;
  let kid: string;
  let privateKey: string;
  let publicKey: string;

  if (fs.existsSync(IDENTITY_PATH)) {
    const stored = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as {
      did: string; kid: string; privateKey: string; publicKey: string;
    };
    did = stored.did;
    kid = stored.kid;
    privateKey = stored.privateKey;
    publicKey = stored.publicKey;
    process.stderr.write(`[server] Loaded identity from ${IDENTITY_PATH}\n`);
  } else {
    const keyPair = await crypto.generateKeyPair();
    did = generateDidKeyFromBase64(keyPair.publicKey);
    kid = `${did}#${did.replace('did:key:', '')}`;
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
    process.stderr.write(`[server] Generated ephemeral identity (run 'npm run generate-identity' to persist)\n`);
  }

  return createKyaOsMiddleware(
    {
      identity: { did, kid, privateKey, publicKey },
      session: { sessionTtlMinutes: 60 },
      autoSession: true,
    },
    crypto,
  );
}

function setCorsHeaders(res: http.ServerResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, MCP-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'MCP-Session-Id');
}

/**
 * Start the MCP server with SSE + Streamable HTTP transports.
 */
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

    // ── SSE transport: GET /sse + POST /messages ──────────────────
    if (url.pathname === '/sse' && req.method === 'GET') {
      const server = createConsentMcpServer(kyaos, { consentUrl, delegationStore });
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

    // ── Streamable HTTP transport: POST /mcp ─────────────────────
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const server = createConsentMcpServer(kyaos, { consentUrl, delegationStore });
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }

    // ── Info endpoint ────────────────────────────────────────────
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: 'consent-basic-example',
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

// Run standalone
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const transport = process.argv.includes('--stdio') ? 'stdio'
    : process.argv.includes('--sse') ? 'sse'
    : process.argv.includes('--mcp') ? 'mcp'
    : 'sse'; // default to HTTP (SSE + /mcp) for Inspector compatibility

  const port = parseInt(process.env['PORT'] ?? '3002', 10);
  // In stdio mode, use ephemeral port (0) to avoid conflicts
  const consentPort = transport === 'stdio'
    ? 0
    : parseInt(process.env['CONSENT_PORT'] ?? '3001', 10);

  loadKyaOsMiddleware().then(async (kyaos) => {
    // Start consent server with the MCP server's identity so VCs are
    // issued by the same DID that verifies them (single trust domain).
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
      const server = createConsentMcpServer(kyaos, { consentUrl, delegationStore });
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
