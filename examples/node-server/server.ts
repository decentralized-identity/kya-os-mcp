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
 *   3. delete_record    — destructive tool gated by the policy step-up (needs_approval
 *                         until signed approval grants are supplied in _kyaos_approvals)
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
import { createKyaOsMiddleware, generateDidKeyFromBase64 } from '@kya-os/mcp';
import { NodeCryptoProvider } from './node-crypto.js';
import { verifyApprovalGrantSignature } from './approval-demo.js';

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
      // This minimal example does NOT host a consent page. `consentUrl` is a
      // placeholder; `formatChallenge` (below) renders an actionable instruction
      // instead — and the challenge proof binds that rendered text. For a hosted
      // browser consent flow + page, see examples/consent-full.
      consentUrl: 'https://example.com/consent?scope=greeting:restricted',
      // Render the needs_authorization challenge as a concrete next step for THIS
      // (page-less) example, rather than a bare URL the caller can't act on.
      formatChallenge: (challenge) => [
        {
          type: 'text',
          text:
            `"restricted_greet" requires a delegation credential (scope: ${challenge.scopes.join(', ')}).\n\n` +
            `This minimal example does not host a consent page. To authorize:\n` +
            `  1. Mint a credential:  npx tsx examples/node-server/issue-delegation.ts\n` +
            `  2. Re-call restricted_greet with "_kyaos_delegation" set to the printed VC.\n\n` +
            `For a hosted consent page + browser flow, see the consent-full example.`,
        },
      ],
    },
    kyaos.wrapWithProof('restricted_greet', async (args) => ({
      content: [{ type: 'text', text: `Hello, ${args['name'] ?? 'world'}! (delegation verified)` }],
    })),
  );

  // delete_record: a destructive, in-scope action. The policy gate classifies it
  // (irreversible + prod namespace → catastrophic) and requires per-action human
  // approval: the first call returns `needs_approval`; supplying signed approval
  // grant(s) in `_kyaos_approvals` (bound to the call's requestHash) lets it proceed.
  // scopeMatched:true mimics composition after a verified delegation. The approval
  // verifier is a REAL Ed25519 check (examples/node-server/approval-demo.ts), not a stub.
  const deleteRecordHandler = kyaos.withPolicyGate!(
    'delete_record',
    kyaos.wrapWithProof('delete_record', async (args) => ({
      content: [{ type: 'text', text: `Deleted record ${args['record'] ?? '(none)'} — approved.` }],
    })),
    {
      scopeMatched: true,
      resolveNamespace: () => 'prod',
      isValidApprovalSignature: verifyApprovalGrantSignature,
    },
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
      {
        name: 'delete_record',
        description:
          'A destructive action gated by the policy step-up: returns needs_approval until signed approval grants are supplied in _kyaos_approvals.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            record: { type: 'string', description: 'Record id to delete' },
            _kyaos_approvals: {
              type: 'array',
              description: 'Signed approval grants (from issue-approval.ts), bound to this call\'s requestHash',
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

    if (name === 'delete_record') {
      return deleteRecordHandler(args as Record<string, unknown>);
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
