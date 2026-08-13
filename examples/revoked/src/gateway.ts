#!/usr/bin/env npx tsx
/**
 * KYA-OS GATEWAY — the agent runtime Claude Desktop plugs into.
 *
 *   Claude Desktop (the brain — no keys)
 *     │  plain MCP  (stdio for local; streamable-http for a remote connector)
 *     ▼
 *   THIS gateway (holds the agent's did:key + delegation VC; signs every call)
 *     │  wallet_send + VC + Ed25519 holder proof   (streamable-http)
 *     ▼
 *   Protected MCP server (withKyaOs verifier + server-held wallet)
 *
 * Claude sees a clean tool surface — `wallet_send({ amount, to? })` — with NO
 * crypto arguments. The gateway injects the credential and mints the
 * per-request holder proof (reusing src/agent.ts). The LLM never touches key
 * material: that is the point, and a talking point.
 *
 * Run:
 *   npm run gateway            # stdio — for Claude Desktop's local config
 *   npm run gateway -- --http  # streamable-http on GATEWAY_PORT (remote connector)
 */
import http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { env } from './lib/wiring.js';
import { runAgentSend, loadAgentIdentity } from './agent.js';

const PROTECTED_URL = env('PROTECTED_MCP_URL', `http://localhost:${env('DEMO_PORT', '4949')}/mcp`);
// The custodian's origin. The gateway holds only the agent's did:key authority
// key — it NEVER loads the funds wallet mnemonic. Balance is a read call to the
// protected server (which custodies the wallet), so the trust boundary is
// physical, not just logical: kill this process and no funds key is exposed.
const PROTECTED_ORIGIN = new URL(PROTECTED_URL).origin;

function cheq(ncheq: bigint): string {
  return (Number(ncheq) / 1e9).toLocaleString('en-US', { maximumFractionDigits: 4 });
}

function createGatewayServer(): Server {
  const server = new Server(
    { name: 'kya-wallet', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'wallet_send',
        description:
          'Send CHEQ from your wallet on the cheqd testnet to a recipient. Your ' +
          'spending authority is a signed, revocable credential issued by your owner ' +
          '(scope payments.transfer, capped). You do not hold or handle any keys — the ' +
          'gateway signs on your behalf. Returns the transaction hash and explorer link ' +
          'on success, or the reason the payment was refused.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            amount: { type: 'string', description: 'Amount to send, in CHEQ (e.g. "1")' },
            to: {
              type: 'string',
              description: 'Recipient cheqd address (optional; defaults to the demo vendor treasury)',
            },
          },
          required: ['amount'],
        },
      },
      {
        name: 'check_balance',
        description: 'Check your cheqd testnet wallet balance and address.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    if (name === 'check_balance') {
      // Read from the custodian, not from a local key. The protected server
      // holds the wallet; the gateway just relays what it reports.
      try {
        const res = await fetch(`${PROTECTED_ORIGIN}/api/state`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const s = (await res.json()) as { agentAddress?: string; balanceNcheq?: string };
        return {
          content: [{
            type: 'text',
            text: `Wallet ${s.agentAddress ?? '(unknown)'}\n` +
              `Balance: ${cheq(BigInt(s.balanceNcheq ?? '0'))} CHEQ (testnet)`,
          }],
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Could not read balance from the payment server: ${err instanceof Error ? err.message : String(err)}` }],
        };
      }
    }

    if (name === 'wallet_send') {
      const amount = String((args as Record<string, unknown>)['amount'] ?? '');
      const toRaw = (args as Record<string, unknown>)['to'];
      // Be forgiving with the LLM: only forward `to` if it looks like a cheqd
      // address, so "pay the vendor" doesn't fail on a non-address string.
      const to = typeof toRaw === 'string' && /^cheqd1[0-9a-z]{20,}$/.test(toRaw) ? toRaw : undefined;

      try {
        const outcome = await runAgentSend({ amount, serverUrl: PROTECTED_URL, ...(to ? { to } : {}) });
        const text = outcome.result.content?.[0]?.text ?? '{}';
        let body: Record<string, unknown> = {};
        try { body = JSON.parse(text); } catch { body = { raw: text }; }

        if (outcome.result.isError || body['error']) {
          const code = String(body['error'] ?? 'refused');
          const reason = String(body['reason'] ?? body['message'] ?? text);
          return {
            isError: true,
            content: [{
              type: 'text',
              text: `Payment refused (${code}): ${reason}\n\n` +
                (code === 'delegation_invalid' && /revoked/i.test(reason)
                  ? 'Your spending credential has been revoked on-chain. No funds moved.'
                  : code === 'SCOPE_CONSTRAINT_VIOLATED'
                    ? 'The amount exceeds the cap in your signed credential. No funds moved.'
                    : 'No funds moved.'),
            }],
          };
        }

        const sent = `${cheq(BigInt(String(body['amountNcheq'] ?? '0')))} CHEQ`;
        return {
          content: [{
            type: 'text',
            text: `Sent ${sent} to ${String(body['to'] ?? 'the vendor')}.\n` +
              `Transaction: ${String(body['txHash'] ?? '')}\n` +
              `Explorer: ${String(body['explorer'] ?? '')}`,
          }],
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Gateway error reaching the payment server: ${err instanceof Error ? err.message : String(err)}` }],
        };
      }
    }

    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  });

  return server;
}

async function main() {
  const identity = loadAgentIdentity(); // fail fast if the agent has no credential/keys
  const useHttp = process.argv.includes('--http');

  if (!useHttp) {
    const server = createGatewayServer();
    await server.connect(new StdioServerTransport());
    process.stderr.write(`[gateway] kya-wallet ready on stdio\n`);
    process.stderr.write(`[gateway] agent ${identity.did}\n`);
    process.stderr.write(`[gateway] forwarding to ${PROTECTED_URL}\n`);
    return;
  }

  const port = Number(env('GATEWAY_PORT', '4950'));
  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${port}`);
    if (url.pathname === '/mcp' && req.method === 'POST') {
      const server = createGatewayServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => transport.close());
      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    }
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ name: 'kya-wallet gateway', agent: identity.did, forwardsTo: PROTECTED_URL, mcp: `/mcp` }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found' }));
  });
  httpServer.listen(port, () => {
    process.stderr.write(`[gateway] kya-wallet ready: http://localhost:${port}/mcp\n`);
    process.stderr.write(`[gateway] agent ${identity.did}\n`);
    process.stderr.write(`[gateway] forwarding to ${PROTECTED_URL}\n`);
  });
}

main().catch((err) => {
  process.stderr.write(`[gateway] fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
