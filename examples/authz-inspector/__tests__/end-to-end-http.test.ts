/**
 * Full clickable-flow test over the real HTTP authorization server.
 *
 * Walks the flow the way a human does in MCP Inspector, but programmatically.
 * Crucially, the agent only ever handles ONE value — the `resume_token`:
 *
 *   1. call read_vault (no args) → challenge: a real /authorize URL + resume_token
 *   2. open /authorize → Approve → the SERVER runs the OAuth + PKCE exchange and
 *      caches the grant under the resume_token (the human copies nothing)
 *   3. re-call read_vault { resume_token } → server auto-applies the grant → vault reads
 *
 * This mirrors the consent-full pattern: approve once, retry once, done. No
 * authorization codes, state, or PKCE verifiers are ever surfaced to the caller.
 * Deterministic and network-free (the authorization server is in-process).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = 3099;
const BASE = `http://localhost:${PORT}`;
let proc: ChildProcess;

beforeAll(async () => {
  proc = spawn('npx', ['tsx', join(here, '..', 'src', 'http.ts')], {
    stdio: ['ignore', 'inherit', 'inherit'],
    env: { ...process.env, PORT: String(PORT) },
  });
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      await fetch(`${BASE}/`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw new Error('demo HTTP server did not start');
}, 30_000);

afterAll(() => {
  proc?.kill('SIGINT');
});

async function mcpClient(): Promise<Client> {
  const client = new Client({ name: 'e2e-client', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`)));
  return client;
}

function textOf(result: { content?: Array<{ type: string; text?: string }> }): string {
  return (result.content ?? []).map((c) => c.text ?? '').join('\n');
}

/** Approve a consent request the way the browser's Approve button does. */
async function approveInBrowser(authorizeUrl: string): Promise<void> {
  const params = new URL(authorizeUrl).searchParams;
  const res = await fetch(`${BASE}/approve`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
    redirect: 'manual',
  });
  // Approve redirects to /callback; following it triggers the server-side
  // token exchange + grant caching. We just need the GET to happen.
  const location = res.headers.get('location');
  expect(location, 'approve should redirect to the callback').toBeTruthy();
  await fetch(location!);
}

describe('authz-inspector one-token clickable flow', () => {
  it('serves a visitable consent page at the challenge authorize URL', async () => {
    const client = await mcpClient();
    const challenge = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
    };
    const authorizeUrl = /(http:\/\/[^\s]+\/authorize[^\s]*)/.exec(textOf(challenge))?.[1];
    expect(authorizeUrl, 'challenge should contain a real /authorize URL').toBeTruthy();

    const page = await fetch(authorizeUrl!);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('Approve');
    expect(html).toContain('vault:read');
    await client.close();
  });

  it('reads the vault after approving — the caller supplies only the resume_token', async () => {
    const client = await mcpClient();

    // 1. Protected call → challenge with a real authorize URL + resume token.
    const challenge = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
    };
    const cText = textOf(challenge);
    const authorizeUrl = /(http:\/\/[^\s]+\/authorize[^\s]*)/.exec(cText)?.[1];
    const resumeToken = /resume_token:\s*(\S+)/.exec(cText)?.[1];
    expect(authorizeUrl && resumeToken).toBeTruthy();
    // The caller is NOT asked for a code or state.
    expect(cText).not.toContain('authorization_code:');

    // 2. Human approves in the browser; the server completes the exchange.
    await approveInBrowser(authorizeUrl!);

    // 3. Re-call with ONLY the resume_token → grant auto-applied → vault reads.
    const authorized = (await client.callTool({
      name: 'read_vault',
      arguments: { resume_token: resumeToken },
    })) as { content: Array<{ type: string; text?: string }>; isError?: boolean };

    expect(authorized.isError).toBeFalsy();
    const text = textOf(authorized);
    expect(text).toContain('Vault read authorized');
    expect(text).toContain('vault:read');
    await client.close();
  });

  it('still shows the pending challenge if retried before approval', async () => {
    const client = await mcpClient();
    const challenge = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
    };
    const resumeToken = /resume_token:\s*(\S+)/.exec(textOf(challenge))?.[1];

    // Retry with the token before approving → not yet authorized, re-prompt.
    const retry = (await client.callTool({
      name: 'read_vault',
      arguments: { resume_token: resumeToken },
    })) as { content: Array<{ type: string; text?: string }> };
    const retryText = textOf(retry);
    expect(retryText).toContain('requires authorization');
    // The same resume_token is restated — retrying before approval does not
    // silently invalidate the token the user is holding.
    expect(retryText).toContain(resumeToken!);
    await client.close();
  });
});
