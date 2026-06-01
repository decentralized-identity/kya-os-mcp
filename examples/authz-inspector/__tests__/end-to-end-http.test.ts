/**
 * Full clickable-flow test over the real HTTP authorization server.
 *
 * Boots the demo's HTTP server (MCP `/mcp` + a genuine OAuth 2.1 + PKCE
 * authorization server) and walks the entire flow the way a human would in a
 * browser, but programmatically: the protected tool returns a challenge with a
 * real `/authorize` URL → GET that page → POST /approve → follow the redirect
 * to /callback → read the issued code → re-call `read_vault` with it → the
 * vault reads. Proves the authorize URL is genuinely visitable and the PKCE
 * code exchange runs end to end locally (no external IdP).
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
  // Wait until the server accepts connections.
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

describe('authz-inspector full clickable flow (real authorization server)', () => {
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

  it('completes the browser flow end to end and reads the vault', async () => {
    const client = await mcpClient();

    // 1. Protected call → challenge with a real authorize URL + resume token.
    const challenge = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
    };
    const cText = textOf(challenge);
    const authorizeUrl = /(http:\/\/[^\s]+\/authorize[^\s]*)/.exec(cText)?.[1];
    const resumeToken = /resume_token:\s*(\S+)/.exec(cText)?.[1];
    expect(authorizeUrl && resumeToken).toBeTruthy();

    // 2. GET the consent page, then POST /approve with the same authorize params
    //    (what the Approve button does), WITHOUT following the redirect.
    const authParams = new URL(authorizeUrl!).searchParams;
    const approve = await fetch(`${BASE}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: authParams.toString(),
      redirect: 'manual',
    });
    expect(approve.status).toBe(302);

    // 3. The redirect carries the authorization code + state.
    const location = approve.headers.get('location')!;
    const back = new URL(location);
    const code = back.searchParams.get('code');
    const state = back.searchParams.get('state');
    expect(code).toBeTruthy();
    expect(state).toBe('demo-state');

    // 4. Re-call read_vault with the real code → PKCE exchange against /token → vault reads.
    const authorized = (await client.callTool({
      name: 'read_vault',
      arguments: { authorization_code: code, resume_token: resumeToken, state },
    })) as { content: Array<{ type: string; text?: string }>; isError?: boolean };

    expect(authorized.isError).toBeFalsy();
    const text = textOf(authorized);
    expect(text).toContain('Vault read authorized');
    expect(text).toContain('vault:read');
    await client.close();
  });
});
