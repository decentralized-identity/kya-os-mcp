/**
 * Full clickable-flow test over the real HTTP authorization server, exercising
 * the stateful Streamable HTTP transport so the grant binds to the connection.
 *
 * Walks the flow the way a human does in MCP Inspector, but programmatically.
 * The caller pastes NOTHING — the only step is clicking Approve:
 *
 *   1. call read_vault (no args) → challenge: a real, clickable /authorize URL
 *   2. open /authorize → Approve → the SERVER runs the OAuth + PKCE exchange and
 *      binds the grant to this connection's session
 *   3. re-call read_vault (no args) → the session-bound grant auto-applies → vault reads
 *
 * No authorization codes, state, PKCE verifiers, or resume tokens are ever
 * surfaced to the caller. Deterministic and network-free (the authorization
 * server is in-process).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execSync, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const PORT = 3099;
const BASE = `http://localhost:${PORT}`;
let proc: ChildProcess;

beforeAll(async () => {
  // The demo spawns a child that imports the BUILT package
  // (`@kya-os/mcp/authz` → dist/authz/index.js). When this suite runs before
  // `npm run build` — e.g. the root `vitest run` that also globs examples —
  // dist/ is absent, the child dies with ERR_MODULE_NOT_FOUND, and that only
  // surfaced as a blind "did not start" timeout. Build once when the artifact
  // is missing so the e2e is self-sufficient regardless of task ordering
  // (a no-op in CI once the package is already built).
  if (!existsSync(join(repoRoot, 'dist', 'authz', 'index.js'))) {
    execSync('npm run build', { cwd: repoRoot, stdio: 'inherit' });
  }

  // Launch via `node --import tsx` rather than `npx tsx`: process.execPath is an
  // absolute path to the current node, so there is no PATH / `npx.cmd` shell
  // quirk on Windows. `cwd` is pinned to the example so `--import tsx` resolves
  // tsx from this package's own node_modules — Node resolves `--import` against
  // the working directory, which under the root test run is the repo root (where
  // tsx is not installed), not this example.
  proc = spawn(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'http.ts')], {
    cwd: join(here, '..'),
    stdio: ['ignore', 'inherit', 'pipe'],
    env: { ...process.env, PORT: String(PORT) },
  });

  // Surface the child's own failure instead of a silent timeout: if it exits
  // early, fail with its captured stderr (e.g. a missing-module crash).
  let stderr = '';
  let exited: string | undefined;
  proc.stderr?.on('data', (d) => { stderr += String(d); });
  proc.on('exit', (code) => {
    if (code) exited = `demo HTTP server exited early (code ${code}):\n${stderr}`;
  });

  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (exited) throw new Error(exited);
    try {
      await fetch(`${BASE}/`);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw new Error(`demo HTTP server did not start${stderr ? `:\n${stderr}` : ''}`);
}, 60_000);

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
    const authorizeUrl = /open the URL:\s*(http:\/\/\S+)/.exec(textOf(challenge))?.[1];
    expect(authorizeUrl, 'challenge should contain a real /authorize URL').toBeTruthy();

    const page = await fetch(authorizeUrl!);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain('Approve');
    expect(html).toContain('vault:read');
    await client.close();
  });

  it('reads the vault after approving — the caller supplies nothing on retry', async () => {
    const client = await mcpClient();

    // 1. Protected call → challenge with a real, clickable authorize URL.
    const challenge = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
    };
    const cText = textOf(challenge);
    // Extract the bare URL from the "(or open the URL: …)" line (no trailing ')').
    const authorizeUrl = /open the URL:\s*(http:\/\/\S+)/.exec(cText)?.[1];
    expect(authorizeUrl, 'challenge should contain a real authorize URL').toBeTruthy();
    // The caller is NOT asked for a code, state, or even a resume_token here.
    expect(cText).not.toContain('authorization_code:');
    expect(cText).toContain('no arguments needed');

    // 2. Human approves in the browser; the server completes the exchange and
    //    binds the grant to this connection's session.
    await approveInBrowser(authorizeUrl!);

    // 3. Re-call with NO arguments at all. Because the MCP client keeps the same
    //    session across calls, the server auto-applies the session-bound grant —
    //    no resume_token, no code, nothing to paste.
    const authorized = (await client.callTool({
      name: 'read_vault',
      arguments: {},
    })) as { content: Array<{ type: string; text?: string }>; isError?: boolean };

    expect(authorized.isError).toBeFalsy();
    const text = textOf(authorized);
    expect(text).toContain('Vault read authorized');
    expect(text).toContain('vault:read');
    await client.close();
  });

  it('re-prompts (does not error) if retried before approval', async () => {
    const client = await mcpClient();
    await client.callTool({ name: 'read_vault', arguments: {} });

    // Retry before approving → still unauthorized, so the tool re-prompts with
    // a fresh authorization challenge rather than erroring or reading the vault.
    const retry = (await client.callTool({ name: 'read_vault', arguments: {} })) as {
      content: Array<{ type: string; text?: string }>;
      isError?: boolean;
    };
    const retryText = textOf(retry);
    expect(retry.isError).toBeFalsy();
    expect(retryText).toContain('requires authorization');
    expect(retryText).not.toContain('Vault read authorized');
    await client.close();
  });
});
