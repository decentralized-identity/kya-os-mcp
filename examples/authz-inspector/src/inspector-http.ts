/**
 * One-command launcher for the Streamable HTTP demo: starts the `/mcp` server,
 * waits until it is accepting connections, then opens MCP Inspector already
 * pointed at it. This mirrors the stdio launcher's single-command experience —
 * you run one thing, not "start the server, then separately start Inspector".
 *
 *   npm run example:authz-inspector:http
 *
 * Dependency-free: spawns the same `src/http.ts` server and the Inspector CLI
 * as child processes; no concurrently/wait-on needed.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = process.env['PORT'] ?? '3030';
const url = `http://localhost:${PORT}/mcp`;

// 1. Start the Streamable HTTP server (inherits stderr for its banner).
const server = spawn('npx', ['tsx', join(here, 'http.ts')], {
  stdio: ['ignore', 'inherit', 'inherit'],
  env: { ...process.env, PORT },
});

let inspector: ReturnType<typeof spawn> | undefined;

function shutdown(code = 0): void {
  inspector?.kill('SIGINT');
  server.kill('SIGINT');
  process.exit(code);
}
process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));

// 2. Poll the port until the server is accepting connections, then launch
//    Inspector pre-pointed at the /mcp URL.
async function waitForServer(timeoutMs = 15_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      // A bare POST is enough to confirm the listener is up; we ignore the body.
      await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  return false;
}

const ready = await waitForServer();
if (!ready) {
  process.stderr.write(`[kya-os] server did not come up on ${url} in time\n`);
  shutdown(1);
}

process.stderr.write(`[kya-os] server is up — launching MCP Inspector at ${url}\n`);
inspector = spawn(
  'npx',
  ['@modelcontextprotocol/inspector', '--transport', 'http', '--server-url', url],
  { stdio: 'inherit', env: process.env },
);

inspector.on('exit', (code) => shutdown(code ?? 0));
