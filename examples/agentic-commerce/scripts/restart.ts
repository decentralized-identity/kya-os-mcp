#!/usr/bin/env npx tsx
/** Cold restart: setup without a grant, then start both services in one command. */
import { spawn, type ChildProcess } from 'node:child_process';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'dotenv';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Do not import wiring here: loading .env.local into this process would pass
// stale identity keys to the service child after setup rotates them.
function readEnv(file: string): Record<string, string> {
  try { return parse(readFileSync(path.join(root, file))); } catch { return {}; }
}
const config = { ...readEnv('.env'), ...readEnv('.env.local'), ...process.env };
let child: ChildProcess | undefined;
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => { stopping = true; child?.kill(signal); });
}

function portInUse(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const done = (inUse: boolean) => { socket.destroy(); resolve(inUse); };
    socket.setTimeout(1000, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

function run(file: string): Promise<number> {
  return new Promise((resolve, reject) => {
    child = spawn(process.execPath, ['--import', 'tsx', file], { cwd: root, stdio: 'inherit', env: process.env });
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve(code ?? (signal === 'SIGINT' || stopping ? 0 : 1)));
  });
}

async function main(): Promise<void> {
  const ports = [Number(config['MERCHANT_PORT'] ?? 4949), Number(config['RP_PORT'] ?? 4950)];
  const occupied = await Promise.all(ports.map(portInUse));
  if (occupied.some(Boolean)) throw new Error(`Demo port in use (${ports.filter((_, i) => occupied[i]).join(', ')}). Stop the existing demo with Ctrl+C, then run npm run demo:restart.`);
  const started = Date.now();
  const setupCode = await run('scripts/setup.ts');
  if (setupCode || stopping) { process.exitCode = setupCode; return; }
  console.log(`\nFresh state prepared in ${((Date.now() - started) / 1000).toFixed(1)} seconds. Starting merchant and RP; human approval is required.`);
  process.exitCode = await run('src/demo.ts');
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
