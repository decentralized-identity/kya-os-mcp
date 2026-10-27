/**
 * .env.local read/merge/write for the setup script. Secrets stay in this
 * gitignored file with 0600 perms — never printed to stdout.
 */
import fs from 'node:fs';
import path from 'node:path';
import { EXAMPLE_ROOT } from './wiring.js';

const ENV_LOCAL = path.join(EXAMPLE_ROOT, '.env.local');

export function readEnvLocal(): Record<string, string> {
  if (!fs.existsSync(ENV_LOCAL)) return {};
  const out: Record<string, string> = {};
  for (const line of fs.readFileSync(ENV_LOCAL, 'utf-8').split('\n')) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (!match) continue;
    let value = match[2]!;
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    out[match[1]!] = value;
  }
  return out;
}

/** Merge keys in; existing non-empty values win unless overwrite is set. */
export function writeEnvLocal(updates: Record<string, string>, options?: { overwrite?: boolean }): void {
  const current = readEnvLocal();
  for (const [key, value] of Object.entries(updates)) {
    if (!options?.overwrite && current[key]) continue;
    current[key] = value;
  }
  // Always double-quote: dotenv treats an unquoted `#` as an inline comment,
  // which silently truncates DID key ids like did:web:...#key-1.
  const body = Object.entries(current).map(([k, v]) => `${k}="${v}"`).join('\n') + '\n';
  fs.writeFileSync(ENV_LOCAL, body, { mode: 0o600 });
  fs.chmodSync(ENV_LOCAL, 0o600);
}
