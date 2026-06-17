#!/usr/bin/env npx tsx
/**
 * Generate the shared Ed25519 identity used by BOTH server instances and read
 * back after a restart. Saves to .kya-os/identity.json.
 *
 * Usage:
 *   npx tsx scripts/generate-identity.ts
 *   npx tsx scripts/generate-identity.ts --force   # overwrite existing
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDENTITY_DIR = path.resolve(__dirname, '..', '.kya-os');
const IDENTITY_PATH = path.join(IDENTITY_DIR, 'identity.json');

async function main() {
  const force = process.argv.includes('--force');

  if (fs.existsSync(IDENTITY_PATH) && !force) {
    const existing = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as { did: string };
    process.stderr.write(`Identity already exists (use --force to regenerate)\n`);
    process.stderr.write(`  DID: ${existing.did}\n`);
    process.stderr.write(`  Path: ${IDENTITY_PATH}\n`);
    return;
  }

  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  fs.mkdirSync(IDENTITY_DIR, { recursive: true });
  fs.writeFileSync(
    IDENTITY_PATH,
    JSON.stringify(
      { did, kid, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, createdAt: new Date().toISOString() },
      null,
      2,
    ) + '\n',
  );

  process.stderr.write(`Identity generated\n  DID: ${did}\n  Path: ${IDENTITY_PATH}\n`);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
