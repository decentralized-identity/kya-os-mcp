#!/usr/bin/env npx tsx
/**
 * Generate Identity
 *
 * Creates a persistent Ed25519 DID identity and saves it to .kya-os/identity.json.
 * If an identity already exists, prints it without overwriting.
 *
 * Usage:
 *   npx tsx scripts/generate-identity.ts
 *   npx tsx scripts/generate-identity.ts --force   # overwrite existing
 *
 * The server reads this file on startup so the DID survives restarts.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NodeCryptoProvider, generateDidKeyFromBase64 } from '@kya-os/mcp';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const IDENTITY_DIR = path.resolve(__dirname, '..', '.kya-os');
const IDENTITY_PATH = path.join(IDENTITY_DIR, 'identity.json');

interface PersistedIdentity {
  did: string;
  kid: string;
  privateKey: string;
  publicKey: string;
  createdAt: string;
}

async function main() {
  const force = process.argv.includes('--force');

  // Check for existing identity
  if (fs.existsSync(IDENTITY_PATH) && !force) {
    const existing = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8')) as PersistedIdentity;
    process.stderr.write(`Identity already exists (use --force to regenerate)\n`);
    process.stderr.write(`  DID: ${existing.did}\n`);
    process.stderr.write(`  Created: ${existing.createdAt}\n`);
    process.stderr.write(`  Path: ${IDENTITY_PATH}\n`);
    return;
  }

  // Generate new identity
  const crypto = new NodeCryptoProvider();
  const keyPair = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(keyPair.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  const identity: PersistedIdentity = {
    did,
    kid,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    createdAt: new Date().toISOString(),
  };

  // Write to disk
  fs.mkdirSync(IDENTITY_DIR, { recursive: true });
  fs.writeFileSync(IDENTITY_PATH, JSON.stringify(identity, null, 2) + '\n');

  process.stderr.write(`Identity generated\n`);
  process.stderr.write(`  DID: ${did}\n`);
  process.stderr.write(`  Path: ${IDENTITY_PATH}\n`);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err}\n`);
  process.exit(1);
});
