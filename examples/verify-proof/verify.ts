#!/usr/bin/env npx tsx
/**
 * KYA-OS Proof Verification Example
 *
 * Verifies a DetachedProof JSON from stdin or file argument.
 *
 * Usage:
 *   echo '{"jws":"...","meta":{...}}' | npx tsx examples/verify-proof/verify.ts
 *   npx tsx examples/verify-proof/verify.ts proof.json
 */

import { readFileSync } from 'node:fs';
import { ProofVerifier, type ProofVerifierConfig } from '../../src/proof/verifier.js';
import { createDidKeyResolver } from '../../src/delegation/did-key-resolver.js';
import { CryptoProvider } from '../../src/providers/base.js';
import { createHash, verify as cryptoVerify } from 'node:crypto';

class NodeCryptoProvider extends CryptoProvider {
  async sign(): Promise<Uint8Array> { throw new Error('Not needed for verification'); }
  async verify(data: Uint8Array, signature: Uint8Array, publicKeyBase64: string): Promise<boolean> {
    const keyBuffer = Buffer.from(publicKeyBase64, 'base64');
    const derPrefix = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
    const derKey = Buffer.concat([derPrefix, keyBuffer.subarray(0, 32)]);
    return cryptoVerify(undefined, Buffer.from(data), { key: derKey, format: 'der', type: 'spki' }, Buffer.from(signature));
  }
  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> { throw new Error('Not needed'); }
  async hash(data: Uint8Array): Promise<string> {
    return `sha256:${createHash('sha256').update(data).digest('hex')}`;
  }
  async randomBytes(): Promise<Uint8Array> { throw new Error('Not needed'); }
}

async function main() {
  let input: string;

  if (process.argv[2]) {
    input = readFileSync(process.argv[2], 'utf-8');
  } else if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk);
    }
    input = Buffer.concat(chunks).toString('utf-8');
  } else {
    console.error('Usage: npx tsx verify.ts <proof.json>');
    console.error('   or: echo \'{"jws":"...","meta":{...}}\' | npx tsx verify.ts');
    process.exit(1);
  }

  const proof = JSON.parse(input);
  console.log('Proof DID:', proof.meta?.did);
  console.log('Proof KID:', proof.meta?.kid);
  console.log('Session:', proof.meta?.sessionId);
  console.log('Timestamp:', new Date((proof.meta?.ts ?? 0) * 1000).toISOString());

  const crypto = new NodeCryptoProvider();
  const didResolver = createDidKeyResolver();

  const config: ProofVerifierConfig = {
    cryptoProvider: crypto,
    fetchPublicKeyFromDID: async (did: string) => {
      const result = didResolver(did);
      if (!result) return null;
      return result.publicKeyJwk;
    },
    timestampSkewSeconds: 300, // 5 minutes — generous for offline verification
  };

  const verifier = new ProofVerifier(config);
  const result = await verifier.verifyProofDetached(proof);

  console.log('\nVerification result:', result.valid ? 'VALID' : 'INVALID');
  if (!result.valid) {
    console.log('Error:', result.error?.code, '-', result.error?.message);
  }
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
