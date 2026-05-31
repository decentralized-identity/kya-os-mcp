#!/usr/bin/env npx tsx
/**
 * KYA-OS Proof Verification Example
 *
 * Verifies a DetachedProof JSON from stdin or a file argument: resolves the
 * signer's DID, checks the JWS signature, nonce-replay, and timestamp skew.
 * (To additionally detect content substitution — e.g. a swapped consent URL —
 * verify with the received request/response; see anti-mitm-demo.ts.)
 *
 * Usage:
 *   echo '{"jws":"...","meta":{...}}' | npx tsx examples/verify-proof/verify.ts
 *   npx tsx examples/verify-proof/verify.ts proof.json
 */

import { readFileSync } from 'node:fs';
import {
  ProofVerifier,
  NodeCryptoProvider,
  MemoryNonceCacheProvider,
  SystemClockProvider,
  RuntimeFetchProvider,
  type DetachedProof,
} from '@kya-os/mcp';

async function main() {
  let input: string;
  if (process.argv[2]) {
    input = readFileSync(process.argv[2], 'utf-8');
  } else if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    input = Buffer.concat(chunks).toString('utf-8');
  } else {
    console.error('Usage: npx tsx verify.ts <proof.json>   (or pipe the proof JSON on stdin)');
    process.exit(1);
  }

  const proof = JSON.parse(input) as DetachedProof;
  console.log('Proof DID: ', proof.meta?.did);
  console.log('Key ID:    ', proof.meta?.kid);
  console.log('Session:   ', proof.meta?.sessionId);
  console.log('Outcome:   ', proof.meta?.outcome ?? 'allowed (success)');
  console.log('Timestamp: ', new Date((proof.meta?.ts ?? 0) * 1000).toISOString());

  const verifier = new ProofVerifier({
    cryptoProvider: new NodeCryptoProvider(),
    clockProvider: new SystemClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RuntimeFetchProvider(),
    timestampSkewSeconds: 300, // generous for offline verification
  });

  // Resolve the signer's public key from its DID (did:key resolved offline).
  const jwk = await verifier.fetchPublicKeyFromDID(proof.meta.did);
  if (!jwk) {
    console.log('\nVerification result: INVALID (could not resolve signer DID)');
    process.exit(1);
  }

  const result = await verifier.verifyProof(proof, jwk);
  console.log('\nVerification result:', result.valid ? 'VALID' : 'INVALID');
  if (!result.valid) {
    console.log('Reason:', result.errorCode, '-', result.reason);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
