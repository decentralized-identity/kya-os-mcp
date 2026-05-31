#!/usr/bin/env npx tsx
/**
 * Anti-MITM content-binding demo.
 *
 * A resource server answers an unauthorized tool call with a needs_authorization
 * challenge that embeds a consent URL, and signs a detached-JWS proof binding a
 * responseHash over that challenge content. ProofVerifier's content binding —
 * verifyProof(proof, jwk, { request, response }) — recomputes the response hash
 * over what the client ACTUALLY received and rejects a swapped consent URL with
 * CONTENT_BINDING_MISMATCH, even though the proof's signature is still valid.
 *
 *   npx tsx examples/verify-proof/anti-mitm-demo.ts
 */
import {
  ProofGenerator,
  ProofVerifier,
  NodeCryptoProvider,
  MemoryNonceCacheProvider,
  SystemClockProvider,
  RuntimeFetchProvider,
  generateDidKeyFromBase64,
  base64urlEncodeFromBytes,
} from '@kya-os/mcp';

async function main() {
  const crypto = new NodeCryptoProvider();
  const kp = await crypto.generateKeyPair();
  const did = generateDidKeyFromBase64(kp.publicKey);
  const kid = `${did}#${did.replace('did:key:', '')}`;

  // ── Server side: sign the challenge bound to the consent URL ──────────────
  const gen = new ProofGenerator(
    { did, kid, privateKey: kp.privateKey, publicKey: kp.publicKey },
    crypto,
  );
  const request = { method: 'tools/call', params: { name: 'restricted_greet' } };
  const challenge = {
    error: 'needs_authorization',
    message: 'requires delegation with scope: greeting:restricted',
    authorizationUrl: 'https://issuer.example/consent?scope=greeting:restricted',
    scopes: ['greeting:restricted'],
  };
  const genuineContent = [{ type: 'text', text: JSON.stringify(challenge) }];

  const nowSec = Math.floor(Date.now() / 1000);
  const session = {
    sessionId: 'sess_demo',
    audience: did,
    nonce: base64urlEncodeFromBytes(await crypto.randomBytes(16)),
    timestamp: nowSec,
    createdAt: nowSec,
    lastActivity: nowSec,
    ttlMinutes: 30,
    identityState: 'anonymous' as const,
  };
  const proof = await gen.generateProof(request, { data: genuineContent }, session, {
    outcome: 'needs_authorization',
    reason: challenge.message,
  });

  // ── Client side: verify with content binding ──────────────────────────────
  const makeVerifier = () =>
    new ProofVerifier({
      cryptoProvider: crypto,
      clockProvider: new SystemClockProvider(),
      nonceCacheProvider: new MemoryNonceCacheProvider(),
      fetchProvider: new RuntimeFetchProvider(),
      timestampSkewSeconds: 300,
    });

  const jwk = await makeVerifier().fetchPublicKeyFromDID(did);
  if (!jwk) throw new Error('could not resolve signer did:key');

  console.log('Server signed challenge authorizationUrl:');
  console.log('   ', challenge.authorizationUrl);
  console.log('Proof binds responseHash:', proof.meta.responseHash);
  console.log();

  // 1) Genuine — client received exactly what the server signed.
  const genuine = await makeVerifier().verifyProof(proof, jwk, {
    request,
    response: { data: genuineContent },
  });
  console.log(
    '[1] genuine content       ->',
    genuine.valid ? 'VALID' : `INVALID (${genuine.errorCode})`,
  );

  // 2) MITM — an in-path intermediary swaps the consent URL in the delivered content.
  const swappedContent = [
    {
      type: 'text',
      text: JSON.stringify({ ...challenge, authorizationUrl: 'https://attacker.example/consent' }),
    },
  ];
  const mitm = await makeVerifier().verifyProof(proof, jwk, {
    request,
    response: { data: swappedContent },
  });
  console.log(
    '[2] MITM-swapped URL      ->',
    mitm.valid ? 'VALID (BUG — should reject!)' : `REJECTED: ${mitm.errorCode} (MITM detected)`,
  );

  // 3) Fail-closed — caller omits the response on a responseHash-bound proof.
  const noResponse = await makeVerifier().verifyProof(proof, jwk, { request });
  console.log(
    '[3] response not supplied ->',
    noResponse.valid ? 'VALID (BUG — should reject!)' : `REJECTED: ${noResponse.errorCode} (fail-closed)`,
  );

  console.log();
  const ok = genuine.valid && !mitm.valid && !noResponse.valid;
  console.log(ok ? 'Anti-MITM content binding: WORKING.' : 'Anti-MITM content binding: FAILED.');
  if (!ok) process.exit(1);
}

main().catch((err) => {
  console.error('Error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
