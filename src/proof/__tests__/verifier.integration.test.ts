/**
 * ProofVerifier Integration Tests (Real Crypto)
 *
 * Companion to verifier.test.ts — these tests use real Ed25519 signing,
 * real nonce caching, and real clock providers instead of mocking.
 *
 * The mocked unit tests verify pipeline logic and error code propagation.
 * These integration tests verify that real proofs are correctly verified
 * and that security properties hold with actual cryptographic operations.
 */

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { ProofGenerator } from '../generator.js';
import { ProofVerifier } from '../verifier.js';
import type { AgentIdentity } from '../../providers/base.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../delegation/did-key-resolver.js';
import type { Ed25519JWK } from '../../utils/crypto-service.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  RealClockProvider,
  RealFetchProvider,
  MemoryNonceCacheProvider,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';

describe('ProofVerifier (real crypto)', () => {
  let crypto: NodeCryptoProvider;
  let agent: AgentIdentity;
  let otherAgent: AgentIdentity;

  beforeAll(async () => {
    crypto = createRealCryptoProvider();
    agent = await createRealIdentity(crypto);
    otherAgent = await createRealIdentity(crypto);
  });

  function makeVerifier(): { verifier: ProofVerifier; nonceCache: MemoryNonceCacheProvider } {
    const nonceCache = new MemoryNonceCacheProvider();
    const verifier = new ProofVerifier({
      cryptoProvider: crypto,
      clockProvider: new RealClockProvider(),
      nonceCacheProvider: nonceCache,
      fetchProvider: new RealFetchProvider(),
      timestampSkewSeconds: 300,
    });
    return { verifier, nonceCache };
  }

  function getJwk(identity: AgentIdentity): Ed25519JWK {
    const raw = extractPublicKeyFromDidKey(identity.did);
    const jwk = publicKeyToJwk(raw!);
    jwk.kid = identity.kid;
    return jwk as Ed25519JWK;
  }

  async function generateProof(identity: AgentIdentity) {
    const gen = new ProofGenerator(
      { did: identity.did, kid: identity.kid, privateKey: identity.privateKey, publicKey: identity.publicKey },
      crypto
    );
    return gen.generateProof(
      { method: 'tools/call', params: { name: 'test-tool' } },
      { data: { output: 'result' } },
      {
        sessionId: 'sess_integration',
        audience: 'did:web:server.example.com',
        nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: Math.floor(Date.now() / 1000),
        createdAt: Math.floor(Date.now() / 1000),
        lastActivity: Math.floor(Date.now() / 1000),
        ttlMinutes: 30,
        identityState: 'anonymous',
      }
    );
  }

  // ── Core Verification ─────────────────────────────────────────

  it('should verify a valid proof with real Ed25519 signature', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);

    const result = await verifier.verifyProof(proof, jwk);

    expect(result.valid).toBe(true);
  });

  it('verifies a denial proof (no responseHash, signed outcome/reason) end-to-end', async () => {
    const { verifier } = makeVerifier();
    const gen = new ProofGenerator(
      { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
      crypto
    );
    const session = {
      sessionId: 'sess_denial',
      audience: 'did:web:server.example.com',
      nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp: Math.floor(Date.now() / 1000),
      createdAt: Math.floor(Date.now() / 1000),
      lastActivity: Math.floor(Date.now() / 1000),
      ttlMinutes: 30,
      identityState: 'anonymous' as const,
    };
    const proof = await gen.generateProof(
      { method: 'tools/call', params: { name: 'db.drop' } },
      undefined,
      session,
      { outcome: 'denied', reason: 'insufficient_scope' }
    );
    expect(proof.meta.responseHash).toBeUndefined();
    expect(proof.meta.outcome).toBe('denied');

    const jwk = getJwk(agent);
    // Verifies cleanly through the full standalone pipeline (structure + signature).
    expect((await verifier.verifyProof(proof, jwk)).valid).toBe(true);

    // outcome/reason are signed-over: tampering the reason invalidates the proof
    // (fresh verifier to avoid a nonce-replay false negative).
    const tampered = { ...proof, meta: { ...proof.meta, reason: 'totally_different' } };
    const { verifier: v2 } = makeVerifier();
    expect((await v2.verifyProof(tampered, jwk)).valid).toBe(false);
  });

  it('verifies a needs_authorization challenge proof bound to the challenge content (responseHash) end-to-end', async () => {
    const { verifier } = makeVerifier();
    const gen = new ProofGenerator(
      { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
      crypto
    );
    const session = {
      sessionId: 'sess_needsauth',
      audience: 'did:web:server.example.com',
      nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp: Math.floor(Date.now() / 1000),
      createdAt: Math.floor(Date.now() / 1000),
      lastActivity: Math.floor(Date.now() / 1000),
      ttlMinutes: 30,
      identityState: 'anonymous' as const,
    };
    // The challenge content carries the authorizationUrl; binding it via
    // responseHash lets a verifier detect a tampered / MITM-swapped consent URL.
    const challengeContent = [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'needs_authorization',
          authorizationUrl: 'https://issuer.example/consent',
          scopes: ['greeting:restricted'],
        }),
      },
    ];
    const proof = await gen.generateProof(
      { method: 'tools/call', params: { name: 'restricted_greet' } },
      { data: challengeContent },
      session,
      { outcome: 'needs_authorization', reason: 'requires delegation with scope: greeting:restricted' }
    );
    expect(proof.meta.outcome).toBe('needs_authorization');
    expect(proof.meta.responseHash).toBeDefined();

    const jwk = getJwk(agent);
    expect((await verifier.verifyProof(proof, jwk)).valid).toBe(true);

    // A MITM swapping the consent URL changes the bound responseHash; the proof
    // then fails verification (fresh verifier avoids a nonce-replay false negative).
    const tampered = { ...proof, meta: { ...proof.meta, responseHash: 'sha256:deadbeefdeadbeef' } };
    const { verifier: v2 } = makeVerifier();
    expect((await v2.verifyProof(tampered, jwk)).valid).toBe(false);
  });

  it('detects a MITM-swapped consent URL via expected-content binding (real anti-MITM)', async () => {
    const gen = new ProofGenerator(
      { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
      crypto
    );
    const session = {
      sessionId: 'sess_mitm',
      audience: 'did:web:server.example.com',
      nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp: Math.floor(Date.now() / 1000),
      createdAt: Math.floor(Date.now() / 1000),
      lastActivity: Math.floor(Date.now() / 1000),
      ttlMinutes: 30,
      identityState: 'anonymous' as const,
    };
    const request = { method: 'tools/call', params: { name: 'restricted_greet' } };
    const genuine = [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'needs_authorization',
          authorizationUrl: 'https://issuer.example/consent',
          scopes: ['greeting:restricted'],
        }),
      },
    ];
    const proof = await gen.generateProof(request, { data: genuine }, session, {
      outcome: 'needs_authorization',
      reason: 'requires delegation',
    });
    const jwk = getJwk(agent);

    // The genuine content the server signed → verifies WITH content binding.
    const ok = makeVerifier().verifier;
    expect(
      (await ok.verifyProof(proof, jwk, { request, response: { data: genuine } })).valid
    ).toBe(true);

    // A malicious in-path intermediary swaps the consent URL in the delivered content.
    // The proof is still authentically signed (signature intact), but the bound
    // responseHash no longer matches the received content → CONTENT_BINDING_MISMATCH.
    // This is the actual anti-MITM detection — over received CONTENT, not over the
    // signed meta. A fresh verifier avoids a nonce-replay false negative.
    const swapped = [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'needs_authorization',
          authorizationUrl: 'https://attacker.example/consent',
          scopes: ['greeting:restricted'],
        }),
      },
    ];
    const v2 = makeVerifier().verifier;
    const result = await v2.verifyProof(proof, jwk, { request, response: { data: swapped } });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('CONTENT_BINDING_MISMATCH');
  });

  it('fails closed when a responseHash-bound proof is verified with only a request (no response)', async () => {
    // The needs_authorization proof binds the URL-bearing content via responseHash.
    // A caller who supplies only { request } must NOT receive valid — the request
    // is identical for a genuine and a MITM'd challenge, so the swapped URL would
    // otherwise go silently unchecked. Fail-closed: the response is required.
    const gen = new ProofGenerator(
      { did: agent.did, kid: agent.kid, privateKey: agent.privateKey, publicKey: agent.publicKey },
      crypto
    );
    const session = {
      sessionId: 'sess_failclosed',
      audience: 'did:web:server.example.com',
      nonce: `nonce-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp: Math.floor(Date.now() / 1000),
      createdAt: Math.floor(Date.now() / 1000),
      lastActivity: Math.floor(Date.now() / 1000),
      ttlMinutes: 30,
      identityState: 'anonymous' as const,
    };
    const request = { method: 'tools/call', params: { name: 'restricted_greet' } };
    const content = [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'needs_authorization',
          authorizationUrl: 'https://issuer.example/consent',
          scopes: ['greeting:restricted'],
        }),
      },
    ];
    const proof = await gen.generateProof(request, { data: content }, session, {
      outcome: 'needs_authorization',
      reason: 'requires delegation',
    });
    expect(proof.meta.responseHash).toBeDefined();

    const jwk = getJwk(agent);
    // Only the request supplied — the URL-bearing responseHash cannot be checked.
    const result = await makeVerifier().verifier.verifyProof(proof, jwk, { request });
    expect(result.valid).toBe(false);
    expect(result.errorCode).toBe('CONTENT_BINDING_MISMATCH');
  });

  it('should reject proof signed by a different key', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const wrongJwk = getJwk(otherAgent);

    const result = await verifier.verifyProof(proof, wrongJwk);

    expect(result.valid).toBe(false);
  });

  // ── Nonce Replay (real cache) ─────────────────────────────────

  it('should prevent nonce replay with real MemoryNonceCacheProvider', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);

    const first = await verifier.verifyProof(proof, jwk);
    expect(first.valid).toBe(true);

    const replay = await verifier.verifyProof(proof, jwk);
    expect(replay.valid).toBe(false);
    expect(replay.reason).toContain('replay');
  });

  it('should scope nonces per agent DID', async () => {
    const { verifier } = makeVerifier();

    const proofA = await generateProof(agent);
    const proofB = await generateProof(otherAgent);
    const jwkA = getJwk(agent);
    const jwkB = getJwk(otherAgent);

    const resultA = await verifier.verifyProof(proofA, jwkA);
    const resultB = await verifier.verifyProof(proofB, jwkB);

    expect(resultA.valid).toBe(true);
    expect(resultB.valid).toBe(true);
  });

  // ── Detached Verification ─────────────────────────────────────

  it('should verify proof via verifyProofDetached with string payload', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);
    const canonical = verifier.buildCanonicalPayload(proof.meta);

    const result = await verifier.verifyProofDetached(proof, canonical, jwk);

    expect(result.valid).toBe(true);
  });

  it('should verify proof via verifyProofDetached with Uint8Array payload', async () => {
    const { verifier } = makeVerifier();
    const proof = await generateProof(agent);
    const jwk = getJwk(agent);
    const canonical = new TextEncoder().encode(verifier.buildCanonicalPayload(proof.meta));

    const result = await verifier.verifyProofDetached(proof, canonical, jwk);

    expect(result.valid).toBe(true);
  });

  // ── Proof Structure Rejection ─────────────────────────────────

  it('should reject malformed proof structure', async () => {
    const { verifier } = makeVerifier();
    const jwk = getJwk(agent);

    const result = await verifier.verifyProof(
      { jws: 'not-valid', meta: { did: 'x' } } as any,
      jwk
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Invalid proof structure');
  });

  // ── fetchPublicKeyFromDID (real DID resolution) ───────────────

  it('should resolve a real did:key to a valid Ed25519 JWK', async () => {
    const { verifier } = makeVerifier();

    const jwk = await verifier.fetchPublicKeyFromDID(agent.did);

    expect(jwk).toBeDefined();
    expect(jwk!.kty).toBe('OKP');
    expect(jwk!.crv).toBe('Ed25519');
    expect(jwk!.x).toBeTruthy();
  });

  it('should resolve did:cheqd public keys when the fetch provider is configured for cheqd', async () => {
    const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
    const kid = `${did}#key-1`;
    const raw = extractPublicKeyFromDidKey(agent.did);
    const publicKeyJwk = publicKeyToJwk(raw!);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            didDocument: {
              id: did,
              verificationMethod: [
                {
                  id: kid,
                  type: 'Ed25519VerificationKey2020',
                  controller: did,
                  publicKeyJwk,
                },
              ],
            },
          }),
          { status: 200 },
        ),
      ),
    );
    const verifier = new ProofVerifier({
      cryptoProvider: crypto,
      clockProvider: new RealClockProvider(),
      nonceCacheProvider: new MemoryNonceCacheProvider(),
      fetchProvider: new RuntimeFetchProvider({
        cheqdResolverUrl: 'https://resolver.cheqd.net',
      }),
      timestampSkewSeconds: 300,
    });

    const jwk = await verifier.fetchPublicKeyFromDID(did, 'key-1');

    expect(jwk?.kid).toBe(kid);
    vi.unstubAllGlobals();
  });
});
