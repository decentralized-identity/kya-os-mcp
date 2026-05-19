/**
 * End-to-End Integration Test
 *
 * Exercises the full KYA-OS protocol flow with real Ed25519 cryptography:
 *   handshake → session → tool call → proof generation → proof verification
 *
 * No mocks — uses NodeCryptoProvider for real signing and verification.
 */

import { describe, it, expect } from "vitest";
import { NodeCryptoProvider } from "../utils/node-crypto-provider.js";
import { MemoryIdentityProvider } from "../../providers/memory.js";
import { MemoryNonceCacheProvider } from "../../providers/memory.js";
import { SessionManager, createHandshakeRequest } from "../../session/manager.js";
import { ProofGenerator } from "../../proof/generator.js";
import { ProofVerifier } from "../../proof/verifier.js";
import { ClockProvider, FetchProvider } from "../../providers/base.js";
import {
  createDidKeyResolver,
  resolveDidKeySync,
  extractPublicKeyFromDidKey,
  publicKeyToJwk,
} from "../../delegation/did-key-resolver.js";
import type { DIDDocument } from "../../delegation/vc-verifier.js";
import type { DetachedProof, StatusList2021Credential, DelegationRecord } from "../../types/protocol.js";

// Minimal concrete providers for the ProofVerifier
class TestClockProvider extends ClockProvider {
  now(): number {
    return Date.now();
  }
  isWithinSkew(timestampMs: number, skewSeconds: number): boolean {
    const diff = Math.abs(Date.now() - timestampMs);
    return diff <= skewSeconds * 1000;
  }
  hasExpired(expiresAt: number): boolean {
    return Date.now() > expiresAt;
  }
  calculateExpiry(ttlSeconds: number): number {
    return Date.now() + ttlSeconds * 1000;
  }
  format(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
}

class TestFetchProvider extends FetchProvider {
  private didResolver = createDidKeyResolver();

  async resolveDID(did: string): Promise<DIDDocument | null> {
    // createDidKeyResolver returns a DIDResolver { resolve(did) }
    return this.didResolver.resolve(did);
  }

  async fetchStatusList(_url: string): Promise<StatusList2021Credential | null> {
    return null;
  }

  async fetchDelegationChain(_id: string): Promise<DelegationRecord[]> {
    return [];
  }

  async fetch(_url: string, _options?: unknown): Promise<Response> {
    throw new Error("Not implemented");
  }
}

describe("KYA-OS Full Protocol Flow", () => {
  it("handshake → session → tool call → proof → verification", async () => {
    const cryptoProvider = new NodeCryptoProvider();

    // ── Step 1: Generate agent identity ──────────────────────────
    const identityProvider = new MemoryIdentityProvider(cryptoProvider);
    const agent = await identityProvider.getIdentity();

    expect(agent.did).toMatch(/^did:key:z/);
    expect(agent.kid).toMatch(/#z[\w]+$/);

    // ── Step 2: Establish session via handshake ──────────────────
    const serverDid = "did:web:test-server.example.com";
    const sessionManager = new SessionManager(cryptoProvider, {
      sessionTtlMinutes: 30,
      timestampSkewSeconds: 120,
      serverDid,
    });

    const handshakeRequest = createHandshakeRequest(serverDid);
    handshakeRequest.agentDid = agent.did;

    const handshakeResult = await sessionManager.validateHandshake(handshakeRequest);

    expect(handshakeResult.success).toBe(true);
    expect(handshakeResult.session).toBeDefined();
    expect(handshakeResult.session!.sessionId).toMatch(/^kyaos_/);
    expect(handshakeResult.session!.agentDid).toBe(agent.did);
    expect(handshakeResult.session!.audience).toBe(serverDid);

    const session = handshakeResult.session!;

    // Verify session is retrievable
    const retrievedSession = await sessionManager.getSession(session.sessionId);
    expect(retrievedSession).not.toBeNull();
    expect(retrievedSession!.sessionId).toBe(session.sessionId);

    // ── Step 3: Simulate a tool call ─────────────────────────────
    const toolRequest = {
      method: "tools/call",
      params: {
        name: "read_file",
        arguments: { path: "/etc/hosts" },
      },
    };

    const toolResponse = {
      data: {
        content: [
          {
            type: "text",
            text: "127.0.0.1 localhost\n::1 localhost",
          },
        ],
      },
    };

    // ── Step 4: Generate proof for the tool call ─────────────────
    const proofGenerator = new ProofGenerator(agent, cryptoProvider);
    const proof = await proofGenerator.generateProof(
      toolRequest,
      toolResponse,
      session,
    );

    // Verify proof structure
    expect(proof.jws).toBeDefined();
    expect(proof.jws.split(".")).toHaveLength(3); // JWS compact format
    expect(proof.meta.did).toBe(agent.did);
    expect(proof.meta.kid).toBe(agent.kid);
    expect(proof.meta.audience).toBe(serverDid);
    expect(proof.meta.sessionId).toBe(session.sessionId);
    expect(proof.meta.nonce).toBe(session.nonce);
    expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(proof.meta.ts).toBeGreaterThan(0);

    // ── Step 5: Verify proof with ProofVerifier ──────────────────
    const verifier = new ProofVerifier({
      cryptoProvider,
      clockProvider: new TestClockProvider() ,
      nonceCacheProvider: new MemoryNonceCacheProvider(),
      fetchProvider: new TestFetchProvider() ,
      timestampSkewSeconds: 300,
    });

    // Resolve the agent's public key via DID:key
    const publicKeyJwk = await verifier.fetchPublicKeyFromDID(agent.did);
    expect(publicKeyJwk).not.toBeNull();
    expect(publicKeyJwk!.kty).toBe("OKP");
    expect(publicKeyJwk!.crv).toBe("Ed25519");

    // Align kid from agent identity
    publicKeyJwk!.kid = agent.kid;

    // Verify the proof
    const verificationResult = await verifier.verifyProof(proof, publicKeyJwk!);

    expect(verificationResult.valid).toBe(true);
    expect(verificationResult.reason).toBeUndefined();

    // ── Step 6: Verify replay protection ─────────────────────────
    // Same proof should be rejected (nonce already used)
    const replayResult = await verifier.verifyProof(proof, publicKeyJwk!);

    expect(replayResult.valid).toBe(false);
    expect(replayResult.reason).toContain("Nonce already used");
  });

  it("should reject proof with tampered response hash", async () => {
    const cryptoProvider = new NodeCryptoProvider();
    const identityProvider = new MemoryIdentityProvider(cryptoProvider);
    const agent = await identityProvider.getIdentity();

    const serverDid = "did:web:test-server.example.com";
    const sessionManager = new SessionManager(cryptoProvider, {
      sessionTtlMinutes: 30,
      serverDid,
    });

    const handshakeRequest = createHandshakeRequest(serverDid);
    handshakeRequest.agentDid = agent.did;

    const { session } = await sessionManager.validateHandshake(handshakeRequest);

    const proofGenerator = new ProofGenerator(agent, cryptoProvider);
    const proof = await proofGenerator.generateProof(
      { method: "tools/call", params: { name: "echo" } },
      { data: { text: "hello" } },
      session!,
    );

    // Tamper with the response hash
    const tamperedProof: DetachedProof = {
      jws: proof.jws,
      meta: {
        ...proof.meta,
        responseHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      },
    };

    const verifier = new ProofVerifier({
      cryptoProvider,
      clockProvider: new TestClockProvider() ,
      nonceCacheProvider: new MemoryNonceCacheProvider(),
      fetchProvider: new TestFetchProvider() ,
      timestampSkewSeconds: 300,
    });

    const publicKeyJwk = await verifier.fetchPublicKeyFromDID(agent.did);
    // Align kid (see main flow test comment)
    publicKeyJwk!.kid = agent.kid;
    const result = await verifier.verifyProof(tamperedProof, publicKeyJwk!);

    // The JWS signature was computed over the original meta — the tampered meta
    // produces a different canonical payload, so signature verification fails.
    expect(result.valid).toBe(false);
  });

  it("should generate unique proofs for different tool calls in same session", async () => {
    const cryptoProvider = new NodeCryptoProvider();
    const identityProvider = new MemoryIdentityProvider(cryptoProvider);
    const agent = await identityProvider.getIdentity();

    const serverDid = "did:web:test-server.example.com";
    const sessionManager = new SessionManager(cryptoProvider, {
      sessionTtlMinutes: 30,
      serverDid,
    });

    const handshakeRequest = createHandshakeRequest(serverDid);
    handshakeRequest.agentDid = agent.did;
    const { session } = await sessionManager.validateHandshake(handshakeRequest);

    const proofGenerator = new ProofGenerator(agent, cryptoProvider);

    const proof1 = await proofGenerator.generateProof(
      { method: "tools/call", params: { name: "tool-a" } },
      { data: { result: "a" } },
      session!,
    );

    const proof2 = await proofGenerator.generateProof(
      { method: "tools/call", params: { name: "tool-b" } },
      { data: { result: "b" } },
      session!,
    );

    // Different tool calls produce different hashes
    expect(proof1.meta.requestHash).not.toBe(proof2.meta.requestHash);
    expect(proof1.meta.responseHash).not.toBe(proof2.meta.responseHash);

    // Different JWS signatures
    expect(proof1.jws).not.toBe(proof2.jws);

    // But same identity and session context
    expect(proof1.meta.did).toBe(proof2.meta.did);
    expect(proof1.meta.sessionId).toBe(proof2.meta.sessionId);
  });

  it("should verify proof using ProofGenerator.verifyProof (self-verification)", async () => {
    const cryptoProvider = new NodeCryptoProvider();
    const identityProvider = new MemoryIdentityProvider(cryptoProvider);
    const agent = await identityProvider.getIdentity();

    const serverDid = "did:web:test-server.example.com";
    const sessionManager = new SessionManager(cryptoProvider, {
      sessionTtlMinutes: 30,
      serverDid,
    });

    const handshakeRequest = createHandshakeRequest(serverDid);
    handshakeRequest.agentDid = agent.did;
    const { session } = await sessionManager.validateHandshake(handshakeRequest);

    const request = { method: "tools/call", params: { name: "echo", arguments: { msg: "hi" } } };
    const response = { data: { echo: "hi" } };

    const proofGenerator = new ProofGenerator(agent, cryptoProvider);
    const proof = await proofGenerator.generateProof(request, response, session!);

    // ProofGenerator can self-verify (uses same agent's public key)
    const selfVerified = await proofGenerator.verifyProof(proof, request, response);
    expect(selfVerified).toBe(true);

    // Tampered response should fail self-verification
    const tamperedResponse = { data: { echo: "tampered" } };
    const tamperedVerified = await proofGenerator.verifyProof(proof, request, tamperedResponse);
    expect(tamperedVerified).toBe(false);
  });

  it("handshake replay should be rejected", async () => {
    const cryptoProvider = new NodeCryptoProvider();

    const serverDid = "did:web:test-server.example.com";
    const sessionManager = new SessionManager(cryptoProvider, {
      sessionTtlMinutes: 30,
      serverDid,
    });

    const handshakeRequest = createHandshakeRequest(serverDid);
    handshakeRequest.agentDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    // First handshake succeeds
    const result1 = await sessionManager.validateHandshake(handshakeRequest);
    expect(result1.success).toBe(true);

    // Replayed handshake (same nonce) should fail
    const result2 = await sessionManager.validateHandshake(handshakeRequest);
    expect(result2.success).toBe(false);
    expect(result2.error?.message).toContain("Nonce already used");
  });

  it("DID:key resolution round-trip", async () => {
    const cryptoProvider = new NodeCryptoProvider();
    const identityProvider = new MemoryIdentityProvider(cryptoProvider);
    const agent = await identityProvider.getIdentity();

    // Resolve the DID we just generated using sync resolver
    const resolved = resolveDidKeySync(agent.did);

    expect(resolved).not.toBeNull();
    expect(resolved!.id).toBe(agent.did);
    expect(resolved!.verificationMethod).toBeDefined();
    expect(resolved!.verificationMethod!.length).toBeGreaterThan(0);

    const vm = resolved!.verificationMethod![0]!;
    expect(vm.publicKeyJwk).toBeDefined();

    const jwk = vm.publicKeyJwk as { kty: string; crv: string; x: string };
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.x).toBeDefined();

    // Also test extractPublicKeyFromDidKey + publicKeyToJwk round-trip
    const extractedBytes = extractPublicKeyFromDidKey(agent.did);
    expect(extractedBytes).not.toBeNull();
    const reconstructedJwk = publicKeyToJwk(extractedBytes!);
    expect(reconstructedJwk.x).toBe(jwk.x);

    // Sign something with the agent's private key
    const message = new TextEncoder().encode("test message");
    const signature = await cryptoProvider.sign(message, agent.privateKey);

    // Decode the public key from the JWK x parameter and verify
    const xBase64url = jwk.x;
    // Convert base64url to base64
    const xBase64 = xBase64url
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      + "=".repeat((4 - (xBase64url.length % 4)) % 4);
    const verified = await cryptoProvider.verify(message, signature, xBase64);
    expect(verified).toBe(true);
  });
});
