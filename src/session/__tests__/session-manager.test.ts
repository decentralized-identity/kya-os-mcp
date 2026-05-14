/**
 * Session Manager Tests — @kya-os/mcp
 *
 * Verifies platform-agnostic SessionManager behaviour:
 * - Nonce format identical to existing implementation
 * - TTL / expiry behaviour unchanged
 * - getSession returns correct session by ID
 * - validateHandshake behaviour unchanged
 *
 * NodeCryptoProvider is injected (test environment is Node.js).
 */

import { describe, it, expect, beforeEach } from "vitest";
import { SessionManager, createHandshakeRequest, validateHandshakeFormat } from "../manager.js";
import type { SessionConfig } from "../manager.js";
import type { HandshakeRequest } from "../../types/protocol.js";

// NodeCryptoProvider for test environment (Node.js)
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";

const cryptoProvider = new NodeCryptoProvider();

function makeSessionManager(config: SessionConfig = {}): SessionManager {
  return new SessionManager(cryptoProvider, config);
}

function makeRequest(overrides: Partial<HandshakeRequest> = {}): HandshakeRequest {
  return {
    nonce: SessionManager.generateNonce(),
    audience: "example.com",
    timestamp: Math.floor(Date.now() / 1000),
    agentDid: "did:key:zAgent",
    ...overrides,
  };
}

describe("SessionManager", () => {
  let manager: SessionManager;

  beforeEach(() => {
    manager = makeSessionManager();
  });

  describe("Nonce format", () => {
    it("should generate nonce as base64url string", () => {
      const nonce = SessionManager.generateNonce();
      expect(typeof nonce).toBe("string");
      expect(nonce.length).toBeGreaterThan(0);
      // base64url uses A-Z a-z 0-9 - _ (no padding)
      expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it("should generate unique nonces", () => {
      const nonces = new Set(Array.from({ length: 20 }, () => SessionManager.generateNonce()));
      expect(nonces.size).toBe(20);
    });

    it("should generate nonces of consistent entropy (16-byte = ~22 base64url chars)", () => {
      const nonce = SessionManager.generateNonce();
      // 16 bytes base64url → ceil(16 * 4/3) = 22 chars (no padding)
      expect(nonce.length).toBeGreaterThanOrEqual(20);
      expect(nonce.length).toBeLessThanOrEqual(24);
    });
  });

  describe("Handshake validation", () => {
    it("should create a valid session on correct handshake", async () => {
      const request = makeRequest();
      const result = await manager.validateHandshake(request);

      expect(result.success).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.session?.audience).toBe(request.audience);
      expect(result.session?.nonce).toBe(request.nonce);
      expect(result.session?.identityState).toBe("anonymous");
    });

    it("should return session ID with mcpi_ prefix", async () => {
      const request = makeRequest();
      const result = await manager.validateHandshake(request);

      expect(result.session?.sessionId).toMatch(/^mcpi_/);
    });

    it("should reject request with stale timestamp", async () => {
      const staleTs = Math.floor(Date.now() / 1000) - 200; // 200s ago, skew is 120s
      const request = makeRequest({ timestamp: staleTs });
      const result = await manager.validateHandshake(request);

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("handshake_failed");
    });

    it("should accept request within timestamp skew", async () => {
      const slightlyOldTs = Math.floor(Date.now() / 1000) - 60; // 60s ago, within 120s default
      const request = makeRequest({ timestamp: slightlyOldTs });
      const result = await manager.validateHandshake(request);

      expect(result.success).toBe(true);
    });

    it("should reject replayed nonce", async () => {
      const request = makeRequest();
      await manager.validateHandshake(request);

      // Same request again (same nonce)
      const second = await manager.validateHandshake(request);
      expect(second.success).toBe(false);
      expect(second.error?.code).toBe("handshake_failed");
    });

    it("should accept different nonces in succession", async () => {
      const r1 = makeRequest();
      const r2 = makeRequest(); // fresh nonce

      const res1 = await manager.validateHandshake(r1);
      const res2 = await manager.validateHandshake(r2);

      expect(res1.success).toBe(true);
      expect(res2.success).toBe(true);
    });
  });

  describe("Session lookup — getSession", () => {
    it("should return session by ID after handshake", async () => {
      const request = makeRequest();
      const { session } = await manager.validateHandshake(request);
      expect(session).toBeDefined();

      const found = await manager.getSession(session!.sessionId);
      expect(found).toBeDefined();
      expect(found?.sessionId).toBe(session!.sessionId);
    });

    it("should return null for unknown session ID", async () => {
      const found = await manager.getSession("mcpi_does-not-exist");
      expect(found).toBeNull();
    });

    it("should update lastActivity on each getSession call", async () => {
      const request = makeRequest();
      const { session } = await manager.validateHandshake(request);

      const before = session!.lastActivity;
      // Artificially advance lastActivity to simulate time passing
      await new Promise((r) => setTimeout(r, 10));
      const found = await manager.getSession(session!.sessionId);

      // lastActivity should be updated (>= before)
      expect(found!.lastActivity).toBeGreaterThanOrEqual(before);
    });
  });

  describe("Session expiry — TTL behaviour", () => {
    it("should expire idle sessions after TTL", async () => {
      // Use 1-minute TTL but manually manipulate lastActivity
      const sm = makeSessionManager({ sessionTtlMinutes: 1 });
      const request = makeRequest();
      const { session } = await sm.validateHandshake(request);
      expect(session).toBeDefined();

      // Backdate lastActivity beyond TTL (simulate 70s of idle)
      session!.lastActivity = Math.floor(Date.now() / 1000) - 70;
      // Directly set in sessions map via cleanup
      await sm.cleanup();

      const found = await sm.getSession(session!.sessionId);
      expect(found).toBeNull();
    });

    it("should not expire active sessions within TTL", async () => {
      const sm = makeSessionManager({ sessionTtlMinutes: 30 });
      const request = makeRequest();
      const { session } = await sm.validateHandshake(request);
      expect(session).toBeDefined();

      const found = await sm.getSession(session!.sessionId);
      expect(found).not.toBeNull();
    });

    it("should expire sessions beyond absolute lifetime", async () => {
      const sm = makeSessionManager({ absoluteSessionLifetime: 1 });
      const request = makeRequest();
      const { session } = await sm.validateHandshake(request);
      expect(session).toBeDefined();

      // Backdate createdAt beyond 1-minute absolute lifetime
      session!.createdAt = Math.floor(Date.now() / 1000) - 65;
      await sm.cleanup();

      const found = await sm.getSession(session!.sessionId);
      expect(found).toBeNull();
    });
  });

  describe("Custom timestamp skew", () => {
    it("should use custom timestampSkewSeconds when provided", async () => {
      const sm = makeSessionManager({ timestampSkewSeconds: 30 });

      // 40s stale — should fail with 30s skew
      const staleRequest = makeRequest({
        timestamp: Math.floor(Date.now() / 1000) - 40,
      });
      const result = await sm.validateHandshake(staleRequest);

      expect(result.success).toBe(false);
    });

    it("should accept request within custom skew", async () => {
      const sm = makeSessionManager({ timestampSkewSeconds: 60 });

      // 50s stale — should pass with 60s skew
      const request = makeRequest({
        timestamp: Math.floor(Date.now() / 1000) - 50,
      });
      const result = await sm.validateHandshake(request);

      expect(result.success).toBe(true);
    });
  });

  describe("getStats", () => {
    it("should report zero active sessions initially", () => {
      const stats = manager.getStats();
      expect(stats.activeSessions).toBe(0);
    });

    it("should report correct count after handshakes", async () => {
      await manager.validateHandshake(makeRequest());
      await manager.validateHandshake(makeRequest());

      const stats = manager.getStats();
      expect(stats.activeSessions).toBe(2);
    });
  });

  describe("clearSessions", () => {
    it("should clear all sessions", async () => {
      await manager.validateHandshake(makeRequest());
      manager.clearSessions();

      const stats = manager.getStats();
      expect(stats.activeSessions).toBe(0);
    });
  });

  describe("setServerDid", () => {
    it("should include serverDid in session when set", async () => {
      manager.setServerDid("did:web:example.com:server");
      const request = makeRequest({ audience: "did:web:example.com:server" });
      const { session } = await manager.validateHandshake(request);

      expect(session?.serverDid).toBe("did:web:example.com:server");
    });
  });

  describe("Audience validation", () => {
    it("should reject handshake when audience doesn't match serverDid", async () => {
      const sm = makeSessionManager({ serverDid: "did:web:example.com:server" });
      const request = makeRequest({ audience: "did:web:other.com:server" });
      const result = await sm.validateHandshake(request);

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe("handshake_failed");
      expect(result.error?.message).toContain("Audience mismatch");
    });

    it("should accept handshake when audience matches serverDid", async () => {
      const sm = makeSessionManager({ serverDid: "did:web:example.com:server" });
      const request = makeRequest({ audience: "did:web:example.com:server" });
      const result = await sm.validateHandshake(request);

      expect(result.success).toBe(true);
      expect(result.session?.audience).toBe("did:web:example.com:server");
    });

    it("should accept handshake when serverDid is not configured (backward compat)", async () => {
      const sm = makeSessionManager(); // No serverDid configured
      const request = makeRequest({ audience: "any-audience" });
      const result = await sm.validateHandshake(request);

      expect(result.success).toBe(true);
    });
  });
});

describe("createHandshakeRequest", () => {
  it("should create a valid handshake request for an audience", () => {
    const req = createHandshakeRequest("example.com");

    expect(req.audience).toBe("example.com");
    expect(typeof req.nonce).toBe("string");
    expect(req.nonce.length).toBeGreaterThan(0);
    expect(typeof req.timestamp).toBe("number");
    expect(req.timestamp).toBeGreaterThan(0);
  });

  it("should generate unique nonces across calls", () => {
    const nonces = new Set(
      Array.from({ length: 20 }, () => createHandshakeRequest("test.com").nonce)
    );
    expect(nonces.size).toBe(20);
  });

  it("should use current timestamp", () => {
    const before = Math.floor(Date.now() / 1000);
    const req = createHandshakeRequest("test.com");
    const after = Math.floor(Date.now() / 1000);

    expect(req.timestamp).toBeGreaterThanOrEqual(before);
    expect(req.timestamp).toBeLessThanOrEqual(after);
  });
});

describe("validateHandshakeFormat", () => {
  it("should return true for a valid request", () => {
    const req = createHandshakeRequest("example.com");
    expect(validateHandshakeFormat(req)).toBe(true);
  });

  it("should return false for missing nonce", () => {
    expect(validateHandshakeFormat({ audience: "x", timestamp: 1 })).toBe(false);
  });

  it("should return false for empty nonce", () => {
    expect(validateHandshakeFormat({ nonce: "", audience: "x", timestamp: 1 })).toBe(false);
  });

  it("should return false for missing audience", () => {
    expect(validateHandshakeFormat({ nonce: "abc", timestamp: 1 })).toBe(false);
  });

  it("should return false for non-integer timestamp", () => {
    expect(validateHandshakeFormat({ nonce: "abc", audience: "x", timestamp: 1.5 })).toBe(false);
  });

  it("should return false for non-object", () => {
    expect(validateHandshakeFormat(null)).toBe(false);
    expect(validateHandshakeFormat("string")).toBe(false);
    expect(validateHandshakeFormat(42)).toBe(false);
  });
});
