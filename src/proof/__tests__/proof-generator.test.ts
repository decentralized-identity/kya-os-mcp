/**
 * Proof Generator Tests — @kya-os/mcp
 *
 * Ported from packages/mcp-i-core/src/proof/__tests__/proof-generator.test.ts.
 * All test logic is identical — only import paths change.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { canonicalize } from "json-canonicalize";
import {
  ProofGenerator,
  createProofResponse,
  extractCanonicalData,
  type ToolRequest,
  type ToolResponse,
} from "../generator.js";
import type { ProofAgentIdentity } from "../generator.js";
import type { SessionContext } from "../../types/protocol.js";

// NodeCryptoProvider for test environment (Node.js)
import { NodeCryptoProvider } from "../../__tests__/utils/node-crypto-provider.js";

const cryptoProvider = new NodeCryptoProvider();

async function makeIdentity(): Promise<ProofAgentIdentity> {
  const keyPair = await cryptoProvider.generateKeyPair();
  return {
    did: "did:web:example.com:agents:test-agent",
    kid: "key-test-123",
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

function makeSession(): SessionContext {
  return {
    sessionId: "sess_test_123",
    audience: "example.com",
    nonce: "test-nonce-456",
    timestamp: Math.floor(Date.now() / 1000),
    createdAt: Math.floor(Date.now() / 1000),
    lastActivity: Math.floor(Date.now() / 1000),
    ttlMinutes: 30,
    identityState: "anonymous",
  };
}

describe("ProofGenerator", () => {
  let proofGenerator: ProofGenerator;
  let mockIdentity: ProofAgentIdentity;
  let mockSession: SessionContext;

  beforeEach(async () => {
    mockIdentity = await makeIdentity();
    mockSession = makeSession();
    proofGenerator = new ProofGenerator(mockIdentity, cryptoProvider);
  });

  describe("Canonical Hash Generation", () => {
    it("should generate consistent hashes for same request/response", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof1 = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );
      const proof2 = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );

      expect(proof1.meta.requestHash).toBe(proof2.meta.requestHash);
      expect(proof1.meta.responseHash).toBe(proof2.meta.responseHash);
    });

    it("should generate different hashes for different requests", async () => {
      const request1: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const request2: ToolRequest = {
        method: "test-tool",
        params: { input: "goodbye" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof1 = await proofGenerator.generateProof(
        request1,
        response,
        mockSession
      );
      const proof2 = await proofGenerator.generateProof(
        request2,
        response,
        mockSession
      );

      expect(proof1.meta.requestHash).not.toBe(proof2.meta.requestHash);
      expect(proof1.meta.responseHash).toBe(proof2.meta.responseHash);
    });

    it("should generate different hashes for different responses", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response1: ToolResponse = { data: { output: "world" } };
      const response2: ToolResponse = { data: { output: "universe" } };

      const proof1 = await proofGenerator.generateProof(
        request,
        response1,
        mockSession
      );
      const proof2 = await proofGenerator.generateProof(
        request,
        response2,
        mockSession
      );

      expect(proof1.meta.requestHash).toBe(proof2.meta.requestHash);
      expect(proof1.meta.responseHash).not.toBe(proof2.meta.responseHash);
    });

    it("should generate SHA-256 hashes with correct format", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );

      expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it("should handle requests without params", async () => {
      const request: ToolRequest = { method: "simple-tool" };
      const response: ToolResponse = { data: { result: "success" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );

      expect(proof.meta.requestHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(proof.meta.responseHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });
  });

  describe("Proof Metadata", () => {
    it("should include all required metadata fields", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );

      expect(proof.meta.did).toBe(mockIdentity.did);
      expect(proof.meta.kid).toBe(mockIdentity.kid);
      expect(proof.meta.ts).toBeTypeOf("number");
      expect(proof.meta.nonce).toBe(mockSession.nonce);
      expect(proof.meta.audience).toBe(mockSession.audience);
      expect(proof.meta.sessionId).toBe(mockSession.sessionId);
      expect(proof.meta.requestHash).toBeTruthy();
      expect(proof.meta.responseHash).toBeTruthy();
    });

    it("should include optional fields when provided", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession,
        {
          scopeId: "orders.create",
          delegationRef: "delegation-ref-123",
          clientDid: "did:key:zClient",
        }
      );

      expect(proof.meta.scopeId).toBe("orders.create");
      expect(proof.meta.delegationRef).toBe("delegation-ref-123");
      expect(proof.meta.clientDid).toBe("did:key:zClient");
    });
  });

  describe("JWS Generation", () => {
    it("should generate compact JWS in correct format", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );

      const jwsParts = proof.jws.split(".");
      expect(jwsParts).toHaveLength(3);
      expect(jwsParts[0]).toBeTruthy();
      expect(jwsParts[1]).toBeTruthy();
      expect(jwsParts[2]).toBeTruthy();
    });

    it("should use EdDSA algorithm", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );

      const [headerB64] = proof.jws.split(".");
      const header = JSON.parse(
        Buffer.from(headerB64, "base64url").toString()
      ) as { alg: string; kid: string };

      expect(header.alg).toBe("EdDSA");
      expect(header.kid).toBe(mockIdentity.kid);
    });

    it("should encode clientDid in the JWS payload when provided", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession,
        { clientDid: "did:key:zClientPayload" }
      );

      const payload = JSON.parse(
        Buffer.from(proof.jws.split(".")[1], "base64url").toString()
      ) as { clientDid: string };

      expect(payload.clientDid).toBe("did:key:zClientPayload");
    });
  });

  describe("Proof Verification", () => {
    it("should verify valid proof structure", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request,
        response,
        mockSession
      );
      const isValid = await proofGenerator.verifyProof(
        proof,
        request,
        response
      );

      expect(isValid).toBe(true);
    });

    it("should reject proof with mismatched request", async () => {
      const request1: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const request2: ToolRequest = {
        method: "test-tool",
        params: { input: "goodbye" },
      };
      const response: ToolResponse = { data: { output: "world" } };

      const proof = await proofGenerator.generateProof(
        request1,
        response,
        mockSession
      );
      const isValid = await proofGenerator.verifyProof(
        proof,
        request2,
        response
      );

      expect(isValid).toBe(false);
    });

    it("should reject proof with mismatched response", async () => {
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const response1: ToolResponse = { data: { output: "world" } };
      const response2: ToolResponse = { data: { output: "universe" } };

      const proof = await proofGenerator.generateProof(
        request,
        response1,
        mockSession
      );
      const isValid = await proofGenerator.verifyProof(
        proof,
        request,
        response2
      );

      expect(isValid).toBe(false);
    });
  });

  describe("JSON Canonicalization", () => {
    it("should canonicalize objects with sorted keys", () => {
      const canonical = extractCanonicalData(
        { method: "test", params: { b: 2, a: 1 } },
        { data: { z: 26, a: 1 } }
      );

      expect(canonical.request).toEqual({
        method: "test",
        params: { b: 2, a: 1 },
      });
      expect(canonical.response).toEqual({ z: 26, a: 1 });
    });
  });
});

describe("Utility Functions", () => {
  describe("createProofResponse", () => {
    it("should create response with proof metadata", async () => {
      const mockIdentity = await makeIdentity();
      const mockSession = makeSession();
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const data = { output: "world" };

      const response = await createProofResponse(
        request,
        data,
        mockIdentity,
        mockSession,
        cryptoProvider
      );

      expect(response.data).toEqual(data);
      expect(response.meta?.proof).toBeDefined();
      expect(response.meta?.proof?.meta.did).toBe(mockIdentity.did);
      expect(response.meta?.proof?.jws).toBeTruthy();
    });

    it("should include optional proof options", async () => {
      const mockIdentity = await makeIdentity();
      const mockSession = makeSession();
      const request: ToolRequest = {
        method: "test-tool",
        params: { input: "hello" },
      };
      const data = { output: "world" };

      const response = await createProofResponse(
        request,
        data,
        mockIdentity,
        mockSession,
        cryptoProvider,
        { scopeId: "orders.create" }
      );

      expect(response.meta?.proof?.meta.scopeId).toBe("orders.create");
    });
  });
});

describe("RFC 8785 JCS Compliance", () => {
  describe("Key Ordering", () => {
    it("should sort object keys lexicographically", () => {
      const obj = { z: 26, a: 1, m: 13 };
      const result = canonicalize(obj);
      expect(result).toBe('{"a":1,"m":13,"z":26}');
    });
  });

  describe("Determinism", () => {
    it("should produce identical output for same input", () => {
      const obj = {
        method: "test",
        params: { nested: { z: 3, a: 1 }, array: [1, 2, 3] },
        timestamp: 1234567890,
      };
      const result1 = canonicalize(obj);
      const result2 = canonicalize(obj);
      expect(result1).toBe(result2);
    });

    it("should produce identical output regardless of property order", () => {
      const obj1 = { a: 1, b: 2, c: 3 };
      const obj2 = { c: 3, a: 1, b: 2 };
      const obj3 = { b: 2, c: 3, a: 1 };

      expect(canonicalize(obj1)).toBe(canonicalize(obj2));
      expect(canonicalize(obj2)).toBe(canonicalize(obj3));
    });
  });
});

describe("Cross-Package Verification — key ordering and Unicode", () => {
  let mockIdentity: ProofAgentIdentity;
  let mockSession: SessionContext;

  beforeEach(async () => {
    mockIdentity = await makeIdentity();
    mockSession = makeSession();
  });

  it("should produce identical hashes for key-reordered requests", async () => {
    const pg = new ProofGenerator(mockIdentity, cryptoProvider);
    const response: ToolResponse = { data: { output: "world" } };

    const proof1 = await pg.generateProof(
      { method: "test-tool", params: { z: 26, a: 1, m: 13 } },
      response,
      mockSession
    );
    const proof2 = await pg.generateProof(
      { method: "test-tool", params: { a: 1, m: 13, z: 26 } },
      response,
      mockSession
    );

    expect(proof1.meta.requestHash).toBe(proof2.meta.requestHash);
  });

  it("should handle Unicode and special characters consistently", async () => {
    const pg = new ProofGenerator(mockIdentity, cryptoProvider);
    const request: ToolRequest = {
      method: "test-tool",
      params: { emoji: "🎉", text: "Hello 世界", special: "\u0000\u001f" },
    };
    const response: ToolResponse = { data: { output: "🌍" } };

    const proof1 = await pg.generateProof(request, response, mockSession);
    const proof2 = await pg.generateProof(request, response, mockSession);

    expect(proof1.meta.requestHash).toBe(proof2.meta.requestHash);
    expect(proof1.meta.responseHash).toBe(proof2.meta.responseHash);
  });
});
