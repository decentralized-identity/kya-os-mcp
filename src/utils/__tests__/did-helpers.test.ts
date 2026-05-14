/**
 * Tests for DID Helper Utilities
 *
 * @package @kya-os/mcp/utils/__tests__
 */

import { describe, it, expect } from "vitest";
import {
  isValidDid,
  getDidMethod,
  normalizeDid,
  compareDids,
  getServerDid,
  generateDidKeyFromBytes,
  generateDidKeyFromBase64,
} from "../did-helpers";

describe("DID Helpers", () => {
  describe("isValidDid", () => {
    it("should return true for valid DIDs", () => {
      expect(isValidDid("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")).toBe(true);
      expect(isValidDid("did:web:example.com")).toBe(true);
      expect(isValidDid("did:web:example.com:path")).toBe(true);
    });

    it("should return false for invalid DIDs", () => {
      expect(isValidDid("not-a-did")).toBe(false);
      expect(isValidDid("")).toBe(false);
      expect(isValidDid("did")).toBe(false);
      expect(isValidDid("key:z6Mk...")).toBe(false);
    });
  });

  describe("getDidMethod", () => {
    it("should extract DID method correctly", () => {
      expect(getDidMethod("did:key:z6Mk...")).toBe("key");
      expect(getDidMethod("did:web:example.com")).toBe("web");
      expect(getDidMethod("did:ion:...")).toBe("ion");
    });

    it("should return null for invalid DIDs", () => {
      expect(getDidMethod("not-a-did")).toBeNull();
      expect(getDidMethod("")).toBeNull();
      expect(getDidMethod("did")).toBeNull();
    });
  });

  describe("normalizeDid", () => {
    it("should trim whitespace", () => {
      expect(normalizeDid("  did:key:z6Mk...  ")).toBe("did:key:z6Mk...");
      expect(normalizeDid("did:key:z6Mk...")).toBe("did:key:z6Mk...");
    });
  });

  describe("compareDids", () => {
    it("should compare DIDs correctly", () => {
      expect(compareDids("did:key:z6Mk...", "did:key:z6Mk...")).toBe(true);
      expect(compareDids("did:key:z6Mk...", "did:web:example.com")).toBe(false);
    });

    it("should normalize before comparing", () => {
      expect(compareDids("  did:key:z6Mk...  ", "did:key:z6Mk...")).toBe(true);
    });
  });

  describe("getServerDid", () => {
    it("should return serverDid when present", () => {
      const config = {
        identity: {
          serverDid: "did:web:server.com",
        },
      };
      expect(getServerDid(config)).toBe("did:web:server.com");
    });

    it("should return agentDid when serverDid not present (backward compatibility)", () => {
      const config = {
        identity: {
          agentDid: "did:web:old-server.com",
        },
      };
      expect(getServerDid(config)).toBe("did:web:old-server.com");
    });

    it("should prefer serverDid over agentDid", () => {
      const config = {
        identity: {
          serverDid: "did:web:new-server.com",
          agentDid: "did:web:old-server.com",
        },
      };
      expect(getServerDid(config)).toBe("did:web:new-server.com");
    });

    it("should throw error when neither serverDid nor agentDid present", () => {
      const config = {
        identity: {},
      };
      expect(() => getServerDid(config)).toThrow("Server DID not configured");
    });
  });

  describe("generateDidKeyFromBytes", () => {
    it("should generate valid did:key from 32-byte Ed25519 public key", () => {
      // Use a known test key (32 bytes)
      const publicKeyBytes = new Uint8Array(32).fill(0xab);
      const did = generateDidKeyFromBytes(publicKeyBytes);

      expect(did).toMatch(/^did:key:z6Mk/);
      expect(isValidDid(did)).toBe(true);
      expect(getDidMethod(did)).toBe("key");
    });

    it("should generate consistent did:key for same input", () => {
      const publicKeyBytes = new Uint8Array(32).fill(0x42);
      const did1 = generateDidKeyFromBytes(publicKeyBytes);
      const did2 = generateDidKeyFromBytes(publicKeyBytes);

      expect(did1).toBe(did2);
    });

    it("should generate different did:key for different inputs", () => {
      const key1 = new Uint8Array(32).fill(0x11);
      const key2 = new Uint8Array(32).fill(0x22);

      const did1 = generateDidKeyFromBytes(key1);
      const did2 = generateDidKeyFromBytes(key2);

      expect(did1).not.toBe(did2);
    });
  });

  describe("generateDidKeyFromBase64", () => {
    it("should generate valid did:key from base64-encoded public key", () => {
      // Base64 encode a 32-byte key
      const publicKeyBytes = new Uint8Array(32).fill(0xcd);
      const publicKeyBase64 = btoa(String.fromCharCode(...publicKeyBytes));

      const did = generateDidKeyFromBase64(publicKeyBase64);

      expect(did).toMatch(/^did:key:z6Mk/);
      expect(isValidDid(did)).toBe(true);
    });

    it("should produce same result as generateDidKeyFromBytes", () => {
      const publicKeyBytes = new Uint8Array(32).fill(0xef);
      const publicKeyBase64 = btoa(String.fromCharCode(...publicKeyBytes));

      const didFromBytes = generateDidKeyFromBytes(publicKeyBytes);
      const didFromBase64 = generateDidKeyFromBase64(publicKeyBase64);

      expect(didFromBytes).toBe(didFromBase64);
    });
  });
});

