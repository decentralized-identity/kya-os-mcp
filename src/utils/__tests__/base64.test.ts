/**
 * Tests for Base64URL Utilities
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  base64urlDecodeToString,
  base64urlDecodeToBytes,
  base64urlEncodeFromString,
  base64urlEncodeFromBytes,
  bytesToBase64,
  base64ToBytes,
} from "../base64.js";

describe("Base64URL Utilities", () => {
  describe("base64urlEncodeFromString", () => {
    it("should encode string to base64url", () => {
      const input = "Hello, World!";
      const encoded = base64urlEncodeFromString(input);

      expect(encoded).toBeDefined();
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("should encode empty string", () => {
      const encoded = base64urlEncodeFromString("");
      expect(encoded).toBe("");
    });

    it("should encode special characters", () => {
      const input = "test@example.com";
      const encoded = base64urlEncodeFromString(input);
      const decoded = base64urlDecodeToString(encoded);

      expect(decoded).toBe(input);
    });

    it("should encode Unicode characters", () => {
      // In Node.js, Buffer.from handles Unicode correctly
      // btoa doesn't handle Unicode, but our function falls back to Buffer
      // Test with characters that work in both paths
      const input = "Hello 世界 World";

      // This should work in Node.js (Buffer path)
      const encoded = base64urlEncodeFromString(input);
      const decoded = base64urlDecodeToString(encoded);

      expect(decoded).toBe(input);
    });
  });

  describe("base64urlDecodeToString", () => {
    it("should decode base64url string", () => {
      const original = "Hello, World!";
      const encoded = base64urlEncodeFromString(original);
      const decoded = base64urlDecodeToString(encoded);

      expect(decoded).toBe(original);
    });

    it("should decode string without padding", () => {
      // Base64URL strings don't have padding
      const encoded = "SGVsbG8gV29ybGQ"; // "Hello World" in base64url
      const decoded = base64urlDecodeToString(encoded);

      expect(decoded).toBe("Hello World");
    });

    it("should decode string with padding", () => {
      // Even if padding is present, it should work
      const encoded = "SGVsbG8="; // "Hello" with padding
      const decoded = base64urlDecodeToString(encoded);

      expect(decoded).toBe("Hello");
    });

    it("should throw error for invalid base64url string", () => {
      expect(() => {
        base64urlDecodeToString("invalid-base64!!!");
      }).toThrow("Invalid base64url string");
    });

    it("should throw error for string with invalid characters", () => {
      expect(() => {
        base64urlDecodeToString("SGVsbG8@World");
      }).toThrow("Invalid base64url string");
    });

    it("should handle empty string", () => {
      const decoded = base64urlDecodeToString("");
      expect(decoded).toBe("");
    });
  });

  describe("base64urlEncodeFromBytes", () => {
    it("should encode Uint8Array to base64url", () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = base64urlEncodeFromBytes(bytes);

      expect(encoded).toBeDefined();
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("should encode empty Uint8Array", () => {
      const bytes = new Uint8Array(0);
      const encoded = base64urlEncodeFromBytes(bytes);
      expect(encoded).toBe("");
    });

    it("should round-trip encode and decode", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255]);
      const encoded = base64urlEncodeFromBytes(original);
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(original);
    });
  });

  describe("base64urlDecodeToBytes", () => {
    it("should decode base64url to Uint8Array", () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]);
      const encoded = base64urlEncodeFromBytes(original);
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(original);
    });

    it("should decode without padding", () => {
      const encoded = "SGVsbG8"; // "Hello" without padding
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it("should throw error for invalid base64url", () => {
      expect(() => {
        base64urlDecodeToBytes("invalid!!!");
      }).toThrow(); // atob throws "Invalid character"
    });

    it("should handle empty string", () => {
      const decoded = base64urlDecodeToBytes("");
      expect(decoded).toEqual(new Uint8Array(0));
    });
  });

  describe("bytesToBase64", () => {
    it("should convert bytes to standard base64", () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]);
      const base64 = bytesToBase64(bytes);

      expect(base64).toBeDefined();
      expect(base64).toBe("SGVsbG8="); // Standard base64 includes padding
    });

    it("should handle empty bytes", () => {
      const bytes = new Uint8Array(0);
      const base64 = bytesToBase64(bytes);
      expect(base64).toBe("");
    });

    it("should include padding when needed", () => {
      const bytes = new Uint8Array([72]); // Single byte
      const base64 = bytesToBase64(bytes);
      expect(base64).toContain("="); // Should have padding
    });
  });

  describe("base64ToBytes", () => {
    it("should convert standard base64 to bytes", () => {
      const base64 = "SGVsbG8="; // "Hello" in standard base64
      const bytes = base64ToBytes(base64);

      expect(bytes).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it("should handle base64 without padding", () => {
      const base64 = "SGVsbG8"; // Without padding
      const bytes = base64ToBytes(base64);

      expect(bytes).toBeDefined();
    });

    it("should handle empty string", () => {
      const bytes = base64ToBytes("");
      expect(bytes).toEqual(new Uint8Array(0));
    });

    it("should round-trip with bytesToBase64", () => {
      const original = new Uint8Array([1, 2, 3, 255, 0]);
      const base64 = bytesToBase64(original);
      const decoded = base64ToBytes(base64);

      expect(decoded).toEqual(original);
    });
  });

  describe("Edge Cases", () => {
    it("should handle large byte arrays", () => {
      const largeArray = new Uint8Array(1000);
      for (let i = 0; i < 1000; i++) {
        largeArray[i] = i % 256;
      }

      const encoded = base64urlEncodeFromBytes(largeArray);
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(largeArray);
    });

    it("should handle bytes with all zeros", () => {
      const zeros = new Uint8Array([0, 0, 0, 0]);
      const encoded = base64urlEncodeFromBytes(zeros);
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(zeros);
    });

    it("should handle bytes with all 255s", () => {
      const maxBytes = new Uint8Array([255, 255, 255, 255]);
      const encoded = base64urlEncodeFromBytes(maxBytes);
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(maxBytes);
    });

    it("should handle single byte", () => {
      const single = new Uint8Array([42]);
      const encoded = base64urlEncodeFromBytes(single);
      const decoded = base64urlDecodeToBytes(encoded);

      expect(decoded).toEqual(single);
    });
  });

  describe("runtime fallbacks", () => {
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("round-trips through the Buffer fallbacks when atob/btoa are absent", () => {
      vi.stubGlobal("atob", undefined);
      vi.stubGlobal("btoa", undefined);
      expect(base64urlDecodeToBytes("AQID")).toEqual(new Uint8Array([1, 2, 3]));
      expect(base64urlEncodeFromBytes(new Uint8Array([1, 2, 3]))).toBe("AQID");
      expect(bytesToBase64(new Uint8Array([1, 2, 3]))).toBe("AQID");
      expect(base64ToBytes("AQID")).toEqual(new Uint8Array([1, 2, 3]));
      expect(base64urlDecodeToString(base64urlEncodeFromString("hello 世界")))
        .toBe("hello 世界");
    });

    it("rejects base64url input containing invalid characters", () => {
      expect(() => base64urlDecodeToString("!!!")).toThrow(/invalid characters/i);
    });

    it("round-trips through the atob/btoa paths when Buffer is absent", () => {
      vi.stubGlobal("Buffer", undefined);
      expect(base64urlDecodeToString("aGVsbG8")).toBe("hello");
      expect(base64urlEncodeFromString("hello")).toBe("aGVsbG8");
      expect(base64urlEncodeFromBytes(new Uint8Array([1, 2, 3]))).toBe("AQID");
      expect(bytesToBase64(new Uint8Array([1, 2, 3]))).toBe("AQID");
    });

    it("fails closed when no base64 codec is available at all", () => {
      vi.stubGlobal("Buffer", undefined);
      vi.stubGlobal("atob", undefined);
      vi.stubGlobal("btoa", undefined);
      expect(() => base64urlDecodeToString("aGVsbG8")).toThrow(/Neither Buffer nor atob/);
      expect(() => base64urlEncodeFromString("x")).toThrow(/Neither Buffer nor btoa/);
    });
  });
});
