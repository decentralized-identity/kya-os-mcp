import { describe, it, expect, beforeEach } from "vitest";
import {
  BitstringManager,
  isIndexSet,
  type CompressionFunction,
  type DecompressionFunction,
} from "../bitstring.js";

// Mock compression functions for testing
class MockCompressor implements CompressionFunction {
  async compress(data: Uint8Array): Promise<Uint8Array> {
    // Simple mock: just return data as-is (no actual compression)
    return data;
  }
}

class MockDecompressor implements DecompressionFunction {
  async decompress(data: Uint8Array): Promise<Uint8Array> {
    // Simple mock: just return data as-is
    return data;
  }
}

describe("BitstringManager", () => {
  let compressor: CompressionFunction;
  let decompressor: DecompressionFunction;

  beforeEach(() => {
    compressor = new MockCompressor();
    decompressor = new MockDecompressor();
  });

  describe("constructor", () => {
    it("should create manager with specified size", () => {
      const manager = new BitstringManager(16, compressor, decompressor);
      expect(manager.getSize()).toBe(16);
    });

    it("should allocate correct number of bytes", () => {
      const manager = new BitstringManager(16, compressor, decompressor);
      // 16 bits = 2 bytes
      expect(manager.getRawBits().length).toBe(2);
    });

    it("should handle size that requires extra byte", () => {
      const manager = new BitstringManager(17, compressor, decompressor);
      // 17 bits = 3 bytes (ceil(17/8) = 3)
      expect(manager.getRawBits().length).toBe(3);
    });
  });

  describe("setBit", () => {
    it("should set bit to 1", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      expect(manager.getBit(0)).toBe(true);
    });

    it("should set bit to 0", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(0, false);
      expect(manager.getBit(0)).toBe(false);
    });

    it("should set multiple bits independently", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);
      manager.setBit(4, true);

      expect(manager.getBit(0)).toBe(true);
      expect(manager.getBit(1)).toBe(false);
      expect(manager.getBit(2)).toBe(true);
      expect(manager.getBit(3)).toBe(false);
      expect(manager.getBit(4)).toBe(true);
    });

    it("should handle bits across byte boundaries", () => {
      const manager = new BitstringManager(16, compressor, decompressor);
      manager.setBit(7, true); // Last bit of first byte
      manager.setBit(8, true); // First bit of second byte

      expect(manager.getBit(7)).toBe(true);
      expect(manager.getBit(8)).toBe(true);
    });

    it("should throw error for negative index", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.setBit(-1, true)).toThrow("out of range");
    });

    it("should throw error for index >= size", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.setBit(8, true)).toThrow("out of range");
    });
  });

  describe("getBit", () => {
    it("should return false for unset bits", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(manager.getBit(0)).toBe(false);
    });

    it("should return true for set bits", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(3, true);
      expect(manager.getBit(3)).toBe(true);
    });

    it("should throw error for negative index", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.getBit(-1)).toThrow("out of range");
    });

    it("should throw error for index >= size", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(() => manager.getBit(8)).toThrow("out of range");
    });
  });

  // P0.2: a NaN / Infinity / fractional index MUST fail closed at every entry point. A NaN slips
  // past a bare `index < 0 || index >= size` guard (both comparisons are false for NaN), so on a
  // REVOCATION read that would resolve from garbage instead of denying.
  describe("non-integer / NaN index fails closed", () => {
    const rejected = [NaN, Infinity, -Infinity, 1.5, -1, 8, 2 ** 53];
    it.each(rejected)("setBit(%s) throws (fail-closed)", (index) => {
      const m = new BitstringManager(8, compressor, decompressor);
      expect(() => m.setBit(index, true)).toThrow("out of range");
    });
    it.each(rejected)("getBit(%s) throws (fail-closed)", (index) => {
      const m = new BitstringManager(8, compressor, decompressor);
      expect(() => m.getBit(index)).toThrow("out of range");
    });
    it("isIndexSet rejects NaN / Infinity / fractional / out-of-range", async () => {
      const m = new BitstringManager(8, compressor, decompressor);
      m.setBit(3, true);
      const encoded = await m.encode();
      for (const index of [NaN, Infinity, -Infinity, 1.5, -1, 999]) {
        await expect(isIndexSet(encoded, index, decompressor)).rejects.toThrow();
      }
    });
    it("treats -0 as the valid integer index 0 (Number.isInteger(-0) === true), not a throw", () => {
      const m = new BitstringManager(8, compressor, decompressor);
      expect(m.getBit(-0)).toBe(false); // index 0, unset
      expect(() => m.setBit(-0, true)).not.toThrow();
      expect(m.getBit(0)).toBe(true);
    });
  });

  describe("getSetBits", () => {
    it("should return empty array when no bits are set", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      expect(manager.getSetBits()).toEqual([]);
    });

    it("should return array of set bit indices", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);
      manager.setBit(5, true);

      const setBits = manager.getSetBits();
      expect(setBits).toContain(0);
      expect(setBits).toContain(2);
      expect(setBits).toContain(5);
      expect(setBits.length).toBe(3);
    });

    it("should return indices in order", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(5, true);
      manager.setBit(1, true);
      manager.setBit(3, true);

      const setBits = manager.getSetBits();
      expect(setBits).toEqual([1, 3, 5]);
    });
  });

  describe("encode", () => {
    it("should encode bitstring to base64url", async () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);

      const encoded = await manager.encode();
      expect(typeof encoded).toBe("string");
      expect(encoded.length).toBeGreaterThan(0);
      // Base64url should not contain +, /, or =
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
    });

    it("should produce consistent encoding", async () => {
      const manager1 = new BitstringManager(8, compressor, decompressor);
      manager1.setBit(0, true);
      manager1.setBit(2, true);

      const manager2 = new BitstringManager(8, compressor, decompressor);
      manager2.setBit(0, true);
      manager2.setBit(2, true);

      const encoded1 = await manager1.encode();
      const encoded2 = await manager2.encode();
      expect(encoded1).toBe(encoded2);
    });
  });

  describe("decode", () => {
    it("should decode encoded bitstring", async () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      manager.setBit(0, true);
      manager.setBit(2, true);
      manager.setBit(5, true);

      const encoded = await manager.encode();
      const decoded = await BitstringManager.decode(
        encoded,
        compressor,
        decompressor
      );

      expect(decoded.getSize()).toBe(8);
      expect(decoded.getBit(0)).toBe(true);
      expect(decoded.getBit(2)).toBe(true);
      expect(decoded.getBit(5)).toBe(true);
      expect(decoded.getBit(1)).toBe(false);
    });

    it("should handle round-trip encoding/decoding", async () => {
      const original = new BitstringManager(16, compressor, decompressor);
      original.setBit(0, true);
      original.setBit(7, true);
      original.setBit(8, true);
      original.setBit(15, true);

      const encoded = await original.encode();
      const decoded = await BitstringManager.decode(
        encoded,
        compressor,
        decompressor
      );

      expect(decoded.getSize()).toBe(original.getSize());
      for (let i = 0; i < original.getSize(); i++) {
        expect(decoded.getBit(i)).toBe(original.getBit(i));
      }
    });
  });

  describe("fromSetBits", () => {
    it("should create manager from set bit indices", () => {
      const manager = BitstringManager.fromSetBits(
        8,
        [0, 2, 5],
        compressor,
        decompressor
      );

      expect(manager.getSize()).toBe(8);
      expect(manager.getBit(0)).toBe(true);
      expect(manager.getBit(2)).toBe(true);
      expect(manager.getBit(5)).toBe(true);
      expect(manager.getBit(1)).toBe(false);
    });

    it("should handle empty set bits array", () => {
      const manager = BitstringManager.fromSetBits(
        8,
        [],
        compressor,
        decompressor
      );

      expect(manager.getSize()).toBe(8);
      expect(manager.getSetBits()).toEqual([]);
    });

    it("should handle bits across byte boundaries", () => {
      const manager = BitstringManager.fromSetBits(
        16,
        [7, 8, 15],
        compressor,
        decompressor
      );

      expect(manager.getBit(7)).toBe(true);
      expect(manager.getBit(8)).toBe(true);
      expect(manager.getBit(15)).toBe(true);
    });
  });

  describe("getRawBits", () => {
    it("should return raw byte array", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      const raw = manager.getRawBits();

      expect(raw).toBeInstanceOf(Uint8Array);
      expect(raw.length).toBe(1); // 8 bits = 1 byte
    });

    it("should return reference to internal bits array", () => {
      const manager = new BitstringManager(8, compressor, decompressor);
      const raw1 = manager.getRawBits();
      manager.setBit(0, true);
      const raw2 = manager.getRawBits();

      // getRawBits returns a reference, so raw1 and raw2 are the same array
      expect(raw1).toBe(raw2);
      // Setting a bit should change the raw bits (same reference)
      expect(raw1[0]).toBe(raw2[0]);
      expect(raw1[0]).not.toBe(0); // Bit 0 is now set
    });
  });

  describe("getSize", () => {
    it("should return correct size", () => {
      const manager = new BitstringManager(32, compressor, decompressor);
      expect(manager.getSize()).toBe(32);
    });
  });
});

describe("isIndexSet", () => {
  let decompressor: DecompressionFunction;

  beforeEach(() => {
    decompressor = new MockDecompressor();
  });

  it("should return true for set bit", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(3, true);
    const encoded = await manager.encode();

    const result = await isIndexSet(encoded, 3, decompressor);
    expect(result).toBe(true);
  });

  it("should return false for unset bit", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(0, true);
    manager.setBit(2, true);
    const encoded = await manager.encode();

    const result = await isIndexSet(encoded, 1, decompressor);
    expect(result).toBe(false);
  });

  it("throws (fail-closed) for an out-of-range index", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    const encoded = await manager.encode();

    // Fail-CLOSED: an out-of-range index cannot be proven clear, so it must throw rather than
    // silently read as "not set" (the prior fail-open let an out-of-range index verify as live).
    await expect(isIndexSet(encoded, 100, decompressor)).rejects.toThrow("out of range");
  });

  it("should handle multiple bits", async () => {
    const manager = new BitstringManager(16, new MockCompressor(), decompressor);
    manager.setBit(0, true);
    manager.setBit(7, true);
    manager.setBit(8, true);
    manager.setBit(15, true);
    const encoded = await manager.encode();

    expect(await isIndexSet(encoded, 0, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 7, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 8, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 15, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 1, decompressor)).toBe(false);
  });
});

describe("W3C multibase encodedList (u prefix)", () => {
  const decompressor = new MockDecompressor();

  it("encode() emits the leading 'u' multibase prefix", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(3, true);
    expect((await manager.encode())[0]).toBe("u");
  });

  it("isIndexSet reads a multibase-prefixed list (the W3C wire form that previously threw)", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(3, true);
    const encoded = await manager.encode(); // now 'u'-prefixed
    expect(encoded[0]).toBe("u");
    expect(await isIndexSet(encoded, 3, decompressor)).toBe(true);
    expect(await isIndexSet(encoded, 2, decompressor)).toBe(false);
  });

  it("isIndexSet still reads an unprefixed list (back-compat, no double-strip)", async () => {
    const manager = new BitstringManager(8, new MockCompressor(), decompressor);
    manager.setBit(3, true);
    const unprefixed = (await manager.encode()).slice(1); // drop the multibase 'u'
    expect(await isIndexSet(unprefixed, 3, decompressor)).toBe(true);
  });

  it("isIndexSet fails closed against a decompression bomb (post-inflation cap)", async () => {
    // The standalone reader shares BitstringManager.decode's 16 MiB cap: an over-inflating
    // decompressor must throw, not allocate the bomb and read a bit from it.
    const bomb: DecompressionFunction = { decompress: async () => new Uint8Array(17 * 1024 * 1024) };
    await expect(isIndexSet("uAAAA", 0, bomb)).rejects.toThrow(/too large/);
  });
});

