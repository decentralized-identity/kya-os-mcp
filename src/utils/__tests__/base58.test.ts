/**
 * Tests for Base58 Utilities
 */

import { describe, it, expect } from "vitest";
import {
  base58Encode,
  base58Decode,
  isValidBase58,
  MAX_BASE58_DECODE_LENGTH,
} from "../base58.js";
import { extractPublicKeyFromDidKey } from "../../delegation/did-key-resolver.js";
import { verificationMethodJwk } from "../../delegation/verification-method-key.js";
import { DelegationCredentialIssuer } from "../../delegation/vc-issuer.js";
import { createKyaOsMiddleware } from "../../middleware/with-kya-os.js";
import { NodeCryptoProvider } from "../../providers/node-crypto.js";
import { base64urlEncodeFromBytes } from "../base64.js";
import { generateDidKeyFromBase64, generateDidKeyFromBytes } from "../did-helpers.js";

describe("Base58 Utilities", () => {
  describe("base58Encode", () => {
    it("should encode bytes to Base58", () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = base58Encode(bytes);

      expect(encoded).toBeDefined();
      expect(typeof encoded).toBe("string");
      expect(encoded.length).toBeGreaterThan(0);
    });

    it("should encode empty bytes to empty string", () => {
      const bytes = new Uint8Array(0);
      const encoded = base58Encode(bytes);

      expect(encoded).toBe("");
    });

    it("should encode single byte", () => {
      const bytes = new Uint8Array([42]);
      const encoded = base58Encode(bytes);

      expect(encoded).toBeDefined();
      expect(encoded.length).toBeGreaterThan(0);
    });

    it("should encode bytes with leading zeros", () => {
      const bytes = new Uint8Array([0, 0, 1, 2, 3]);
      const encoded = base58Encode(bytes);

      // Leading zeros should be encoded as '1'
      expect(encoded.startsWith("1")).toBe(true);
    });

    it("should encode all zero bytes", () => {
      const bytes = new Uint8Array([0, 0, 0]);
      const encoded = base58Encode(bytes);

      expect(encoded).toBeDefined();
      // All zeros should result in multiple '1' characters
      expect(encoded.length).toBeGreaterThan(0);
    });

    it("should produce deterministic output", () => {
      const bytes = new Uint8Array([1, 2, 3, 4, 5]);
      const encoded1 = base58Encode(bytes);
      const encoded2 = base58Encode(bytes);

      expect(encoded1).toBe(encoded2);
    });
  });

  describe("base58Decode", () => {
    it("should decode Base58 to bytes", () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]);
      const encoded = base58Encode(original);
      const decoded = base58Decode(encoded);

      expect(decoded).toEqual(original);
    });

    it("should decode empty string to empty bytes", () => {
      const decoded = base58Decode("");

      expect(decoded).toEqual(new Uint8Array(0));
    });

    it("should decode string with leading '1' characters", () => {
      // Leading '1' characters represent leading zeros
      const encoded = "11ABC";
      const decoded = base58Decode(encoded);

      expect(decoded).toBeDefined();
      expect(decoded[0]).toBe(0);
      expect(decoded[1]).toBe(0);
    });

    it("should round-trip encode and decode", () => {
      const testCases = [
        new Uint8Array([1, 2, 3]),
        new Uint8Array([255, 255, 255]),
        new Uint8Array([0, 1, 2]),
        new Uint8Array([128, 64, 32]),
      ];

      for (const bytes of testCases) {
        const encoded = base58Encode(bytes);
        const decoded = base58Decode(encoded);

        expect(decoded).toEqual(bytes);
      }
    });

    it("should throw error for invalid Base58 character", () => {
      expect(() => {
        base58Decode("invalid@base58");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character '0'", () => {
      expect(() => {
        base58Decode("ABC0DEF");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character 'O'", () => {
      expect(() => {
        base58Decode("ABCODEF");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character 'I'", () => {
      expect(() => {
        base58Decode("ABCDIEF");
      }).toThrow("Invalid base58 character");
    });

    it("should throw error for character 'l'", () => {
      expect(() => {
        base58Decode("ABCDlEF");
      }).toThrow("Invalid base58 character");
    });
  });

  describe("isValidBase58", () => {
    it("should return true for valid Base58 string", () => {
      const valid = base58Encode(new Uint8Array([1, 2, 3]));
      expect(isValidBase58(valid)).toBe(true);
    });

    it("should return true for empty string", () => {
      expect(isValidBase58("")).toBe(true);
    });

    it("should return false for string with invalid character '0'", () => {
      expect(isValidBase58("ABC0DEF")).toBe(false);
    });

    it("should return false for string with invalid character 'O'", () => {
      expect(isValidBase58("ABCODEF")).toBe(false);
    });

    it("should return false for string with invalid character 'I'", () => {
      expect(isValidBase58("ABCDIEF")).toBe(false);
    });

    it("should return false for string with invalid character 'l'", () => {
      expect(isValidBase58("ABCDlEF")).toBe(false);
    });

    it("should return false for string with special characters", () => {
      expect(isValidBase58("ABC@DEF")).toBe(false);
      expect(isValidBase58("ABC-DEF")).toBe(false);
      expect(isValidBase58("ABC DEF")).toBe(false);
    });

    it("should return true for all valid Base58 characters", () => {
      const validChars =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
      expect(isValidBase58(validChars)).toBe(true);
    });

    it("should return true for string with only '1' characters", () => {
      expect(isValidBase58("1111")).toBe(true);
    });
  });

  describe("Edge Cases", () => {
    it("should handle large byte arrays", () => {
      const largeArray = new Uint8Array(100);
      for (let i = 0; i < 100; i++) {
        largeArray[i] = i % 256;
      }

      const encoded = base58Encode(largeArray);
      const decoded = base58Decode(encoded);

      expect(decoded).toEqual(largeArray);
    });

    it("should handle bytes with maximum values", () => {
      const maxBytes = new Uint8Array([255, 255, 255, 255]);
      const encoded = base58Encode(maxBytes);
      const decoded = base58Decode(encoded);

      expect(decoded).toEqual(maxBytes);
    });

    it("should handle single byte encoding/decoding", () => {
      for (let i = 0; i < 256; i++) {
        const bytes = new Uint8Array([i]);
        const encoded = base58Encode(bytes);
        const decoded = base58Decode(encoded);

        expect(decoded).toEqual(bytes);
      }
    });

    it("should handle mixed leading zeros and non-zero bytes", () => {
      const testCases = [
        new Uint8Array([0, 1]),
        new Uint8Array([0, 0, 1]),
        new Uint8Array([0, 255]),
        new Uint8Array([0, 0, 0, 1, 2, 3]),
      ];

      for (const bytes of testCases) {
        const encoded = base58Encode(bytes);
        const decoded = base58Decode(encoded);

        expect(decoded).toEqual(bytes);
      }
    });

    it("should produce shorter output for small values", () => {
      const small = new Uint8Array([1]);
      const large = new Uint8Array([255, 255, 255]);

      const smallEncoded = base58Encode(small);
      const largeEncoded = base58Encode(large);

      // Small values should produce shorter Base58 strings
      expect(smallEncoded.length).toBeLessThan(largeEncoded.length);
    });
  });

  describe("Real-world DID:key Examples", () => {
    it("should encode/decode Ed25519 public key bytes", () => {
      // Example Ed25519 public key (32 bytes)
      const ed25519Key = new Uint8Array([
        0xed,
        0x01, // Ed25519 multicodec prefix
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc,
        0xde,
        0xf0,
      ]);

      const encoded = base58Encode(ed25519Key);
      expect(isValidBase58(encoded)).toBe(true);

      const decoded = base58Decode(encoded);
      expect(decoded).toEqual(ed25519Key);
    });
  });

  describe("decode cost is bounded (inputs come from counterparty DIDs)", () => {
    it("round-trips random bytes, including leading zero bytes", () => {
      for (let i = 0; i < 200; i++) {
        const bytes = new Uint8Array(1 + (i % 40));
        crypto.getRandomValues(bytes);
        bytes.fill(0, 0, i % 4); // 0-3 leading zero bytes
        expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
      }
    });

    it("decodes without a length limit when no maxLength is passed, as before", () => {
      expect(base58Decode("2".repeat(2_000)).length).toBeGreaterThan(0);
    });

    it("refuses input over an explicit maxLength before decoding it", () => {
      const bound = MAX_BASE58_DECODE_LENGTH;
      expect(base58Decode("2".repeat(bound), bound).length).toBeGreaterThan(0);
      const t0 = performance.now();
      expect(() => base58Decode("2".repeat(50_000), bound)).toThrow(/exceeds 1024 characters/);
      expect(performance.now() - t0).toBeLessThan(250);
      expect(() => base58Decode("22", 1)).toThrow(/exceeds 1 characters/);
    });

    it.each([Number.NaN, -1, 1.5, Number.POSITIVE_INFINITY])(
      "rejects a maxLength of %s instead of treating it as unbounded",
      (maxLength) => {
        expect(() => base58Decode("22", maxLength)).toThrow(RangeError);
      },
    );

    it("accepts a maxLength of 0 for empty input only", () => {
      expect(base58Decode("", 0)).toEqual(new Uint8Array(0));
      expect(() => base58Decode("2", 0)).toThrow(/exceeds 0 characters/);
    });

    it.each(["publicKeyMultibase", "publicKeyBase58"] as const)(
      "rejects a 100 KB %s in a DID document without decoding it",
      (field) => {
        const huge = "2".repeat(100_000);
        const method = {
          id: "did:web:example.com#k",
          type: "Ed25519VerificationKey2020",
          controller: "did:web:example.com",
          [field]: field === "publicKeyMultibase" ? `z${huge}` : huge,
        };
        const t0 = performance.now();
        expect(verificationMethodJwk(method)).toBeUndefined();
        expect(performance.now() - t0).toBeLessThan(250);
      },
    );

    it("rejects a 100 KB did:key without decoding it", () => {
      const t0 = performance.now();
      expect(extractPublicKeyFromDidKey("did:key:z6Mk" + "2".repeat(100_000))).toBeNull();
      expect(performance.now() - t0).toBeLessThan(250);
    });

    it("rejects a did:key whose payload carries bytes beyond the 32-byte key", () => {
      const key = new Uint8Array(32).fill(7);
      const did = generateDidKeyFromBytes(key);
      expect(extractPublicKeyFromDidKey(did)).toEqual(key);
      // The right multicodec prefix, then one byte too many.
      const padded = `did:key:z${base58Encode(new Uint8Array([0xed, 0x01, ...key, 0x00]))}`;
      expect(extractPublicKeyFromDidKey(padded)).toBeNull();
    });

    it("end-to-end: a tool call carrying a 100 KB did:key issuer does not pin the event loop", async () => {
      const crypto = new NodeCryptoProvider();
      const server = await crypto.generateKeyPair();
      const serverDid = generateDidKeyFromBase64(server.publicKey);
      const mw = createKyaOsMiddleware(
        {
          identity: { did: serverDid, kid: `${serverDid}#k`, privateKey: server.privateKey, publicKey: server.publicKey },
          session: { sessionTtlMinutes: 60 },
        },
        crypto,
      );
      const attacker = await crypto.generateKeyPair();
      const issuerDid = "did:key:z6Mk" + "2".repeat(100_000);
      const issuer = new DelegationCredentialIssuer(
        { getDid: () => issuerDid, getKeyId: () => `${issuerDid}#k`, getPrivateKey: () => attacker.privateKey },
        async (canonical: string, _d: string, kid: string) => ({
          type: "Ed25519Signature2020",
          created: new Date().toISOString(),
          verificationMethod: kid,
          proofPurpose: "assertionMethod",
          proofValue: base64urlEncodeFromBytes(
            await crypto.sign(new TextEncoder().encode(canonical), attacker.privateKey),
          ),
        }),
      );
      const vc = await issuer.createAndIssueDelegation({
        id: "d-1",
        issuerDid,
        subjectDid: issuerDid,
        constraints: { scopes: ["t:s"], notAfter: Math.floor(Date.now() / 1000) + 3600 },
      });
      const handler = mw.wrapWithDelegation("tool", { scopeId: "t:s", consentUrl: "https://example.com/c" }, async () => ({
        content: [{ type: "text", text: "ok" }],
      }));

      const t0 = performance.now();
      const res = await handler({ _kyaos_delegation: vc });
      expect(res.isError).toBe(true);
      // Unbounded, this took seconds before any signature check ran.
      expect(performance.now() - t0).toBeLessThan(1_000);
    });
  });
});
