import { describe, it, expect } from "vitest";

import { WebCryptoProvider } from "../web-crypto.js";
import { NodeCryptoProvider } from "../node-crypto.js";
import { base64ToBytes, base64urlEncodeFromBytes, bytesToBase64 } from "../../utils/base64.js";
import { generateDidKeyFromBytes } from "../../utils/did-helpers.js";

const web = new WebCryptoProvider();
const node = new NodeCryptoProvider();
const enc = (s: string) => new TextEncoder().encode(s);

describe("WebCryptoProvider", () => {
  it("round-trips sign → verify with its own key", async () => {
    const { privateKey, publicKey } = await web.generateKeyPair();
    const msg = enc("hello kya-os");
    const sig = await web.sign(msg, privateKey);
    expect(await web.verify(msg, sig, publicKey)).toBe(true);
  });

  it("verify() returns false (never throws) for a tampered message", async () => {
    const { privateKey, publicKey } = await web.generateKeyPair();
    const sig = await web.sign(enc("original"), privateKey);
    expect(await web.verify(enc("tampered"), sig, publicKey)).toBe(false);
  });

  it("verify() returns false for a wrong/garbage key instead of throwing", async () => {
    const { privateKey } = await web.generateKeyPair();
    const sig = await web.sign(enc("x"), privateKey);
    expect(await web.verify(enc("x"), sig, "not-a-real-key")).toBe(false);
  });

  it("hash matches NodeCryptoProvider (sha256:<hex>)", async () => {
    const data = enc("canonical payload bytes");
    expect(await web.hash(data)).toBe(await node.hash(data));
    expect(await web.hash(data)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("randomBytes returns the requested length and varies", async () => {
    const a = await web.randomBytes(32);
    const b = await web.randomBytes(32);
    expect(a).toHaveLength(32);
    expect(bytesToBase64(a)).not.toBe(bytesToBase64(b));
  });

  describe("cross-provider parity with NodeCryptoProvider (drop-in interchangeable)", () => {
    it("a Node-signed proof verifies under WebCrypto (the Worker path)", async () => {
      const { privateKey, publicKey } = await node.generateKeyPair();
      const msg = enc("proof canonical bytes");
      const sigNode = await node.sign(msg, privateKey);
      expect(await web.verify(msg, sigNode, publicKey)).toBe(true);
    });

    it("a WebCrypto-signed proof verifies under Node", async () => {
      const { privateKey, publicKey } = await web.generateKeyPair();
      const msg = enc("proof canonical bytes");
      const sigWeb = await web.sign(msg, privateKey);
      expect(await node.verify(msg, sigWeb, publicKey)).toBe(true);
    });

    it("Ed25519 is deterministic → both providers produce byte-identical signatures", async () => {
      const { privateKey } = await node.generateKeyPair();
      const msg = enc("deterministic");
      const sigNode = await node.sign(msg, privateKey);
      const sigWeb = await web.sign(msg, privateKey);
      expect(bytesToBase64(sigWeb)).toBe(bytesToBase64(sigNode));
    });

    it("both reject a 64-byte public key (key || junk)", async () => {
      const kp = await node.generateKeyPair();
      const msg = enc("m");
      const sig = await node.sign(msg, kp.privateKey);
      const padded = bytesToBase64(
        new Uint8Array([...base64ToBytes(kp.publicKey), ...new Uint8Array(32).fill(7)]),
      );
      expect(await web.verify(msg, sig, padded)).toBe(false);
      expect(await node.verify(msg, sig, padded)).toBe(false);
    });

    it("both reject a public key with trailing non-base64 characters", async () => {
      const kp = await node.generateKeyPair();
      const msg = enc("m");
      const sig = await node.sign(msg, kp.privateKey);
      const junk = `${kp.publicKey}!!!!`;
      expect(await web.verify(msg, sig, junk)).toBe(false);
      expect(await node.verify(msg, sig, junk)).toBe(false);
    });

    it("both accept the same key unpadded or in base64url", async () => {
      const kp = await node.generateKeyPair();
      const msg = enc("m");
      const sig = await node.sign(msg, kp.privateKey);
      const url = base64urlEncodeFromBytes(base64ToBytes(kp.publicKey));
      for (const provider of [node, web]) {
        expect(await provider.verify(msg, sig, url)).toBe(true);
      }
    });
  });

  describe("small-order public keys", () => {
    // A = identity (small order). With R = identity and S = 0 the verification
    // equation [S]B == R + [k]A holds for EVERY message, so anyone could sign
    // anything as a did:key built from this key.
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const universalSig = new Uint8Array(64);
    universalSig[0] = 1;
    const pub = bytesToBase64(identity);

    it("the weak key is a well-formed did:key (nothing upstream rejects it)", () => {
      expect(generateDidKeyFromBytes(identity)).toMatch(/^did:key:z6Mk/);
    });

    it.each([
      ["NodeCryptoProvider", node],
      ["WebCryptoProvider", web],
    ] as const)("%s rejects a universal signature under a small-order key", async (_name, provider) => {
      expect(await provider.verify(enc("transfer $1 to alice"), universalSig, pub)).toBe(false);
      expect(await provider.verify(enc("transfer $1M to mallory"), universalSig, pub)).toBe(false);
    });
  });
});
