import { describe, it, expect } from "vitest";

import { WebCryptoProvider } from "../web-crypto.js";
import { NodeCryptoProvider } from "../node-crypto.js";
import { bytesToBase64 } from "../../utils/base64.js";

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
  });
});
