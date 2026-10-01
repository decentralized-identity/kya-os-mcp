/**
 * The CryptoProviders' contact with their runtime: when `node:crypto` is
 * loaded, what each provider says where its primitive is missing, and that
 * verify() answers false, never throws, whatever it is handed.
 */
import { afterEach, describe, it, expect, vi } from "vitest";

import { NodeCryptoProvider } from "../node-crypto.js";
import { WebCryptoProvider } from "../web-crypto.js";

const msg = new TextEncoder().encode("m");

describe("NodeCryptoProvider loads node:crypto on first use", () => {
  it("does not load node:crypto at import, only when a method first needs it", async () => {
    let loads = 0;
    vi.resetModules();
    vi.doMock("node:crypto", async (importOriginal) => {
      loads += 1;
      return importOriginal();
    });
    try {
      const { NodeCryptoProvider: Fresh } = await import("../node-crypto.js");
      // Importing the module (as a browser bundle of the providers entry
      // would) must not touch the node built-in.
      expect(loads).toBe(0);

      const provider = new Fresh();
      const kp = await provider.generateKeyPair();
      expect(loads).toBe(1);
      const sig = await provider.sign(msg, kp.privateKey);
      expect(await provider.verify(msg, sig, kp.publicKey)).toBe(true);
      expect(await provider.hash(msg)).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(await provider.randomBytes(16)).toHaveLength(16);
      expect(loads).toBe(1);
    } finally {
      vi.doUnmock("node:crypto");
      vi.resetModules();
    }
  });

  it("fails with a pointer to WebCryptoProvider where node:crypto is missing", async () => {
    vi.resetModules();
    vi.doMock("node:crypto", () => {
      throw new Error("node:crypto is not available in workerd");
    });
    try {
      const { NodeCryptoProvider: Fresh } = await import("../node-crypto.js");
      const provider = new Fresh();
      await expect(provider.hash(msg)).rejects.toThrow(
        /node:crypto is unavailable in this runtime; use WebCryptoProvider/,
      );
      // Every method reports the same thing, not a module-resolution error.
      await expect(provider.generateKeyPair()).rejects.toThrow(/use WebCryptoProvider/);
    } finally {
      vi.doUnmock("node:crypto");
      vi.resetModules();
    }
  });
});

describe("WebCryptoProvider without a usable WebCrypto", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it.each([
    ["no crypto global", undefined],
    ["crypto without subtle", {}],
  ])("names the missing primitive (%s)", async (_label, value) => {
    vi.stubGlobal("crypto", value);
    await expect(new WebCryptoProvider().hash(msg)).rejects.toThrow(
      /WebCrypto \(crypto\.subtle\) is unavailable in this runtime/,
    );
  });

  it("refuses a generateKey result that is not a key pair", async () => {
    // A runtime that answers with a single key (here a real HMAC key) must
    // not yield a half-filled key pair.
    const single = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    vi.spyOn(crypto.subtle, "generateKey").mockResolvedValueOnce(single);
    await expect(new WebCryptoProvider().generateKeyPair()).rejects.toThrow(
      /expected an Ed25519 key pair/,
    );
  });
});

describe("verify() answers false, never throws", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each([
    ["NodeCryptoProvider", new NodeCryptoProvider()],
    ["WebCryptoProvider", new WebCryptoProvider()],
  ] as const)(
    "%s returns false for a signature that is not bytes (an untyped caller)",
    async (_name, provider) => {
      const { publicKey } = await provider.generateKeyPair();
      for (const signature of [undefined, null, 42]) {
        const notBytes = signature as unknown as Uint8Array;
        await expect(provider.verify(msg, notBytes, publicKey)).resolves.toBe(false);
      }
    },
  );

  it("WebCryptoProvider returns false when the runtime refuses a well-formed key", async () => {
    const provider = new WebCryptoProvider();
    const kp = await provider.generateKeyPair();
    const sig = await provider.sign(msg, kp.privateKey);
    expect(await provider.verify(msg, sig, kp.publicKey)).toBe(true);
    // Some runtimes validate the curve point on import; that refusal must
    // surface as a failed verification, not an exception.
    vi.spyOn(crypto.subtle, "importKey").mockRejectedValueOnce(new DOMException("bad key"));
    await expect(provider.verify(msg, sig, kp.publicKey)).resolves.toBe(false);
  });
});
