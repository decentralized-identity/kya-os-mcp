/**
 * WebCrypto CryptoProvider
 *
 * Ed25519 crypto backed by the WebCrypto API (`globalThis.crypto.subtle`).
 * Isomorphic — runs in Cloudflare Workers, Deno, modern browsers, and Node 20+
 * — so an edge runtime (or the isomorphic `@kya-os/verifier`) can use the
 * shared `ProofVerifier` without pulling in `node:crypto`.
 *
 * Mirrors {@link NodeCryptoProvider}'s key formats EXACTLY — raw 32-byte
 * Ed25519 keys, base64-encoded; `sha256:<hex>` digests — so the two are
 * drop-in interchangeable: a proof signed under one verifies under the other.
 * (Cross-provider parity is asserted in the tests.)
 *
 * Requires a runtime whose WebCrypto implements the Ed25519 curve (Workers,
 * Deno, Node 20+, recent browsers). Throws a clear error if `crypto.subtle`
 * is unavailable rather than failing obscurely deep in a verify call.
 *
 * @example
 * ```typescript
 * import { WebCryptoProvider } from '@kya-os/mcp/providers';
 * const verifier = new ProofVerifier({ cryptoProvider: new WebCryptoProvider(), ... });
 * ```
 */

import { CryptoProvider } from "./base.js";
import { base64ToBytes, bytesToBase64 } from "../utils/base64.js";

const ALG = "Ed25519" as const;

/** PKCS8 DER header for Ed25519 private keys (16 bytes) — matches NodeCryptoProvider. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function getCrypto(): typeof crypto {
  // `crypto` is the WebCrypto global (Node 20+, Cloudflare Workers, Deno,
  // browsers). Typed via the runtime's lib/@types — referenced bare (like
  // authz/oidc/pkce.ts) so this file needs no DOM lib in tsconfig.
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error(
      "WebCryptoProvider: WebCrypto (crypto.subtle) is unavailable in this runtime",
    );
  }
  return crypto;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// WebCrypto's BufferSource requires a Uint8Array backed by a concrete
// ArrayBuffer (not the wider ArrayBufferLike a bare `Uint8Array` type
// admits). `.slice()` always allocates a fresh ArrayBuffer, so it doubles
// as the narrowing conversion.
function toBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.slice();
}

// CryptoKeyPair isn't a global name without the DOM lib (see getCrypto), so
// it's derived from generateKey's own return type rather than named directly.
type SubtleCryptoT = ReturnType<typeof getCrypto>["subtle"];
type GeneratedKey = Awaited<ReturnType<SubtleCryptoT["generateKey"]>>;
type GeneratedKeyPair = Extract<GeneratedKey, { privateKey: unknown }>;

function isKeyPair(key: GeneratedKey): key is GeneratedKeyPair {
  return "privateKey" in key && "publicKey" in key;
}

export class WebCryptoProvider extends CryptoProvider {
  async sign(data: Uint8Array, privateKeyBase64: string): Promise<Uint8Array> {
    const raw = base64ToBytes(privateKeyBase64);
    // Accept both raw 32-byte and full 64-byte Ed25519 keys (use the seed).
    const seed = raw.length === 64 ? raw.subarray(0, 32) : raw;
    const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
    pkcs8.set(ED25519_PKCS8_PREFIX, 0);
    pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
    const key = await getCrypto().subtle.importKey("pkcs8", pkcs8, { name: ALG }, false, ["sign"]);
    const sig = await getCrypto().subtle.sign({ name: ALG }, key, toBufferSource(data));
    return new Uint8Array(sig);
  }

  async verify(
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyBase64: string,
  ): Promise<boolean> {
    try {
      const raw = base64ToBytes(publicKeyBase64);
      const key = await getCrypto().subtle.importKey(
        "raw",
        toBufferSource(raw),
        { name: ALG },
        false,
        ["verify"],
      );
      return await getCrypto().subtle.verify(
        { name: ALG },
        key,
        toBufferSource(signature),
        toBufferSource(data),
      );
    } catch {
      // Never throw on a bad key/signature — verification simply fails.
      return false;
    }
  }

  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    const kp = await getCrypto().subtle.generateKey({ name: ALG }, true, ["sign", "verify"]);
    if (!isKeyPair(kp)) {
      throw new Error("WebCryptoProvider: expected an Ed25519 key pair from generateKey");
    }
    const rawPub = new Uint8Array(await getCrypto().subtle.exportKey("raw", kp.publicKey));
    const pkcs8 = new Uint8Array(await getCrypto().subtle.exportKey("pkcs8", kp.privateKey));
    // Strip the 16-byte PKCS8 prefix to recover the raw 32-byte seed (mirrors
    // NodeCryptoProvider, which slices [16,48) of the DER).
    const seed = pkcs8.subarray(ED25519_PKCS8_PREFIX.length, ED25519_PKCS8_PREFIX.length + 32);
    return { privateKey: bytesToBase64(seed), publicKey: bytesToBase64(rawPub) };
  }

  async hash(data: Uint8Array): Promise<string> {
    const digest = new Uint8Array(await getCrypto().subtle.digest("SHA-256", toBufferSource(data)));
    return `sha256:${toHex(digest)}`;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return getCrypto().getRandomValues(new Uint8Array(length));
  }
}
