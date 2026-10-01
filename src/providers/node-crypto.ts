/**
 * Node.js CryptoProvider
 *
 * Ed25519 crypto backed by Node.js built-in `node:crypto`.
 * Use this on any Node.js 20+ server.
 *
 * `node:crypto` is loaded on first use, never at module load: the
 * `@kya-os/mcp/providers` entry also serves `WebCryptoProvider` to browsers and
 * Workers, and a top-level import of a node built-in would break their bundles.
 *
 * @example
 * ```typescript
 * import { NodeCryptoProvider } from '@kya-os/mcp/providers';
 * import { withKyaOs } from '@kya-os/mcp/middleware';
 *
 * await withKyaOs(server, { crypto: new NodeCryptoProvider() });
 * ```
 */

import { CryptoProvider } from "./base.js";
import { ED25519_PKCS8_DER_HEADER } from "../utils/ed25519-constants.js";
import { decodeEd25519PublicKey } from "../utils/ed25519-public-key.js";

/** SPKI DER header for Ed25519 public keys (12 bytes) */
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

type NodeCrypto = typeof import("node:crypto");
let nodeCryptoPromise: Promise<NodeCrypto> | undefined;

/**
 * Load (and cache) `node:crypto`. Where it is absent, fail with a pointer to
 * the provider that works there rather than a module-resolution error.
 */
function loadNodeCrypto(): Promise<NodeCrypto> {
  return (nodeCryptoPromise ??= import("node:crypto").catch((cause: unknown) => {
    throw new Error(
      "NodeCryptoProvider: node:crypto is unavailable in this runtime; use WebCryptoProvider",
      { cause },
    );
  }));
}

export class NodeCryptoProvider extends CryptoProvider {
  async sign(
    data: Uint8Array,
    privateKeyBase64: string,
  ): Promise<Uint8Array> {
    const { createPrivateKey, sign } = await loadNodeCrypto();
    const privateKey = Buffer.from(privateKeyBase64, "base64");

    // Handle both raw 32-byte and full 64-byte Ed25519 keys
    const keyBytes =
      privateKey.length === 64 ? privateKey.subarray(0, 32) : privateKey;

    const keyObject = createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_DER_HEADER, keyBytes]),
      format: "der",
      type: "pkcs8",
    });

    return new Uint8Array(sign(null, Buffer.from(data), keyObject));
  }

  async verify(
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyBase64: string,
  ): Promise<boolean> {
    const { createPublicKey, verify } = await loadNodeCrypto();
    // Exactly 32 bytes, decoded strictly: Node's base64 decoder would skip
    // junk and the SPKI wrap would accept extra bytes after the key.
    const publicKey = decodeEd25519PublicKey(publicKeyBase64);
    if (!publicKey) {
      return false;
    }
    try {
      const keyObject = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
        format: "der",
        type: "spki",
      });

      return verify(
        null,
        Buffer.from(data),
        keyObject,
        Buffer.from(signature),
      );
    } catch {
      return false;
    }
  }

  async generateKeyPair(): Promise<{
    privateKey: string;
    publicKey: string;
  }> {
    const { generateKeyPairSync } = await loadNodeCrypto();
    const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" },
    });

    return {
      privateKey: (privateKey as Buffer).subarray(16, 48).toString("base64"),
      publicKey: (publicKey as Buffer).subarray(12, 44).toString("base64"),
    };
  }

  async hash(data: Uint8Array): Promise<string> {
    const { createHash } = await loadNodeCrypto();
    const hex = createHash("sha256")
      .update(Buffer.from(data))
      .digest("hex");
    return `sha256:${hex}`;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    const { randomBytes } = await loadNodeCrypto();
    return new Uint8Array(randomBytes(length));
  }
}
