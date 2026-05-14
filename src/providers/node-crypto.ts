/**
 * Node.js CryptoProvider
 *
 * Ed25519 crypto backed by Node.js built-in `node:crypto`.
 * Use this on any Node.js 20+ server.
 *
 * @example
 * ```typescript
 * import { NodeCryptoProvider } from '@kya-os/mcp/providers';
 * import { withMCPI } from '@kya-os/mcp/middleware';
 *
 * await withMCPI(server, { crypto: new NodeCryptoProvider() });
 * ```
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  randomBytes,
} from "node:crypto";
import { CryptoProvider } from "./base.js";

/** PKCS8 DER header for Ed25519 private keys (16 bytes) */
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/** SPKI DER header for Ed25519 public keys (12 bytes) */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export class NodeCryptoProvider extends CryptoProvider {
  async sign(
    data: Uint8Array,
    privateKeyBase64: string,
  ): Promise<Uint8Array> {
    const privateKey = Buffer.from(privateKeyBase64, "base64");

    // Handle both raw 32-byte and full 64-byte Ed25519 keys
    const keyBytes =
      privateKey.length === 64 ? privateKey.subarray(0, 32) : privateKey;

    const keyObject = createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, keyBytes]),
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
    try {
      const keyObject = createPublicKey({
        key: Buffer.concat([
          ED25519_SPKI_PREFIX,
          Buffer.from(publicKeyBase64, "base64"),
        ]),
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
    const hex = createHash("sha256")
      .update(Buffer.from(data))
      .digest("hex");
    return `sha256:${hex}`;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(randomBytes(length));
  }
}
