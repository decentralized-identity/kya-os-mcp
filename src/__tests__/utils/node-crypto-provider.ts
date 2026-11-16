/**
 * Node.js Crypto Provider for Testing
 *
 * Uses Node.js built-in crypto module for Ed25519 operations.
 * Only used in tests — not included in the published package.
 */

import * as crypto from 'node:crypto';
import { CryptoProvider } from '../../providers/base.js';

export class NodeCryptoProvider extends CryptoProvider {
  async sign(data: Uint8Array, privateKeyBase64: string): Promise<Uint8Array> {
    const privateKey = Buffer.from(privateKeyBase64, 'base64');

    // Handle both raw 32-byte and full 64-byte Ed25519 keys
    const keyBytes =
      privateKey.length === 64 ? privateKey.subarray(0, 32) : privateKey;

    // Wrap in PKCS8 format for Node.js crypto
    const pkcs8 = Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      keyBytes,
    ]);

    const keyObject = crypto.createPrivateKey({
      key: pkcs8,
      format: 'der',
      type: 'pkcs8',
    });

    const signature = crypto.sign(null, Buffer.from(data), keyObject);
    return new Uint8Array(signature);
  }

  async verify(
    data: Uint8Array,
    signature: Uint8Array,
    publicKeyBase64: string
  ): Promise<boolean> {
    try {
      const publicKey = Buffer.from(publicKeyBase64, 'base64');

      // Wrap in SPKI format for Node.js crypto
      const spki = Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKey,
      ]);

      const keyObject = crypto.createPublicKey({
        key: spki,
        format: 'der',
        type: 'spki',
      });

      return crypto.verify(
        null,
        Buffer.from(data),
        keyObject,
        Buffer.from(signature)
      );
    } catch {
      return false;
    }
  }

  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });

    // Extract raw keys from DER encoding
    const rawPrivate = (privateKey as Buffer).subarray(16, 48);
    const rawPublic = (publicKey as Buffer).subarray(12, 44);

    return {
      privateKey: rawPrivate.toString('base64'),
      publicKey: rawPublic.toString('base64'),
    };
  }

  async hash(data: Uint8Array): Promise<string> {
    const hex = crypto
      .createHash('sha256')
      .update(Buffer.from(data))
      .digest('hex');
    return `sha256:${hex}`;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(crypto.randomBytes(length));
  }
}

/** The provider tests share: it holds no state, so one instance serves every test. */
export const nodeCrypto = new NodeCryptoProvider();

/** `sha256:` and the hex SHA-256 of `bytes`, by {@link nodeCrypto}: the hash a digest is taken with. */
export const nodeHash = (bytes: Uint8Array): Promise<string> => nodeCrypto.hash(bytes);
