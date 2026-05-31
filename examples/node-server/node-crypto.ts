/**
 * Node.js CryptoProvider for examples.
 * Uses node:crypto for Ed25519 operations.
 */

import { createHash, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
import { CryptoProvider } from '@kya-os/mcp';

export class NodeCryptoProvider extends CryptoProvider {
  async sign(data: Uint8Array, privateKeyBase64: string): Promise<Uint8Array> {
    const keyBuffer = Buffer.from(privateKeyBase64, 'base64');
    const derPrefix = Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
    const derKey = Buffer.concat([derPrefix, keyBuffer.subarray(0, 32)]);
    const keyObj = { key: derKey, format: 'der' as const, type: 'pkcs8' as const };
    return new Uint8Array(sign(undefined, Buffer.from(data), keyObj));
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicKeyBase64: string): Promise<boolean> {
    const keyBuffer = Buffer.from(publicKeyBase64, 'base64');
    const derPrefix = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
    const derKey = Buffer.concat([derPrefix, keyBuffer.subarray(0, 32)]);
    const keyObj = { key: derKey, format: 'der' as const, type: 'spki' as const };
    return verify(undefined, Buffer.from(data), keyObj, Buffer.from(signature));
  }

  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const privDer = privateKey.export({ type: 'pkcs8', format: 'der' });
    const pubDer = publicKey.export({ type: 'spki', format: 'der' });
    // Extract raw 32-byte keys from DER
    const rawPrivate = (privDer as Buffer).subarray(-32);
    const rawPublic = (pubDer as Buffer).subarray(-32);
    return {
      privateKey: rawPrivate.toString('base64'),
      publicKey: rawPublic.toString('base64'),
    };
  }

  async hash(data: Uint8Array): Promise<string> {
    const digest = createHash('sha256').update(data).digest('hex');
    return `sha256:${digest}`;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(randomBytes(length));
  }
}
