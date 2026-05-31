import { describe, it, expect } from 'vitest';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';

describe('NodeCryptoProvider', () => {
  const crypto = new NodeCryptoProvider();

  describe('generateKeyPair', () => {
    it('returns base64 Ed25519 key material (32-byte seed + 32-byte public key)', async () => {
      const { privateKey, publicKey } = await crypto.generateKeyPair();
      expect(Buffer.from(privateKey, 'base64')).toHaveLength(32);
      expect(Buffer.from(publicKey, 'base64')).toHaveLength(32);
    });

    it('returns a distinct key pair on each call', async () => {
      const a = await crypto.generateKeyPair();
      const b = await crypto.generateKeyPair();
      expect(a.privateKey).not.toBe(b.privateKey);
      expect(a.publicKey).not.toBe(b.publicKey);
    });
  });

  describe('sign / verify', () => {
    it('round-trips: a signature over data verifies against its public key', async () => {
      const { privateKey, publicKey } = await crypto.generateKeyPair();
      const data = new TextEncoder().encode('kya-os proof payload');
      const sig = await crypto.sign(data, privateKey);
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(await crypto.verify(data, sig, publicKey)).toBe(true);
    });

    it('rejects a tampered payload', async () => {
      const { privateKey, publicKey } = await crypto.generateKeyPair();
      const sig = await crypto.sign(new TextEncoder().encode('original'), privateKey);
      expect(await crypto.verify(new TextEncoder().encode('tampered'), sig, publicKey)).toBe(false);
    });

    it('rejects a signature made with a different key', async () => {
      const a = await crypto.generateKeyPair();
      const b = await crypto.generateKeyPair();
      const data = new TextEncoder().encode('x');
      const sig = await crypto.sign(data, a.privateKey);
      expect(await crypto.verify(data, sig, b.publicKey)).toBe(false);
    });

    it('verify returns false (never throws) for malformed key material', async () => {
      const { privateKey } = await crypto.generateKeyPair();
      const sig = await crypto.sign(new TextEncoder().encode('x'), privateKey);
      expect(await crypto.verify(new TextEncoder().encode('x'), sig, 'not-a-valid-key')).toBe(false);
    });

    it('accepts a 64-byte private key, using the first 32 bytes as the seed', async () => {
      const { privateKey, publicKey } = await crypto.generateKeyPair();
      const seed = Buffer.from(privateKey, 'base64'); // 32-byte seed
      const sixtyFour = Buffer.concat([seed, Buffer.alloc(32)]).toString('base64');
      const data = new TextEncoder().encode('64-byte key path');
      const sig = await crypto.sign(data, sixtyFour);
      expect(await crypto.verify(data, sig, publicKey)).toBe(true);
    });
  });

  describe('hash', () => {
    it('returns a sha256:<64 hex> digest', async () => {
      const h = await crypto.hash(new TextEncoder().encode('abc'));
      expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it('is deterministic for the same input', async () => {
      const data = new TextEncoder().encode('same input');
      expect(await crypto.hash(data)).toBe(await crypto.hash(data));
    });
  });

  describe('randomBytes', () => {
    it('returns the requested length and varies between calls', async () => {
      const a = await crypto.randomBytes(16);
      const b = await crypto.randomBytes(16);
      expect(a).toBeInstanceOf(Uint8Array);
      expect(a).toHaveLength(16);
      expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    });
  });
});
