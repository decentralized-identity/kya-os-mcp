/**
 * Tests for Memory Provider Implementations
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  MemoryStorageProvider,
  MemoryNonceCacheProvider,
  MemoryIdentityProvider
} from '../../providers/memory.js';
import { MockCryptoProvider } from '../utils/mock-providers.js';
import { NodeCryptoProvider } from '../utils/node-crypto-provider.js';
import { SessionManager } from '../../session/manager.js';
import { createKyaOsMiddleware } from '../../middleware/with-kya-os.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';

describe('MemoryStorageProvider', () => {
  let provider: MemoryStorageProvider;

  beforeEach(() => {
    provider = new MemoryStorageProvider();
  });

  describe('get', () => {
    it('should return null for non-existent keys', async () => {
      const value = await provider.get('nonexistent');
      expect(value).toBeNull();
    });

    it('should return stored values', async () => {
      await provider.set('key1', 'value1');
      const value = await provider.get('key1');
      expect(value).toBe('value1');
    });
  });

  describe('set', () => {
    it('should store values', async () => {
      await provider.set('key1', 'value1');
      const value = await provider.get('key1');
      expect(value).toBe('value1');
    });

    it('should overwrite existing values', async () => {
      await provider.set('key1', 'value1');
      await provider.set('key1', 'value2');
      const value = await provider.get('key1');
      expect(value).toBe('value2');
    });

    it('should handle empty string values', async () => {
      await provider.set('key1', '');
      const value = await provider.get('key1');
      expect(value).toBe('');
    });
  });

  describe('delete', () => {
    it('should delete existing keys', async () => {
      await provider.set('key1', 'value1');
      await provider.delete('key1');
      const value = await provider.get('key1');
      expect(value).toBeNull();
    });

    it('should handle deleting non-existent keys', async () => {
      await expect(provider.delete('nonexistent')).resolves.toBeUndefined();
    });
  });

  describe('exists', () => {
    it('should return false for non-existent keys', async () => {
      const exists = await provider.exists('nonexistent');
      expect(exists).toBe(false);
    });

    it('should return true for existing keys', async () => {
      await provider.set('key1', 'value1');
      const exists = await provider.exists('key1');
      expect(exists).toBe(true);
    });

    it('should return true for empty string values', async () => {
      await provider.set('key1', '');
      const exists = await provider.exists('key1');
      expect(exists).toBe(true);
    });
  });

  describe('list', () => {
    beforeEach(async () => {
      await provider.set('prefix/key1', 'value1');
      await provider.set('prefix/key2', 'value2');
      await provider.set('other/key3', 'value3');
      await provider.set('key4', 'value4');
    });

    it('should list all keys when no prefix provided', async () => {
      const keys = await provider.list();
      expect(keys).toHaveLength(4);
      expect(keys).toContain('prefix/key1');
      expect(keys).toContain('prefix/key2');
      expect(keys).toContain('other/key3');
      expect(keys).toContain('key4');
    });

    it('should filter by prefix', async () => {
      const keys = await provider.list('prefix/');
      expect(keys).toHaveLength(2);
      expect(keys).toContain('prefix/key1');
      expect(keys).toContain('prefix/key2');
    });

    it('should return empty array for non-matching prefix', async () => {
      const keys = await provider.list('nonexistent/');
      expect(keys).toHaveLength(0);
    });

    it('should handle empty prefix', async () => {
      const keys = await provider.list('');
      expect(keys).toHaveLength(4);
    });
  });
});

describe('MemoryNonceCacheProvider', () => {
  let provider: MemoryNonceCacheProvider;

  beforeEach(() => {
    provider = new MemoryNonceCacheProvider();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('consume', () => {
    it('admits exactly one concurrent claim without calling has/add', async () => {
      const has = vi.spyOn(provider, 'has');
      const add = vi.spyOn(provider, 'add');
      const results = await Promise.all([
        provider.consume('nonce', 5, 'did:key:zA'),
        provider.consume('nonce', 5, 'did:key:zA'),
      ]);
      expect(results).toEqual([true, false]);
      expect(has).not.toHaveBeenCalled();
      expect(add).not.toHaveBeenCalled();
    });

    it('preserves the first expiry and permits a claim exactly at expiry', async () => {
      expect(await provider.consume('nonce', 5)).toBe(true);
      vi.advanceTimersByTime(4000);
      expect(await provider.consume('nonce', 100)).toBe(false);
      vi.advanceTimersByTime(1000);
      expect(await provider.has('nonce')).toBe(false);
      expect(await provider.consume('nonce', 5)).toBe(true);
    });

    it('isolates nonce values by the complete DID and anonymous namespace', async () => {
      expect(await provider.consume('nonce', 5, 'did:key:zA')).toBe(true);
      expect(await provider.consume('nonce', 5, 'did:key:zB')).toBe(true);
      expect(await provider.consume('nonce', 5)).toBe(true);
      expect(await provider.consume('nonce', 5, 'did:key:zA')).toBe(false);
    });

    it.each([0, -1, NaN, Infinity])('rejects invalid TTL %s without claiming', async (ttl) => {
      await expect(provider.consume('nonce', ttl)).rejects.toThrow('TTL');
      expect(await provider.has('nonce')).toBe(false);
    });
  });

  describe('has', () => {
    it('should return false for non-existent nonces', async () => {
      const has = await provider.has('nonexistent');
      expect(has).toBe(false);
    });

    it('should return true for valid nonces', async () => {
      await provider.add('nonce1', 5); // 5 seconds TTL
      const has = await provider.has('nonce1');
      expect(has).toBe(true);
    });

    it('should return false for expired nonces', async () => {
      await provider.add('nonce1', -1); // Negative TTL = expired
      const has = await provider.has('nonce1');
      expect(has).toBe(false);
    });

    it('should remove expired nonces when checking', async () => {
      await provider.add('nonce1', -1); // Negative TTL = expired
      await provider.has('nonce1'); // This should remove it

      // Check internal state
      const has = await provider.has('nonce1');
      expect(has).toBe(false);
    });
  });

  describe('add', () => {
    it('should add nonces with expiry', async () => {
      await provider.add('nonce1', 5); // 5 seconds TTL
      const has = await provider.has('nonce1');
      expect(has).toBe(true);
    });

    it('should overwrite existing nonces', async () => {
      await provider.add('nonce1', 5); // 5 seconds TTL
      await provider.add('nonce1', 10); // 10 seconds TTL

      // Advance time by 7 seconds (between 5 and 10)
      vi.advanceTimersByTime(7000);

      const has = await provider.has('nonce1');
      expect(has).toBe(true); // Should still be valid with new expiry
    });
  });

  describe('cleanup', () => {
    it('should remove expired nonces', async () => {
      await provider.add('expired', -1); // Negative TTL = expired
      await provider.add('valid', 5); // 5 seconds TTL

      await provider.cleanup();

      expect(await provider.has('expired')).toBe(false);
      expect(await provider.has('valid')).toBe(true);
    });

    it('should handle empty cache', async () => {
      await expect(provider.cleanup()).resolves.toBeUndefined();
    });
  });

  describe('expiry without cleanup()', () => {
    // withKyaOs and SessionManager default to this cache and nothing schedules
    // cleanup(), so the cache has to release dead entries on its own.
    const size = (cache: MemoryNonceCacheProvider) =>
      (cache as unknown as { nonces: Map<string, number> }).nonces.size;

    it('sweeps expired nonces as a busy cache is written to', async () => {
      vi.setSystemTime(0);
      const cache = new MemoryNonceCacheProvider();
      // Any self-issued did:key can mint signed, admitted nonces like these.
      for (let i = 0; i < 20_000; i++) {
        await cache.consume(`nonce-${i}`, 60, 'did:key:zAttacker');
      }
      vi.setSystemTime(24 * 60 * 60 * 1000);
      for (let i = 0; i < 2_000; i++) {
        await cache.consume(`later-${i}`, 60, 'did:key:zAttacker');
      }
      expect(size(cache)).toBeLessThanOrEqual(2_000);
    });

    it('releases expired nonces in a quiet cache on its next write', async () => {
      const cache = new MemoryNonceCacheProvider();
      for (let i = 0; i < 50; i++) await cache.add(`n-${i}`, 60);
      vi.advanceTimersByTime(24 * 60 * 60 * 1000);
      await cache.add('fresh', 60);
      expect(size(cache)).toBe(1);
      expect(await cache.has('fresh')).toBe(true);
    });

    it('SessionManager: expired handshake nonces are evicted without a cleanup() call', async () => {
      vi.setSystemTime(new Date('2026-09-30T00:00:00Z'));
      const nonceCache = new MemoryNonceCacheProvider();
      const manager = new SessionManager(new NodeCryptoProvider(), {
        serverDid: 'did:web:server.example.com',
        nonceCache,
        maxSessions: 100,
      });
      // Unauthenticated callers: 2,000 handshakes spread over ~33 hours.
      for (let i = 0; i < 2_000; i++) {
        const r = await manager.validateHandshake({
          nonce: SessionManager.generateNonce(),
          audience: 'did:web:server.example.com',
          timestamp: Math.floor(Date.now() / 1000),
        });
        expect(r.success).toBe(true);
        vi.advanceTimersByTime(60_000);
      }
      expect(manager.getStats().activeSessions).toBeLessThanOrEqual(100);
      expect(size(nonceCache)).toBeLessThan(2_000);
    });

    it('withKyaOs: expired handshake nonces are eventually released', async () => {
      vi.setSystemTime(new Date('2026-09-30T00:00:00Z'));
      const crypto = new NodeCryptoProvider();
      const kp = await crypto.generateKeyPair();
      const did = generateDidKeyFromBase64(kp.publicKey);
      const nonceCache = new MemoryNonceCacheProvider();
      const kyaos = createKyaOsMiddleware(
        { identity: { did, kid: `${did}#key-1`, privateKey: kp.privateKey, publicKey: kp.publicKey }, nonceCache },
        crypto,
      );
      const handshake = (i: number) =>
        kyaos.handleHandshake({
          nonce: `handshake-nonce-${Date.now()}-${i}`,
          audience: did,
          timestamp: Math.floor(Date.now() / 1000),
        });

      for (let i = 0; i < 50; i++) await handshake(i);
      vi.setSystemTime(new Date('2026-10-01T00:00:00Z')); // a day later: all long expired
      for (let i = 0; i < 50; i++) await handshake(i);

      expect(size(nonceCache)).toBeLessThanOrEqual(50);
    });

    it('never sweeps a live nonce, so replay protection holds across sweeps', async () => {
      const cache = new MemoryNonceCacheProvider();
      expect(await cache.consume('live', 3600, 'did:key:zA')).toBe(true);
      for (let i = 0; i < 2_500; i++) await cache.consume(`n-${i}`, 1, 'did:key:zA');
      vi.advanceTimersByTime(120_000);
      await cache.consume('trigger', 1, 'did:key:zA');
      expect(await cache.consume('live', 3600, 'did:key:zA')).toBe(false);
    });
  });

  describe('destroy', () => {
    it('should clear all nonces', async () => {
      await provider.add('nonce1', 5); // 5 seconds TTL
      await provider.add('nonce2', 5); // 5 seconds TTL

      await provider.destroy();

      expect(await provider.has('nonce1')).toBe(false);
      expect(await provider.has('nonce2')).toBe(false);
    });
  });
});

describe('MemoryIdentityProvider', () => {
  let provider: MemoryIdentityProvider;
  let cryptoProvider: MockCryptoProvider;

  beforeEach(() => {
    cryptoProvider = new MockCryptoProvider();
    provider = new MemoryIdentityProvider(cryptoProvider);
  });

  describe('getIdentity', () => {
    it('should generate identity on first call', async () => {
      const identity = await provider.getIdentity();

      expect(identity).toBeDefined();
      expect(identity.did).toMatch(/^did:key:z/);
      expect(identity.kid).toBe(`${identity.did}#${identity.did.replace('did:key:', '')}`);
      expect(identity.privateKey).toMatch(/^[A-Za-z0-9+/=]+$/); // Valid base64 string
      expect(identity.publicKey).toMatch(/^[A-Za-z0-9+/=]+$/); // Valid base64 string
      expect(identity.type).toBe('development');
      expect(identity.createdAt).toBeDefined();
    });

    it('should return same identity on subsequent calls', async () => {
      const identity1 = await provider.getIdentity();
      const identity2 = await provider.getIdentity();

      expect(identity1).toEqual(identity2);
    });

    it('should throw without crypto provider', async () => {
      const providerNoCrypto = new MemoryIdentityProvider();
      await expect(providerNoCrypto.getIdentity()).rejects.toThrow('Crypto provider required');
    });
  });

  describe('saveIdentity', () => {
    it('should save and return the saved identity', async () => {
      const customIdentity = {
        did: 'did:key:zcustom',
        kid: 'did:key:zcustom#zcustom',
        privateKey: 'custom-private',
        publicKey: 'custom-public',
        createdAt: new Date().toISOString(),
        type: 'production' as const,
        metadata: { custom: true }
      };

      await provider.saveIdentity(customIdentity);
      const retrieved = await provider.getIdentity();

      expect(retrieved).toEqual(customIdentity);
    });
  });

  describe('rotateKeys', () => {
    it('should generate new identity', async () => {
      const oldIdentity = await provider.getIdentity();
      // Change the mock to return different keys for rotation
      cryptoProvider.keyPairResult = {
        privateKey: 'cm90YXRlZC1wcml2YXRlLWtleQ==', // base64 of "rotated-private-key"
        publicKey: 'cm90YXRlZC1wdWJsaWMta2V5', // base64 of "rotated-public-key"
      };
      const newIdentity = await provider.rotateKeys();

      expect(newIdentity.did).not.toBe(oldIdentity.did);
      expect(newIdentity.privateKey).toMatch(/^[A-Za-z0-9+/=]+$/); // Valid base64 string
      expect(newIdentity.publicKey).toMatch(/^[A-Za-z0-9+/=]+$/); // Valid base64 string
    });

    it('should return new identity on subsequent calls', async () => {
      const oldIdentity = await provider.getIdentity();
      // Change the mock to return different keys for rotation
      cryptoProvider.keyPairResult = {
        privateKey: 'cm90YXRlZC1wcml2YXRlLWtleQ==',
        publicKey: 'cm90YXRlZC1wdWJsaWMta2V5',
      };
      await provider.rotateKeys();
      const currentIdentity = await provider.getIdentity();

      expect(currentIdentity.did).not.toBe(oldIdentity.did);
    });

    it('should throw without crypto provider', async () => {
      const providerNoCrypto = new MemoryIdentityProvider();
      await expect(providerNoCrypto.rotateKeys()).rejects.toThrow('Crypto provider required');
    });
  });

  describe('deleteIdentity', () => {
    it('should delete existing identity', async () => {
      const identity = await provider.getIdentity();
      // Change mock keys so regenerated identity differs
      cryptoProvider.keyPairResult = {
        privateKey: 'ZGVsZXRlZC1wcml2YXRlLWtleQ==', // base64 of "deleted-private-key"
        publicKey: 'ZGVsZXRlZC1wdWJsaWMta2V5', // base64 of "deleted-public-key"
      };
      await provider.deleteIdentity();

      // Should generate new identity after deletion
      const newIdentity = await provider.getIdentity();
      expect(newIdentity.did).not.toBe(identity.did);
    });

    it('should handle deleting when no identity exists', async () => {
      await expect(provider.deleteIdentity()).resolves.toBeUndefined();
    });
  });

  describe('DID generation', () => {
    it('should generate consistent DID format', async () => {
      const identity = await provider.getIdentity();
      expect(identity.did).toMatch(/^did:key:z[A-Za-z0-9]+$/);
    });

    it('should generate proper did:key DID from public key', async () => {
      const identity = await provider.getIdentity();
      // The DID should start with did:key:z (multibase base58btc prefix)
      expect(identity.did).toMatch(/^did:key:z/);
      // DID should be longer than just the prefix (base58btc encoded Ed25519 multicodec + key)
      expect(identity.did.length).toBeGreaterThan(10);
    });
  });
});
