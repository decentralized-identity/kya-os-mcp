/**
 * Tests for Base Provider Classes
 *
 * These tests verify that the abstract base classes are properly defined
 * and that implementations must provide all required methods.
 */

import { describe, it, expect } from 'vitest';
import {
  CryptoProvider,
  ClockProvider,
  FetchProvider,
  StorageProvider,
  NonceCacheProvider,
  IdentityProvider
} from '../../providers/base.js';

describe('Base Provider Classes', () => {
  describe('CryptoProvider', () => {
    it('should be defined as a class', () => {
      expect(CryptoProvider).toBeDefined();
      expect(typeof CryptoProvider).toBe('function');
    });

    it('should require implementation of abstract methods', () => {
      // TypeScript abstract methods don't exist at runtime
      // They're enforced at compile-time, not runtime
      class TestCrypto extends CryptoProvider {}
      const instance = new TestCrypto();

      // These methods are undefined because they're abstract
      expect(instance.sign).toBeUndefined();
      expect(instance.verify).toBeUndefined();
      expect(instance.generateKeyPair).toBeUndefined();
      expect(instance.hash).toBeUndefined();
      expect(instance.randomBytes).toBeUndefined();
    });

    it('should work when properly implemented', async () => {
      class TestCrypto extends CryptoProvider {
        async sign(data: Uint8Array, privateKey: string): Promise<Uint8Array> {
          return new Uint8Array([1, 2, 3]);
        }
        async verify(data: Uint8Array, signature: Uint8Array, publicKey: string): Promise<boolean> {
          return true;
        }
        async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
          return { privateKey: 'test-private', publicKey: 'test-public' };
        }
        async hash(data: Uint8Array): Promise<Uint8Array> {
          return new Uint8Array([4, 5, 6]);
        }
        async randomBytes(length: number): Promise<Uint8Array> {
          return new Uint8Array(length);
        }
      }

      const instance = new TestCrypto();
      expect(await instance.sign(new Uint8Array(), '')).toEqual(new Uint8Array([1, 2, 3]));
      expect(await instance.verify(new Uint8Array(), new Uint8Array(), '')).toBe(true);
      expect(await instance.generateKeyPair()).toEqual({ privateKey: 'test-private', publicKey: 'test-public' });
      expect(await instance.hash(new Uint8Array())).toEqual(new Uint8Array([4, 5, 6]));
      expect(await instance.randomBytes(5)).toHaveLength(5);
    });
  });

  describe('ClockProvider', () => {
    it('should be defined as a class', () => {
      expect(ClockProvider).toBeDefined();
      expect(typeof ClockProvider).toBe('function');
    });

    it('should require implementation of abstract methods', () => {
      class TestClock extends ClockProvider {}
      const instance = new TestClock();

      expect(instance.now).toBeUndefined();
      expect(instance.isWithinSkew).toBeUndefined();
      expect(instance.hasExpired).toBeUndefined();
      expect(instance.calculateExpiry).toBeUndefined();
      expect(instance.format).toBeUndefined();
    });
  });

  describe('FetchProvider', () => {
    it('should be defined as a class', () => {
      expect(FetchProvider).toBeDefined();
      expect(typeof FetchProvider).toBe('function');
    });

    it('should require implementation of abstract methods', () => {
      class TestFetch extends FetchProvider {}
      const instance = new TestFetch();

      expect(instance.resolveDID).toBeUndefined();
      expect(instance.fetchStatusList).toBeUndefined();
      expect(instance.fetchDelegationChain).toBeUndefined();
      expect(instance.fetch).toBeUndefined();
    });
  });

  describe('StorageProvider', () => {
    it('should be defined as a class', () => {
      expect(StorageProvider).toBeDefined();
      expect(typeof StorageProvider).toBe('function');
    });

    it('should require implementation of abstract methods', () => {
      class TestStorage extends StorageProvider {}
      const instance = new TestStorage();

      expect(instance.get).toBeUndefined();
      expect(instance.set).toBeUndefined();
      expect(instance.delete).toBeUndefined();
      expect(instance.exists).toBeUndefined();
      expect(instance.list).toBeUndefined();
    });
  });

  describe('NonceCacheProvider', () => {
    it('should be defined as a class', () => {
      expect(NonceCacheProvider).toBeDefined();
      expect(typeof NonceCacheProvider).toBe('function');
    });

    it('should require implementation of abstract methods', () => {
      class TestNonceCache extends NonceCacheProvider {}
      const instance = new TestNonceCache();

      expect(instance.consume).toBeUndefined();
      expect(instance.has).toBeUndefined();
      expect(instance.add).toBeUndefined();
      expect(instance.cleanup).toBeUndefined();
      expect(instance.destroy).toBeUndefined();
    });
  });

  describe('IdentityProvider', () => {
    it('should be defined as a class', () => {
      expect(IdentityProvider).toBeDefined();
      expect(typeof IdentityProvider).toBe('function');
    });

    it('should require implementation of abstract methods', () => {
      class TestIdentity extends IdentityProvider {}
      const instance = new TestIdentity();

      expect(instance.getIdentity).toBeUndefined();
      expect(instance.saveIdentity).toBeUndefined();
      expect(instance.rotateKeys).toBeUndefined();
      expect(instance.deleteIdentity).toBeUndefined();
    });
  });

  describe('AgentIdentity interface', () => {
    it('should have proper type structure', () => {
      const validIdentity = {
        did: 'did:key:z123',
        kid: 'did:key:z123#z123',
        privateKey: 'private-key',
        publicKey: 'public-key',
        createdAt: new Date().toISOString(),
        type: 'development' as const,
        metadata: { foo: 'bar' }
      };

      // Type checking is done at compile time
      // This test just verifies the shape is correct
      expect(validIdentity.did).toBe('did:key:z123');
      expect(validIdentity.type).toBe('development');
      expect(validIdentity.metadata).toEqual({ foo: 'bar' });
    });
  });
});
