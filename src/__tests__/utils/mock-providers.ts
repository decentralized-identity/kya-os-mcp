/**
 * Mock Provider Implementations for Testing
 *
 * Provides controllable mock versions of all provider abstract classes.
 */

import { vi } from 'vitest';
import {
  CryptoProvider,
  ClockProvider,
  FetchProvider,
  StorageProvider,
  NonceCacheProvider,
  IdentityProvider,
  type AgentIdentity,
} from '../../providers/base.js';
import type { DIDDocument } from '../../delegation/vc-verifier.js';
import type { StatusList2021Credential, DelegationRecord } from '../../types/protocol.js';

/**
 * Mock Crypto Provider
 */
export class MockCryptoProvider extends CryptoProvider {
  public signResult = new Uint8Array([1, 2, 3, 4]);
  public verifyResult = true;
  public hashResult = 'sha256:mock-hash';
  public keyPairResult = {
    privateKey: 'bW9jay1wcml2YXRlLWtleQ==', // base64 of "mock-private-key"
    publicKey: 'bW9jay1wdWJsaWMta2V5', // base64 of "mock-public-key"
  };

  async sign(_data: Uint8Array, _privateKey: string): Promise<Uint8Array> {
    return this.signResult;
  }

  async verify(
    _data: Uint8Array,
    _signature: Uint8Array,
    _publicKey: string
  ): Promise<boolean> {
    return this.verifyResult;
  }

  async generateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    return this.keyPairResult;
  }

  async hash(_data: Uint8Array): Promise<string> {
    return this.hashResult;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Uint8Array(length).fill(42);
  }
}

/**
 * Mock Clock Provider
 */
export class MockClockProvider extends ClockProvider {
  private currentTime: number = Date.now();

  setTime(time: number): void {
    this.currentTime = time;
  }

  advance(ms: number): void {
    this.currentTime += ms;
  }

  now(): number {
    return this.currentTime;
  }

  isWithinSkew(timestamp: number, skewSeconds: number): boolean {
    const skewMs = skewSeconds * 1000;
    return Math.abs(this.currentTime - timestamp) <= skewMs;
  }

  hasExpired(expiresAt: number): boolean {
    return this.currentTime > expiresAt;
  }

  calculateExpiry(ttlSeconds: number): number {
    return this.currentTime + ttlSeconds * 1000;
  }

  format(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
}

/**
 * Mock Fetch Provider
 */
export class MockFetchProvider extends FetchProvider {
  private didDocuments = new Map<string, DIDDocument>();
  private statusLists = new Map<string, StatusList2021Credential>();
  private delegationChains = new Map<string, DelegationRecord[]>();
  public fetch: (url: string, options?: unknown) => Promise<Response>;

  constructor() {
    super();
    this.fetch = vi.fn(
      async (url: string, _options?: unknown): Promise<Response> => {
        return new Response(JSON.stringify({ url }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    ) as (url: string, options?: unknown) => Promise<Response>;
  }

  setDIDDocument(did: string, doc: DIDDocument): void {
    this.didDocuments.set(did, doc);
  }

  setStatusList(url: string, list: StatusList2021Credential): void {
    this.statusLists.set(url, list);
  }

  setDelegationChain(id: string, chain: DelegationRecord[]): void {
    this.delegationChains.set(id, chain);
  }

  async resolveDID(did: string): Promise<DIDDocument | null> {
    return this.didDocuments.get(did) ?? null;
  }

  async fetchStatusList(url: string): Promise<StatusList2021Credential | null> {
    return this.statusLists.get(url) ?? null;
  }

  async fetchDelegationChain(id: string): Promise<DelegationRecord[]> {
    return this.delegationChains.get(id) ?? [];
  }
}

/**
 * Mock Storage Provider
 */
export class MockStorageProvider extends StorageProvider {
  private store: Map<string, string> = new Map();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async set(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }

  async list(prefix?: string): Promise<string[]> {
    const keys = Array.from(this.store.keys());
    if (prefix) {
      return keys.filter((k) => k.startsWith(prefix));
    }
    return keys;
  }

  clear(): void {
    this.store.clear();
  }
}

/**
 * Mock Nonce Cache Provider
 */
export class MockNonceCacheProvider extends NonceCacheProvider {
  private nonces: Map<string, number> = new Map();
  public cleanupCalled = false;
  public destroyCalled = false;
  private clock?: ClockProvider;

  setClock(clock: ClockProvider): void {
    this.clock = clock;
  }

  async consume(nonce: string, ttlSeconds: number, agentDid?: string): Promise<boolean> {
    const key = agentDid ? `nonce:${agentDid}:${nonce}` : `nonce:${nonce}`;
    const now = this.clock ? this.clock.now() : Date.now();
    const expiry = this.nonces.get(key);
    if (expiry !== undefined && expiry > now) return false;
    this.nonces.set(key, now + ttlSeconds * 1000);
    return true;
  }

  async has(nonce: string, agentDid?: string): Promise<boolean> {
    const key = agentDid ? `nonce:${agentDid}:${nonce}` : `nonce:${nonce}`;
    const expiry = this.nonces.get(key);
    if (!expiry) return false;

    const now = this.clock ? this.clock.now() : Date.now();
    if (now > expiry) {
      this.nonces.delete(key);
      return false;
    }

    return true;
  }

  async add(
    nonce: string,
    ttlSeconds: number,
    agentDid?: string
  ): Promise<void> {
    const key = agentDid ? `nonce:${agentDid}:${nonce}` : `nonce:${nonce}`;
    const now = this.clock ? this.clock.now() : Date.now();
    const expiresAt = now + ttlSeconds * 1000;
    this.nonces.set(key, expiresAt);
  }

  async cleanup(): Promise<void> {
    this.cleanupCalled = true;
    const now = this.clock ? this.clock.now() : Date.now();
    for (const [nonce, expiry] of this.nonces) {
      if (now > expiry) {
        this.nonces.delete(nonce);
      }
    }
  }

  async destroy(): Promise<void> {
    this.destroyCalled = true;
    this.nonces.clear();
  }

  clear(): void {
    this.nonces.clear();
  }

  size(): number {
    return this.nonces.size;
  }
}

/**
 * Mock Identity Provider
 */
export class MockIdentityProvider extends IdentityProvider {
  private identity?: AgentIdentity;
  public rotateKeysCalled = false;
  public deleteIdentityCalled = false;
  private rotateCount = 0;

  constructor(identity?: AgentIdentity) {
    super();
    this.identity = identity;
  }

  async getIdentity(): Promise<AgentIdentity> {
    if (!this.identity) {
      this.identity = {
        did: 'did:key:zmock123',
        kid: 'did:key:zmock123#zmock123',
        privateKey: 'mock-private-key',
        publicKey: 'mock-public-key',
        createdAt: new Date().toISOString(),
        type: 'development',
        metadata: { mock: true },
      };
    }
    return this.identity;
  }

  async saveIdentity(identity: AgentIdentity): Promise<void> {
    this.identity = identity;
  }

  async rotateKeys(): Promise<AgentIdentity> {
    this.rotateKeysCalled = true;
    this.rotateCount++;
    this.identity = {
      did: `did:key:zmock456-${this.rotateCount}`,
      kid: `did:key:zmock456-${this.rotateCount}#zmock456-${this.rotateCount}`,
      privateKey: `mock-private-key-rotated-${this.rotateCount}`,
      publicKey: `mock-public-key-rotated-${this.rotateCount}`,
      createdAt: new Date().toISOString(),
      type: 'development',
      metadata: {
        mock: true,
        rotated: true,
        rotateCount: this.rotateCount,
      },
    };
    return this.identity;
  }

  async deleteIdentity(): Promise<void> {
    this.deleteIdentityCalled = true;
    this.identity = undefined;
  }

  setIdentity(identity: AgentIdentity): void {
    this.identity = identity;
  }
}

/**
 * Create a full set of mock providers for testing
 */
export function createMockProviders() {
  const cryptoProvider = new MockCryptoProvider();
  const clockProvider = new MockClockProvider();
  const fetchProvider = new MockFetchProvider();
  const storageProvider = new MockStorageProvider();
  const nonceCacheProvider = new MockNonceCacheProvider();
  const identityProvider = new MockIdentityProvider();

  nonceCacheProvider.setClock(clockProvider);

  return {
    cryptoProvider,
    clockProvider,
    fetchProvider,
    storageProvider,
    nonceCacheProvider,
    identityProvider,
  };
}
