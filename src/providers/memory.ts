/**
 * Memory-based provider implementations
 *
 * Simple in-memory implementations for development and testing.
 */

import {
  CryptoProvider,
  StorageProvider,
  NonceCacheProvider,
  IdentityProvider,
  type AgentIdentity,
} from './base.js';
import { generateDidKeyFromBase64, didKeyFragment } from '../utils/did-helpers.js';

export class MemoryStorageProvider extends StorageProvider {
  private store: Map<string, string> = new Map();

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
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
}

export class MemoryNonceCacheProvider extends NonceCacheProvider {
  private nonces: Map<string, number> = new Map();

  /** Atomic within this cache instance: no await separates the read and write. */
  async consume(nonce: string, ttlSeconds: number, agentDid?: string): Promise<boolean> {
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
      throw new RangeError('Nonce TTL must be a positive finite number');
    }
    const key = this.key(nonce, agentDid);
    const now = Date.now();
    const expiry = this.nonces.get(key);
    if (expiry !== undefined && expiry > now) return false;
    this.nonces.set(key, now + ttlSeconds * 1000);
    return true;
  }

  private key(nonce: string, agentDid?: string): string {
    return JSON.stringify([agentDid ?? null, nonce]);
  }

  async has(nonce: string, agentDid?: string): Promise<boolean> {
    const key = this.key(nonce, agentDid);
    const expiry = this.nonces.get(key);
    if (!expiry) return false;

    if (Date.now() >= expiry) {
      this.nonces.delete(key);
      return false;
    }

    return true;
  }

  async add(nonce: string, ttlSeconds: number, agentDid?: string): Promise<void> {
    const key = this.key(nonce, agentDid);
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.nonces.set(key, expiresAt);
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [nonce, expiry] of this.nonces) {
      if (now >= expiry) {
        this.nonces.delete(nonce);
      }
    }
  }

  async destroy(): Promise<void> {
    this.nonces.clear();
  }
}

export class MemoryIdentityProvider extends IdentityProvider {
  private identity?: AgentIdentity;
  private cryptoProvider: CryptoProvider | undefined;

  constructor(cryptoProvider?: CryptoProvider) {
    super();
    this.cryptoProvider = cryptoProvider;
  }

  async getIdentity(): Promise<AgentIdentity> {
    if (!this.identity) {
      this.identity = await this.generateIdentity();
    }
    return this.identity;
  }

  async saveIdentity(identity: AgentIdentity): Promise<void> {
    this.identity = identity;
  }

  async rotateKeys(): Promise<AgentIdentity> {
    this.identity = await this.generateIdentity();
    return this.identity;
  }

  async deleteIdentity(): Promise<void> {
    this.identity = undefined;
  }

  private async generateIdentity(): Promise<AgentIdentity> {
    if (!this.cryptoProvider) {
      throw new Error('Crypto provider required for identity generation');
    }

    const keyPair = await this.cryptoProvider.generateKeyPair();
    const did = this.generateDIDFromPublicKey(keyPair.publicKey);

    return {
      did,
      kid: `${did}#${didKeyFragment(did)}`,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      createdAt: new Date().toISOString(),
      type: 'development',
    };
  }

  private generateDIDFromPublicKey(publicKey: string): string {
    return generateDidKeyFromBase64(publicKey);
  }
}
