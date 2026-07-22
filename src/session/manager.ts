/**
 * Session Management — Platform-agnostic Protocol Reference
 *
 * Handles handshake enforcement, session management, and nonce validation
 * according to KYA-OS requirements 4.5–4.9 and 19.1–19.2.
 *
 * Platform adapters inject a CryptoProvider for all random byte generation.
 * The static generateNonce() uses globalThis.crypto (available Node 20+ and
 * Cloudflare Workers) to remain synchronous without platform-specific imports.
 */

import { KYA_OS_ERROR_CODES, type KyaOsErrorCode } from "../errors.js";
import type {
  HandshakeRequest,
  SessionContext,
  NonceCache,
  MetaPolicy,
} from '../types/protocol.js';
import {
  AUTH_NONCE_TTL_MS,
  ANON_NONCE_TTL_MS,
} from '../types/protocol.js';
import type { CryptoProvider } from '../providers/base.js';
import { MemoryNonceCacheProvider } from '../providers/memory.js';
import { SessionStore, MemorySessionStore } from './session-store.js';
import { logger } from '../logging/index.js';

export interface SessionConfig {
  timestampSkewSeconds?: number;
  sessionTtlMinutes?: number;
  absoluteSessionLifetime?: number;
  nonceCache?: NonceCache;
  serverDid?: string;
  /** Maximum number of concurrent sessions. Oldest sessions are evicted when exceeded. Default: 10000 */
  maxSessions?: number;
  /**
   * Optional pluggable session store. Defaults to an in-memory
   * {@link MemorySessionStore} that reproduces the prior single-process
   * behavior. Inject a durable {@link SessionStore} (Redis / Durable Object /
   * DB) to make sessions survive restarts and resolve across instances (enables
   * the wallet-less cross-instance retry + proof-nonce continuity).
   */
  sessionStore?: SessionStore;
  /**
   * Policy for non-KYA-OS `_meta` keys during proof verification (SEP-414).
   * Default 'strict' IGNORES foreign keys (never hashed, trusted, or rejected);
   * 'allow-extensions' surfaces them. Neither rejects coexisting reserved keys
   * such as `io.modelcontextprotocol/*` or `traceparent`. See {@link MetaPolicy}.
   */
  metaPolicy?: MetaPolicy;
}

export interface HandshakeResult {
  success: boolean;
  session?: SessionContext;
  error?: {
    code: KyaOsErrorCode;
    message: string;
    remediation?: string;
  };
}

export class SessionManager {
  private config: Required<Omit<SessionConfig, 'absoluteSessionLifetime' | 'serverDid' | 'maxSessions' | 'metaPolicy' | 'sessionStore'>> & {
    absoluteSessionLifetime?: number;
    serverDid?: string;
    metaPolicy: MetaPolicy;
  };
  private cryptoProvider: CryptoProvider;
  private sessionStore: SessionStore;

  constructor(cryptoProvider: CryptoProvider, config: SessionConfig = {}) {
    this.cryptoProvider = cryptoProvider;
    this.sessionStore =
      config.sessionStore ??
      new MemorySessionStore({ maxSessions: config.maxSessions ?? 10_000 });
    this.config = {
      timestampSkewSeconds: config.timestampSkewSeconds ?? 120,
      sessionTtlMinutes: config.sessionTtlMinutes ?? 30,
      nonceCache: config.nonceCache ?? new MemoryNonceCacheProvider(),
      metaPolicy: config.metaPolicy ?? 'strict',
      ...(config.absoluteSessionLifetime !== undefined && {
        absoluteSessionLifetime: config.absoluteSessionLifetime,
      }),
      ...(config.serverDid !== undefined && { serverDid: config.serverDid }),
    };

    if (this.config.nonceCache instanceof MemoryNonceCacheProvider) {
      logger.warn(
        '[SessionManager] Using MemoryNonceCacheProvider — not suitable for ' +
          'multi-instance deployments. Use Redis, DynamoDB, or Cloudflare KV ' +
          'for production.'
      );
    }
  }

  setServerDid(serverDid: string): void {
    this.config.serverDid = serverDid;
  }

  /**
   * Validate a KYA-OS handshake request and create a session.
   *
   * Performs the following checks:
   * - Timestamp within acceptable skew window
   * - Audience matches server DID (if configured)
   * - Nonce not previously used (replay protection)
   *
   * @param request - The handshake request containing nonce, audience, timestamp, and optional agentDid
   * @returns Result object with success flag, session on success, or error details on failure
   */
  async validateHandshake(request: HandshakeRequest): Promise<HandshakeResult> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const timeDiff = Math.abs(now - request.timestamp);

      if (timeDiff > this.config.timestampSkewSeconds) {
        return {
          success: false,
          error: {
            code: KYA_OS_ERROR_CODES.handshake_failed,
            message: `Timestamp outside acceptable range (±${this.config.timestampSkewSeconds}s)`,
            remediation: `Check NTP sync on client and server. Current server time: ${now}, received: ${request.timestamp}, diff: ${timeDiff}s. Adjust timestampSkewSeconds if needed.`,
          },
        };
      }

      // Validate audience matches this server's DID (SPEC.md §4 MUST)
      if (this.config.serverDid && request.audience !== this.config.serverDid) {
        return {
          success: false,
          error: {
            code: KYA_OS_ERROR_CODES.handshake_failed,
            message: `Audience mismatch: expected ${this.config.serverDid}, got ${request.audience}`,
          },
        };
      }

      const nonceExists = await this.config.nonceCache.has(
        request.nonce,
        request.agentDid
      );
      if (nonceExists) {
        return {
          success: false,
          error: {
            code: KYA_OS_ERROR_CODES.nonce_replay,
            message: 'Nonce already used (replay attack prevention)',
            remediation: 'Generate a new unique nonce for each request',
          },
        };
      }

      // Use different TTLs for anonymous vs authenticated nonces (SPEC.md §5.2)
      const isAnonymous = !request.agentDid;
      const nonceTtlMs = isAnonymous ? ANON_NONCE_TTL_MS : AUTH_NONCE_TTL_MS;
      const nonceTtlSeconds = Math.ceil(nonceTtlMs / 1000);
      await this.config.nonceCache.add(
        request.nonce,
        nonceTtlSeconds,
        request.agentDid
      );

      const sessionId = await this.generateSessionId();
      const clientInfo = await this.buildClientInfo(request);

      const session: SessionContext = {
        sessionId,
        audience: request.audience,
        nonce: request.nonce,
        timestamp: request.timestamp,
        createdAt: now,
        lastActivity: now,
        ttlMinutes: this.config.sessionTtlMinutes,
        identityState: 'anonymous',
        metaPolicy: this.config.metaPolicy,
        agentDid: request.agentDid,
        ...(this.config.serverDid && { serverDid: this.config.serverDid }),
        ...(clientInfo && { clientInfo }),
      };

      await this.sessionStore.set(sessionId, session);

      return { success: true, session };
    } catch (error) {
      return {
        success: false,
        error: {
          code: KYA_OS_ERROR_CODES.handshake_failed,
          message: `Handshake validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
      };
    }
  }

  /**
   * Retrieve a session by ID, checking for expiration.
   *
   * Updates lastActivity timestamp on successful retrieval (sliding window expiry).
   * Returns null if session doesn't exist, has exceeded idle TTL, or has exceeded
   * absolute lifetime (if configured).
   *
   * @param sessionId - The session ID (e.g., "kyaos_...")
   * @returns Session context if valid, null if expired or not found
   */
  async getSession(sessionId: string): Promise<SessionContext | null> {
    const session = await this.sessionStore.get(sessionId);
    if (!session) return null;

    const now = Math.floor(Date.now() / 1000);
    const idleTimeSeconds = now - session.lastActivity;
    const maxIdleSeconds = session.ttlMinutes * 60;

    if (idleTimeSeconds > maxIdleSeconds) {
      await this.sessionStore.delete(sessionId);
      return null;
    }

    if (this.config.absoluteSessionLifetime !== undefined) {
      const sessionAgeSeconds = now - session.createdAt;
      const maxAgeSeconds = this.config.absoluteSessionLifetime * 60;
      if (sessionAgeSeconds > maxAgeSeconds) {
        await this.sessionStore.delete(sessionId);
        return null;
      }
    }

    session.lastActivity = now;
    await this.sessionStore.set(sessionId, session);
    return session;
  }

  private async generateSessionId(): Promise<string> {
    const bytes = await this.cryptoProvider.randomBytes(16);
    bytes[6] = (bytes[6]! & 0x0f) | 0x40;
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
    return `kyaos_${uuid}`;
  }

  private async generateClientId(): Promise<string> {
    const bytes = await this.cryptoProvider.randomBytes(6);
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return `client_${hex}`;
  }

  private normalizeClientInfoString(value: unknown): string | undefined {
    if (typeof value !== 'string') return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  private async buildClientInfo(
    request: HandshakeRequest
  ): Promise<SessionContext['clientInfo'] | undefined> {
    const hasMetadata =
      !!request.clientInfo ||
      typeof request.clientProtocolVersion === 'string' ||
      request.clientCapabilities !== undefined;

    if (!hasMetadata) return undefined;

    const source = request.clientInfo;

    return {
      name: this.normalizeClientInfoString(source?.name) ?? 'unknown',
      title: this.normalizeClientInfoString(source?.title),
      version: this.normalizeClientInfoString(source?.version),
      platform: this.normalizeClientInfoString(source?.platform),
      vendor: this.normalizeClientInfoString(source?.vendor),
      persistentId: this.normalizeClientInfoString(source?.persistentId),
      clientId:
        this.normalizeClientInfoString(source?.clientId) ??
        (await this.generateClientId()),
      protocolVersion: this.normalizeClientInfoString(request.clientProtocolVersion),
      capabilities: request.clientCapabilities,
    };
  }

  static generateNonce(): string {
    const buffer = new Uint8Array(16);
    globalThis.crypto.getRandomValues(buffer);
    let binaryStr = '';
    for (let i = 0; i < buffer.length; i++) {
      binaryStr += String.fromCharCode(buffer[i]!);
    }
    return btoa(binaryStr)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  async cleanup(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    for (const [sessionId, session] of await this.sessionStore.entries()) {
      const idleTimeSeconds = now - session.lastActivity;
      const maxIdleSeconds = session.ttlMinutes * 60;
      let expired = idleTimeSeconds > maxIdleSeconds;

      if (!expired && this.config.absoluteSessionLifetime !== undefined) {
        const sessionAgeSeconds = now - session.createdAt;
        const maxAgeSeconds = this.config.absoluteSessionLifetime * 60;
        expired = sessionAgeSeconds > maxAgeSeconds;
      }

      if (expired) {
        await this.sessionStore.delete(sessionId);
      }
    }

    await this.sessionStore.cleanup();
    await this.config.nonceCache.cleanup();
  }

  getStats(): {
    activeSessions: number;
    config: {
      timestampSkewSeconds: number;
      sessionTtlMinutes: number;
      absoluteSessionLifetime?: number;
      cacheType: string;
    };
  } {
    return {
      activeSessions: this.sessionStore.size(),
      config: {
        timestampSkewSeconds: this.config.timestampSkewSeconds,
        sessionTtlMinutes: this.config.sessionTtlMinutes,
        absoluteSessionLifetime: this.config.absoluteSessionLifetime,
        cacheType: this.config.nonceCache.constructor.name,
      },
    };
  }

  async clearSessions(): Promise<void> {
    await this.sessionStore.clear();
  }
}

export function createHandshakeRequest(audience: string): HandshakeRequest {
  return {
    nonce: SessionManager.generateNonce(),
    audience,
    timestamp: Math.floor(Date.now() / 1000),
  };
}

export function validateHandshakeFormat(request: unknown): request is HandshakeRequest {
  return (
    typeof request === 'object' &&
    request !== null &&
    typeof (request as Record<string, unknown>)['nonce'] === 'string' &&
    ((request as Record<string, unknown>)['nonce'] as string).length > 0 &&
    typeof (request as Record<string, unknown>)['audience'] === 'string' &&
    ((request as Record<string, unknown>)['audience'] as string).length > 0 &&
    typeof (request as Record<string, unknown>)['timestamp'] === 'number' &&
    ((request as Record<string, unknown>)['timestamp'] as number) > 0 &&
    Number.isInteger((request as Record<string, unknown>)['timestamp'])
  );
}
