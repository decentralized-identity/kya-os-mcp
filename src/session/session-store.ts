/**
 * SessionStore — the optional provider seam for KYA-OS session persistence.
 *
 * The KYA-OS session is a convenience layer (a stable context for proof-nonce
 * generation and wallet-less `getBySession` grant resolution), NOT the durable
 * authority — that is the per-request holder-of-key proof (§7) and the
 * DID-anchored grant (§6). So this seam is OPTIONAL: it defaults to an in-memory
 * implementation wrapping a Map, exactly reproducing the prior single-process
 * behavior. Inject a Redis / Durable Object / database-backed store to make
 * sessions (and therefore the wallet-less cross-instance retry and proof-nonce
 * continuity) survive restarts and resolve across load-balanced instances —
 * mirroring the {@link NonceCacheProvider} / GrantStore precedent.
 *
 * Expiry POLICY (idle TTL, absolute lifetime) lives in the SessionManager, which
 * owns the session config; the store is plain persistence. The manager sweeps
 * expired records by iterating {@link SessionStore.entries} and deleting them, so
 * a durable backing MAY instead rely on a backend TTL and return `[]` from
 * `entries()`.
 */

import type { SessionContext } from '../types/protocol.js';

/**
 * Persistence seam for KYA-OS sessions. Implementations store a session by id,
 * read it back, delete it, enumerate for the manager's TTL sweep, and report a
 * best-effort count.
 */
export abstract class SessionStore {
  /** Read a session by id, or undefined if absent. */
  abstract get(sessionId: string): Promise<SessionContext | undefined>;
  /** Persist (or replace) a session. Implementations enforce their own capacity. */
  abstract set(sessionId: string, session: SessionContext): Promise<void>;
  /** Delete a session by id. */
  abstract delete(sessionId: string): Promise<void>;
  /**
   * Snapshot of all (sessionId, session) entries — the SessionManager's TTL
   * sweep iterates this. Durable backings that rely on a backend TTL MAY return
   * an empty array.
   */
  abstract entries(): Promise<Array<[string, SessionContext]>>;
  /** Maintenance hook (e.g. compact bookkeeping / drop expired). */
  abstract cleanup(): Promise<void>;
  /** Remove all sessions (admin / test reset). */
  abstract clear(): Promise<void>;
  /**
   * Best-effort current count for diagnostics: exact for the in-memory impl,
   * a last-known/approximate value for durable backings.
   */
  abstract size(): number;
}

export interface MemorySessionStoreOptions {
  /**
   * Maximum concurrent sessions. The oldest (by insertion order) are evicted
   * when the limit is reached, matching the prior SessionManager behavior.
   * Default: 10000.
   */
  maxSessions?: number;
}

/**
 * In-memory {@link SessionStore} — the dev/reference implementation, wrapping a
 * Map plus insertion-order eviction. This is the default and reproduces the
 * prior single-process session behavior bit-for-bit. NOT for multi-instance
 * deployments: sessions are lost on restart and not shared across instances.
 */
export class MemorySessionStore extends SessionStore {
  private readonly sessions = new Map<string, SessionContext>();
  private insertionOrder: string[] = [];
  private readonly maxSessions: number;

  constructor(options: MemorySessionStoreOptions = {}) {
    super();
    this.maxSessions = options.maxSessions ?? 10_000;
  }

  async get(sessionId: string): Promise<SessionContext | undefined> {
    return this.sessions.get(sessionId);
  }

  async set(sessionId: string, session: SessionContext): Promise<void> {
    if (!this.sessions.has(sessionId)) {
      this.evictIfNeeded();
      this.insertionOrder.push(sessionId);
    }
    this.sessions.set(sessionId, session);
  }

  async delete(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);
    // insertionOrder is compacted lazily in cleanup()/evictIfNeeded — a deleted
    // id left behind is simply skipped, never resurrected.
  }

  async entries(): Promise<Array<[string, SessionContext]>> {
    return [...this.sessions.entries()];
  }

  async cleanup(): Promise<void> {
    this.insertionOrder = this.insertionOrder.filter((id) => this.sessions.has(id));
  }

  async clear(): Promise<void> {
    this.sessions.clear();
    this.insertionOrder = [];
  }

  size(): number {
    return this.sessions.size;
  }

  /** Evict oldest sessions (insertion order) until below capacity. */
  private evictIfNeeded(): void {
    while (this.sessions.size >= this.maxSessions && this.insertionOrder.length > 0) {
      const oldest = this.insertionOrder.shift();
      // Skip ids already deleted; only a live id counts as an eviction.
      if (oldest !== undefined) this.sessions.delete(oldest);
    }
  }
}
