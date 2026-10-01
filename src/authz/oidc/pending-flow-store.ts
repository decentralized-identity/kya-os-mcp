/**
 * PendingFlowStore — the provider seam for in-flight OAuth/OIDC PKCE state.
 *
 * Between {@link GenericOidcAdapter.initiateFlow} (which mints a resume token and
 * the PKCE `codeVerifier`) and the authorization callback (which exchanges the
 * code), the verifier must be held server-side keyed by the resume token — it is
 * never placed on the wire. Holding it in a per-process `Map` breaks the moment a
 * second instance or a restart enters the picture: if the callback lands on
 * another instance the verifier is gone, the token exchange fails closed, and no
 * grant is ever minted.
 *
 * This seam mirrors {@link GrantStore} / `NonceCacheProvider`: the in-memory
 * implementation here is the dev/reference impl; production injects a Redis /
 * Durable Object / database-backed store behind the same interface so
 * `initiateFlow` on instance A and the callback on instance B share one verifier.
 *
 * `get` (non-consuming read) and `delete` (consume) are kept separate so the
 * adapter can preserve its one-time-use ordering: it reads the pending flow,
 * validates `state`, performs the token exchange, and deletes ONLY after the
 * exchange succeeds — so a transient IdP error does not burn the resume token.
 *
 * Production note: a durable backing SHOULD make `delete`-after-exchange atomic
 * (e.g. Redis `GETDEL`, or a compare-and-set) to close the one-time-use replay
 * window across instances.
 */

/** In-flight authorization state held between initiateFlow and the callback. */
export interface PendingFlow {
  agentDid: string;
  scopes: string[];
  state: string;
  codeVerifier: string;
  redirectUri: string;
}

/**
 * Store for pending (awaiting-callback) OAuth/OIDC PKCE flows. Implementations
 * persist a flow under a resume token with a TTL, read it back (non-consuming),
 * consume it after a successful exchange, and sweep expired entries.
 */
export abstract class PendingFlowStore {
  /** Persist (or replace) a pending flow under `token`, expiring after `ttlMs`. */
  abstract put(token: string, flow: PendingFlow, ttlMs: number): Promise<void>;
  /** Read the pending flow without consuming it (e.g. inspection). */
  abstract get(token: string): Promise<PendingFlow | undefined>;
  /**
   * Atomically read AND remove the pending flow — the one-time-use gate for the
   * token exchange. Returns the flow if it existed and was not expired, else
   * undefined; either way the token is gone afterward, so two concurrent
   * callbacks for the same token can never both proceed (closes the replay
   * window). Durable backings (Redis / Durable Object / DB) MUST implement this
   * atomically (e.g. Redis `GETDEL`, or a compare-and-set) — a non-atomic
   * read-then-delete reopens the window across instances.
   */
  abstract consume(token: string): Promise<PendingFlow | undefined>;
  /** Remove a pending flow without reading it. */
  abstract delete(token: string): Promise<void>;
  /** Drop expired entries. */
  abstract cleanup(): Promise<void>;
}

/** Writes between amortised expired-entry sweeps (bounds memory without a timer). */
const SWEEP_EVERY = 1000;
/** Longest the store goes between sweeps while written to, so low traffic also frees memory. */
const SWEEP_INTERVAL_MS = 60_000;

export interface MemoryPendingFlowStoreOptions {
  /** Clock injection for tests; defaults to Date.now. */
  now?: () => number;
}

/**
 * In-memory {@link PendingFlowStore} — the dev/reference implementation.
 *
 * NOT for production: pending flows are lost on restart and are invisible to a
 * sibling instance, so a callback that lands elsewhere cannot complete. Inject a
 * Redis / Durable Object / database-backed store for multi-instance deployments.
 *
 * Most initiated flows are never completed, so expired entries are swept as
 * the store is written to rather than only on a matching read.
 */
export class MemoryPendingFlowStore extends PendingFlowStore {
  private readonly pending = new Map<string, { flow: PendingFlow; expiresAt: number }>();
  private readonly now: () => number;
  private writesSinceSweep = 0;
  private lastSweepAt: number;

  constructor(options: MemoryPendingFlowStoreOptions = {}) {
    super();
    this.now = options.now ?? (() => Date.now());
    this.lastSweepAt = this.now();
  }

  async put(token: string, flow: PendingFlow, ttlMs: number): Promise<void> {
    const now = this.now();
    this.pending.set(token, { flow: { ...flow }, expiresAt: now + ttlMs });
    // Amortised eviction (count or interval, whichever comes first), so
    // abandoned flows cannot accumulate without a scheduled cleanup().
    if (++this.writesSinceSweep >= SWEEP_EVERY || now - this.lastSweepAt >= SWEEP_INTERVAL_MS) {
      this.writesSinceSweep = 0;
      this.lastSweepAt = now;
      this.evictExpired(now);
    }
  }

  async get(token: string): Promise<PendingFlow | undefined> {
    const entry = this.pending.get(token);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.pending.delete(token);
      return undefined;
    }
    return { ...entry.flow };
  }

  async consume(token: string): Promise<PendingFlow | undefined> {
    // get + delete with NO await in between → atomic in single-threaded JS:
    // a second consume() for the same token sees nothing.
    const entry = this.pending.get(token);
    if (!entry) return undefined;
    this.pending.delete(token);
    if (entry.expiresAt <= this.now()) return undefined;
    return { ...entry.flow };
  }

  async delete(token: string): Promise<void> {
    this.pending.delete(token);
  }

  async cleanup(): Promise<void> {
    this.evictExpired(this.now());
  }

  private evictExpired(now: number): void {
    for (const [token, entry] of this.pending) {
      if (entry.expiresAt <= now) this.pending.delete(token);
    }
  }
}
