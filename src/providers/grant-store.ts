/**
 * GrantStore — the provider seam for an approved authorization grant.
 *
 * Where {@link ResumeTokenStore} holds a *pending* authorization challenge
 * (token → {agentDid, scopes}, awaiting approval), a GrantStore holds the
 * *approved* result one lifecycle step later: a durable grant bound to the
 * agent DID, optionally bound to a session for a no-paste retry.
 *
 * Layering this seam makes explicit:
 *   - the durable authority is the grant, anchored to the **agent DID** (and,
 *     when known, the user DID) — portable across sessions and instances;
 *   - the **session** binding is a transport convenience for wallet-less
 *     clients, and is confused-deputy-safe: a grant bound to one session is
 *     never returned to another;
 *   - the store is pluggable. The in-memory implementation here is the
 *     dev/reference impl; production injects Redis, a Durable Object, or a
 *     database behind the same interface (mirroring {@link NonceCacheProvider}).
 *
 * A grant is the convenience cache of authority, not the authority's proof:
 * possession is still proven per request by the agent's detached-JWS signature
 * over the request (holder-of-key). Storing a grant never substitutes for that.
 */

export interface Grant {
  /** Stable id for this grant (used for revocation). */
  id: string;
  /** The agent the grant authorizes — the durable binding key. */
  agentDid: string;
  /** The user on whose behalf the agent acts, when known. */
  userDid?: string;
  /** The scopes granted. */
  scopes: string[];
  /**
   * The session that approved this grant, when known. Enables the no-paste
   * retry: a later call from the same session resolves the grant with no token.
   * A grant bound to one session is never returned to another.
   */
  sessionId?: string;
  /** The authorization method that produced the grant. */
  authorization?: { type: string; provider?: string };
  /** The delegation credential (VC-JWT), when one was minted. */
  credentialJwt?: string;
  /** When the grant was issued (ms epoch). */
  issuedAt: number;
  /** When the grant expires (ms epoch); omitted means no expiry. */
  expiresAt?: number;
  /** Lifecycle status. Revocation is soft — the record is retained. */
  status: 'active' | 'expired' | 'revoked';
  /** Why the grant was revoked, when applicable. */
  revocationReason?: string;
}

/**
 * Store for approved authorization grants. Implementations bind a grant,
 * resolve active grants by agent DID or by session, and soft-revoke.
 */
export abstract class GrantStore {
  /** Persist (or replace) a grant. */
  abstract bind(grant: Grant): Promise<void>;
  /** Active grants for an agent DID, optionally narrowed to required scopes. */
  abstract getByAgent(agentDid: string, requiredScopes?: string[]): Promise<Grant[]>;
  /** Active grants bound to a session, optionally narrowed to required scopes. */
  abstract getBySession(sessionId: string, requiredScopes?: string[]): Promise<Grant[]>;
  /** A grant by id regardless of status (returns revoked/expired records too). */
  abstract getById(id: string): Promise<Grant | undefined>;
  /** Soft-revoke a grant: mark revoked with a reason; do not delete. */
  abstract revoke(id: string, reason?: string): Promise<void>;
  /** Drop expired records. */
  abstract cleanup(): Promise<void>;
}

export interface MemoryGrantStoreOptions {
  /** Clock injection for tests; defaults to Date.now. */
  now?: () => number;
}

/**
 * In-memory {@link GrantStore} — the dev/reference implementation.
 *
 * NOT for production: grants are lost on restart and do not scale past a single
 * process. Inject a Redis / Durable Object / database-backed store instead. A
 * runtime warning is emitted when this is used as a session manager's store
 * (see SessionManager), matching the NonceCacheProvider precedent.
 */
export class MemoryGrantStore extends GrantStore {
  private readonly grants = new Map<string, Grant>();
  private readonly now: () => number;

  constructor(options: MemoryGrantStoreOptions = {}) {
    super();
    this.now = options.now ?? (() => Date.now());
  }

  async bind(grant: Grant): Promise<void> {
    this.grants.set(grant.id, { ...grant });
  }

  async getByAgent(agentDid: string, requiredScopes?: string[]): Promise<Grant[]> {
    return this.activeGrants().filter(
      (g) => g.agentDid === agentDid && this.coversScopes(g, requiredScopes),
    );
  }

  async getBySession(sessionId: string, requiredScopes?: string[]): Promise<Grant[]> {
    return this.activeGrants().filter(
      (g) => g.sessionId === sessionId && this.coversScopes(g, requiredScopes),
    );
  }

  async getById(id: string): Promise<Grant | undefined> {
    const grant = this.grants.get(id);
    return grant ? { ...grant } : undefined;
  }

  async revoke(id: string, reason?: string): Promise<void> {
    const grant = this.grants.get(id);
    if (!grant) return;
    grant.status = 'revoked';
    if (reason !== undefined) grant.revocationReason = reason;
  }

  async cleanup(): Promise<void> {
    const now = this.now();
    for (const [id, grant] of this.grants) {
      if (grant.expiresAt !== undefined && grant.expiresAt <= now) {
        this.grants.delete(id);
      }
    }
  }

  /** Active = not revoked and not past expiry. */
  private activeGrants(): Grant[] {
    const now = this.now();
    const out: Grant[] = [];
    for (const grant of this.grants.values()) {
      if (grant.status === 'revoked') continue;
      if (grant.expiresAt !== undefined && grant.expiresAt <= now) continue;
      out.push({ ...grant });
    }
    return out;
  }

  private coversScopes(grant: Grant, requiredScopes?: string[]): boolean {
    if (!requiredScopes || requiredScopes.length === 0) return true;
    return requiredScopes.every((s) => grant.scopes.includes(s));
  }
}
