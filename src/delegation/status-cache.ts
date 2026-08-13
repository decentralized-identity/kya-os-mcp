/**
 * `withStatusCache` — an EXPLICIT staleness knob for revocation checks.
 *
 * The delegation verifier consults `StatusListResolver.checkStatus` on every
 * verification (the 2026-08-12 fail-open fix): freshness policy belongs HERE,
 * at the resolver, where the deployment declares it — never in a silent
 * verdict cache. This wrapper caches status BITS for a bounded, named
 * `maxStalenessMs`, so "how stale may revocation data be?" is a deployment
 * decision with a number attached — the same trade the old verdict cache made
 * silently, now scoped to status data only and signed off by name.
 *
 * Fail-closed is preserved: a resolver THROW is never cached (the next call
 * retries), and `maxStalenessMs <= 0` makes the wrapper a pass-through.
 */
import type { CredentialStatus } from '../types/protocol.js';
import type { StatusListResolver } from './vc-verifier.types.js';
import { TtlCache } from '../utils/ttl-cache.js';

export interface StatusCacheOptions {
  /** Upper bound on served staleness, in ms — your declared revocation SLA. `<= 0` disables caching. */
  maxStalenessMs: number;
  /** Maximum cached entries (FIFO eviction). Default 1000. */
  maxEntries?: number;
}

export function withStatusCache(
  resolver: StatusListResolver,
  options: StatusCacheOptions,
): StatusListResolver {
  const cache = new TtlCache<boolean>({
    ttlMs: options.maxStalenessMs,
    maxEntries: options.maxEntries ?? 1000,
  });

  return {
    async checkStatus(status: CredentialStatus): Promise<boolean> {
      const key = `${status.statusListCredential}\0${status.statusListIndex}\0${status.statusPurpose}`;
      const hit = cache.get(key);
      if (hit !== undefined) return hit;
      // A throw propagates uncached — fail-closed deny now, retry next call.
      const revoked = await resolver.checkStatus(status);
      cache.set(key, revoked);
      return revoked;
    },
  };
}
