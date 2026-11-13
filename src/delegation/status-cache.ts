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
 * retries), and `maxStalenessMs <= 0` makes the wrapper a pass-through. The
 * `context` naming the credential's issuer, and its chain's pinned root,
 * reaches the wrapped resolver unchanged and is part of the cache key.
 */
import type { CredentialStatus } from '../types/protocol.js';
import type { StatusCheckContext } from '../utils/statuslist-acceptance.js';
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
    async checkStatus(status: CredentialStatus, context?: StatusCheckContext): Promise<boolean> {
      // The context is part of the key: whether a list may speak for a credential depends on the
      // issuers the context names, so a verdict never crosses credentials that name other issuers.
      // JSON arrays turn undefined into null. Those are not equivalent: a
      // checker may default an omitted purpose but must refuse explicit null.
      // Object members preserve that distinction (omission versus JSON null).
      const key = JSON.stringify({
        url: status.statusListCredential,
        index: status.statusListIndex,
        purpose: status.statusPurpose,
        issuer: context?.credentialIssuer,
        root: context?.trustedRootIssuer,
      });
      const hit = cache.get(key);
      if (hit !== undefined) return hit;
      // A throw propagates uncached — fail-closed deny now, retry next call.
      const revoked = await resolver.checkStatus(status, context);
      cache.set(key, revoked);
      return revoked;
    },
  };
}
