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
 * retries), nor is an answer that is not a boolean, and `maxStalenessMs: 0` makes the wrapper a pass-through. The
 * `context` naming the credential's issuer, and its chain's pinned root,
 * reaches the wrapped resolver unchanged and is part of the cache key. A call
 * that passes no context, as a wrapper written before the context existed
 * makes, is read under the context its entry carries (`carriedContext`), so it
 * is keyed and passed on as the call that carried it in was. An entry that is
 * not an object is refused as `delegation_malformed`, and the resolver is not
 * asked, so no resolver can accept one.
 */
import type { CredentialStatus } from '../types/protocol.js';
import type { StatusCheckContext } from '../utils/statuslist-acceptance.js';
import { readRevoked } from '../utils/revocation-answer.js';
import { carriedContext, carryingContext } from '../utils/status-check-carrier.js';
import type { StatusListResolver } from './vc-verifier.types.js';
import { TtlCache } from '../utils/ttl-cache.js';
import { cacheCapacityOption, requiredCacheTtlOption } from '../utils/cache-options.js';
import { describeValue } from '../utils/describe-value.js';
import { RefusalError } from '../utils/refusal.js';

export interface StatusCacheOptions {
  /**
   * Upper bound on served staleness, in ms, your declared revocation SLA: a finite number, 0 or
   * more, where `0` disables caching. It has no default. Any other value throws a `TypeError` naming
   * the option.
   */
  maxStalenessMs: number;
  /**
   * Maximum cached entries (FIFO eviction): a whole number greater than 0. Default 1000. Any other
   * value throws a `TypeError` naming the option.
   */
  maxEntries?: number;
}

/** @throws TypeError when `maxStalenessMs` or `maxEntries` is not one it can keep verdicts for. */
export function withStatusCache(
  resolver: StatusListResolver,
  options: StatusCacheOptions,
): StatusListResolver {
  const cache = new TtlCache<boolean>({
    ttlMs: requiredCacheTtlOption(options.maxStalenessMs, 'maxStalenessMs'),
    maxEntries: cacheCapacityOption(options.maxEntries, 'maxEntries') ?? 1000,
  });

  return {
    async checkStatus(status: CredentialStatus, given?: StatusCheckContext): Promise<boolean> {
      const context = given ?? carriedContext(status);
      // An entry that is not an object holds nothing to key a verdict by, and names no list to
      // check, so it is refused here rather than handed to a resolver that might accept it.
      if (typeof status !== 'object' || status === null) {
        throw new RefusalError('delegation_malformed', `the status entry (${describeValue(status)}) is not an object`);
      }
      // The entry's statusSize is part of the key: entries of different sizes at one index keep
      // their status in different bits, so a verdict for one is no answer for the other.
      // The context is part of the key: it decides who keeps the entry's URL (the credential's
      // issuer, or the pinned root when its own credential names that URL), so a verdict is never
      // served to an entry whose keeper may differ.
      // JSON arrays turn undefined into null. Those are not equivalent: a
      // checker may default an omitted purpose but must refuse explicit null.
      // Object members preserve that distinction (omission versus JSON null).
      const key = JSON.stringify({
        url: status.statusListCredential,
        index: status.statusListIndex,
        purpose: status.statusPurpose,
        size: status.statusSize,
        issuer: context?.credentialIssuer,
        root: context?.trustedRootIssuer,
        rootList: context?.trustedRootStatusList,
      });
      const hit = cache.get(key);
      if (hit !== undefined) return hit;
      // A throw propagates uncached — fail-closed deny now, retry next call.
      const revoked = await resolver.checkStatus(carryingContext(status, context), context);
      // An answer that is not a boolean is refused by its reader and, like a throw, is not kept.
      if (readRevoked(revoked) !== undefined) cache.set(key, revoked);
      return revoked;
    },
  };
}
