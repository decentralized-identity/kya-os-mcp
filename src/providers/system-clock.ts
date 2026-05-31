/**
 * System ClockProvider
 *
 * Wall-clock `ClockProvider` backed by `Date.now()`. The default clock for any
 * runtime with a trustworthy system time — pair it with `ProofVerifier`,
 * `SessionManager`, or anything else that needs a clock.
 *
 * For deterministic tests, supply your own controllable `ClockProvider` instead.
 *
 * @example
 * ```typescript
 * import { ProofVerifier, SystemClockProvider, NodeCryptoProvider } from '@kya-os/mcp';
 *
 * const verifier = new ProofVerifier({
 *   cryptoProvider: new NodeCryptoProvider(),
 *   clockProvider: new SystemClockProvider(),
 *   // ...nonceCacheProvider, fetchProvider
 * });
 * ```
 */

import { ClockProvider } from "./base.js";

export class SystemClockProvider extends ClockProvider {
  /** Current time as a millisecond epoch timestamp. */
  now(): number {
    return Date.now();
  }

  /**
   * True if `timestamp` is within ±`skewSeconds` of now.
   *
   * Note: `timestamp` is MILLISECONDS — `ProofVerifier` calls this with
   * `proof.meta.ts * 1000` (proof timestamps are in seconds).
   */
  isWithinSkew(timestamp: number, skewSeconds: number): boolean {
    return Math.abs(Date.now() - timestamp) <= skewSeconds * 1000;
  }

  /** True once now is strictly past `expiresAt` (ms epoch). */
  hasExpired(expiresAt: number): boolean {
    return Date.now() > expiresAt;
  }

  /** Absolute ms-epoch expiry for a relative TTL in seconds. */
  calculateExpiry(ttlSeconds: number): number {
    return Date.now() + ttlSeconds * 1000;
  }

  /** ISO-8601 rendering of a ms-epoch timestamp. */
  format(timestamp: number): string {
    return new Date(timestamp).toISOString();
  }
}
