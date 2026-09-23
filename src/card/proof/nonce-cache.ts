/**
 * KYA-OS Entity Card — batteries-included replay defense for `org.kya-os/proof.v1`.
 *
 * The {@link ConsumeNonceIfFresh} seam is security-critical: it MUST be an ATOMIC test-AND-set
 * (record the nonce AND report whether it was already seen, in one step). Hand-rolling it is the
 * documented footgun — so this module ships the two implementations a developer should reach for:
 *
 *   - {@link InMemoryNonceCache} — a single-process, race-free TTL cache. The check-and-set runs in
 *     one synchronous critical section (no `await` between read and write), so it cannot interleave
 *     with a concurrent replay within one process. Use it for a single instance / dev.
 *   - {@link consumeFromNonceCacheProvider} — delegates to `NonceCacheProvider.consume`, which
 *     a shared/distributed provider should implement atomically in its backend. Providers
 *     without it fall back to `has()` then `add()` unless `requireAtomicNonce` is set.
 *
 * Type-only import of `NonceCacheProvider`. The shared admission helper is the only runtime
 * dependency: no coupling to the legacy proof engine and no `mcp-i-core` dependency.
 */

import type { NonceCacheProvider } from '../../providers/base.js';
import { admitNonce, checkNonceStore } from '../../providers/nonce-admission.js';
import { NONCE_RETENTION_SEC, type ConsumeNonceIfFresh } from './types.js';

/** Inserts between amortised expired-entry sweeps (bounds memory without a timer/lifecycle). */
const SWEEP_EVERY = 1000;

/** Construction options for {@link InMemoryNonceCache}. */
export interface InMemoryNonceCacheOptions {
  /** How long a consumed nonce is remembered, in seconds (default {@link NONCE_RETENTION_SEC} —
   *  the full verifier acceptance window, so an evicted nonce can never outlive a valid proof). */
  ttlSec?: number;
  /** Injectable clock returning epoch MILLISECONDS (deterministic tests; default `Date.now`). */
  now?: () => number;
}

/**
 * A single-process, race-free replay cache implementing the {@link ConsumeNonceIfFresh} seam.
 * Remembers each `(did, nonce)` for `ttlSec` — long enough to cover the proof's own lifetime — and
 * rejects any repeat within that window.
 */
export class InMemoryNonceCache {
  /** `did\0nonce` → expiry epoch ms. */
  private readonly seen = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly clock: () => number;
  /** Inserts since the last sweep — amortises {@link cleanup} so `seen` stays bounded. */
  private insertsSinceSweep = 0;

  constructor(opts: InMemoryNonceCacheOptions = {}) {
    this.ttlMs = (opts.ttlSec ?? NONCE_RETENTION_SEC) * 1000;
    this.clock = opts.now ?? Date.now;
  }

  /**
   * Atomic test-AND-set: record `nonce` for `did` and return `true` iff it was NOT already recorded
   * (and unexpired); return `false` on a replay, leaving the prior record intact. One synchronous
   * critical section — no `await` between the read and the write — so it is race-free within one
   * process. Arrow field so it stays bound when passed directly as the seam.
   */
  readonly consume: ConsumeNonceIfFresh = (nonce, did, minTtlSec = 0) => {
    // NUL (`\0`) delimiter: `did` and `nonce` are opaque strings, so an ambiguous separator
    // (e.g. a space) could let one (did, nonce) pair collide with another. `\0` cannot appear
    // in a DID and is not a valid nonce byte, so the composite key stays unambiguous.
    const key = `${did}\0${nonce}`;
    const now = this.clock();
    const expiry = this.seen.get(key);
    if (expiry !== undefined && expiry > now) return false;
    const ttlMs = Math.max(this.ttlMs, minTtlSec * 1000);
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new RangeError('Nonce retention must be positive and finite');
    }
    this.seen.set(key, now + ttlMs);
    // Amortised eviction: sweep expired entries every SWEEP_EVERY inserts so a long-running
    // process cannot accumulate dead nonces unboundedly — no timer or lifecycle to manage.
    if (++this.insertsSinceSweep >= SWEEP_EVERY) {
      this.insertsSinceSweep = 0;
      this.cleanup();
    }
    return true;
  };

  /** Drop expired entries — call periodically to bound memory in a long-running process. */
  cleanup(): void {
    const now = this.clock();
    for (const [key, expiry] of this.seen) if (expiry <= now) this.seen.delete(key);
  }
}

/** Options for {@link consumeFromNonceCacheProvider}. */
export interface NonceCacheProviderAdapterOptions {
  /** Minimum TTL in seconds (default {@link NONCE_RETENTION_SEC}); verifier floors may raise it. */
  ttlSec?: number;
  /** Refuse a provider without `consume()` instead of falling back to `has()` then `add()`. */
  requireAtomicNonce?: boolean;
}

/**
 * Adapt {@link NonceCacheProvider.consume} into the {@link ConsumeNonceIfFresh} seam.
 *
 * Uses the provider's backend-native atomic test-and-set (SPEC §12.2) when it has one. A
 * provider without `consume()` falls back to `has()` then `add()`, which cannot stop
 * concurrent duplicates, and logs a warning once; under `requireAtomicNonce` this factory
 * throws for such a provider instead. Storage failure rejects the call, which the verifier
 * handles as failed nonce admission. The bundled {@link MemoryNonceCacheProvider} is atomic
 * only within one cache instance.
 */
export function consumeFromNonceCacheProvider(
  provider: NonceCacheProvider,
  opts: NonceCacheProviderAdapterOptions = {},
): ConsumeNonceIfFresh {
  const ttlSec = opts.ttlSec ?? NONCE_RETENTION_SEC;
  const admission = { requireAtomicNonce: opts.requireAtomicNonce ?? false };
  checkNonceStore(provider, admission);
  return (nonce, did, minTtlSec = 0) =>
    admitNonce(provider, nonce, Math.max(ttlSec, minTtlSec), did, admission);
}
