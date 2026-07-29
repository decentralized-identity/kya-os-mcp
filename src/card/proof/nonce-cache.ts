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
 *   - {@link consumeFromNonceCacheProvider} — composes the two-method `NonceCacheProvider`
 *     (`has()` + `add()`) into the atomic seam for a shared/distributed store (see the atomicity
 *     note on the function).
 *
 * Type-only import of `NonceCacheProvider` — no runtime coupling to the legacy proof engine and no
 * `mcp-i-core` dependency.
 */

import type { NonceCacheProvider } from '../../providers/base.js';
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
  readonly consume: ConsumeNonceIfFresh = (nonce, did) => {
    // NUL (`\0`) delimiter: `did` and `nonce` are opaque strings, so an ambiguous separator
    // (e.g. a space) could let one (did, nonce) pair collide with another. `\0` cannot appear
    // in a DID and is not a valid nonce byte, so the composite key stays unambiguous.
    const key = `${did}\0${nonce}`;
    const now = this.clock();
    const expiry = this.seen.get(key);
    if (expiry !== undefined && expiry > now) return false;
    this.seen.set(key, now + this.ttlMs);
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
  /** TTL applied to each recorded nonce, in seconds (default {@link NONCE_RETENTION_SEC}). */
  ttlSec?: number;
}

/**
 * Adapt a two-method {@link NonceCacheProvider} (`has()` + `add()`) into the atomic
 * {@link ConsumeNonceIfFresh} seam.
 *
 * ATOMICITY: `has()` then `add()` is only race-free when the provider serialises the pair — a
 * single-process store, or a backend with a native compare-and-set. For a SHARED distributed cache,
 * back it with a store that enforces atomic check-and-set (SPEC §12.2); otherwise two concurrent
 * replays can both observe `has() === false` before either `add()`s. The bundled
 * {@link InMemoryNonceCache} is race-free by construction and is the safer single-process default.
 */
export function consumeFromNonceCacheProvider(
  provider: NonceCacheProvider,
  opts: NonceCacheProviderAdapterOptions = {},
): ConsumeNonceIfFresh {
  const ttlSec = opts.ttlSec ?? NONCE_RETENTION_SEC;
  return async (nonce, did) => {
    if (await provider.has(nonce, did)) return false;
    await provider.add(nonce, ttlSec, did);
    return true;
  };
}
