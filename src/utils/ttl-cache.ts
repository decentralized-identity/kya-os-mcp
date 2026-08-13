/**
 * Minimal TTL + FIFO-bounded map — the ONE eviction implementation shared by
 * the delegation verifier's signature-result cache and the `withStatusCache`
 * resolver wrapper (DRY). Internal utility; not exported from the package
 * surface.
 *
 * Semantics: `ttlMs <= 0` or `maxEntries <= 0` disables storage entirely (an
 * entry that is born expired or unstorable must never serve); expired entries
 * are deleted on read; overwriting a key re-inserts it as newest; when full,
 * the oldest inserted entry is evicted (simple FIFO, no LRU bookkeeping).
 */
export class TtlCache<T> {
  private entries = new Map<string, { value: T; expiresAt: number }>();
  private insertionOrder: string[] = [];

  constructor(private options: { ttlMs: number; maxEntries: number }) {}

  get(key: string): T | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: T): void {
    if (this.options.ttlMs <= 0 || this.options.maxEntries <= 0) return;

    // Overwrite = delete + re-insert, keeping `entries` and `insertionOrder`
    // in bijection. Without this, N concurrent misses on one key leave N-1
    // phantom order entries (a slow leak keyed by KB-scale cache keys), and
    // an at-capacity refresh evicts an innocent neighbor.
    if (this.entries.has(key)) this.delete(key);

    // Evict oldest entries if the cache is full (simple FIFO)
    while (
      this.entries.size >= this.options.maxEntries &&
      this.insertionOrder.length > 0
    ) {
      const oldest = this.insertionOrder.shift();
      if (oldest) this.entries.delete(oldest);
    }

    this.entries.set(key, {
      value,
      expiresAt: Date.now() + this.options.ttlMs,
    });
    this.insertionOrder.push(key);
  }

  delete(key: string): void {
    this.entries.delete(key);
    const index = this.insertionOrder.indexOf(key);
    if (index !== -1) this.insertionOrder.splice(index, 1);
  }

  deleteWhere(predicate: (key: string) => boolean): void {
    for (const key of [...this.entries.keys()]) {
      if (predicate(key)) this.delete(key);
    }
  }

  clear(): void {
    this.entries.clear();
    this.insertionOrder = [];
  }
}
