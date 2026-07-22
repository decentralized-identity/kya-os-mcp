import { describe, expect, it } from 'vitest';
import { InMemoryNonceCache } from '../nonce-cache.js';

describe('InMemoryNonceCache', () => {
  it('rejects a replay within the retention window and forgets it after expiry', () => {
    let now = 1_750_000_000_000;
    const cache = new InMemoryNonceCache({ ttlSec: 10, now: () => now });

    expect(cache.consume('nonce-1', 'did:key:zA')).toBe(true);
    expect(cache.consume('nonce-1', 'did:key:zA')).toBe(false);
    // The composite key is DID-scoped: another DID may use the same nonce value.
    expect(cache.consume('nonce-1', 'did:key:zB')).toBe(true);

    now += 10_001;
    expect(cache.consume('nonce-1', 'did:key:zA')).toBe(true);
  });

  it('drops only expired entries on cleanup', () => {
    let now = 1_750_000_000_000;
    const cache = new InMemoryNonceCache({ ttlSec: 10, now: () => now });
    cache.consume('stale', 'did:key:zA');
    now += 5_000;
    cache.consume('fresh', 'did:key:zA');
    now += 5_001;

    cache.cleanup();
    expect(cache.consume('stale', 'did:key:zA')).toBe(true);
    expect(cache.consume('fresh', 'did:key:zA')).toBe(false);
  });

  it('sweeps expired entries automatically after the amortised insert threshold', () => {
    let now = 1_750_000_000_000;
    const cache = new InMemoryNonceCache({ ttlSec: 1, now: () => now });
    cache.consume('expired-early', 'did:key:zA');
    now += 1_001;
    for (let index = 0; index < 1_000; index += 1) {
      expect(cache.consume(`nonce-${index}`, 'did:key:zA')).toBe(true);
    }
    // The sweep ran during the loop, so the long-expired entry was evicted and
    // its identity is consumable again without an explicit cleanup() call.
    expect(cache.consume('expired-early', 'did:key:zA')).toBe(true);
  });
});
