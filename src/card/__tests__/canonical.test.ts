/**
 * Request-hash cross-format comparison. The card emits the RFC 9421 `sha-256=:<base64>:` form while
 * the legacy hasher emits `sha256:<hex>`; the two carry the SAME digest for the same input but are
 * never string-equal. `digestsEqual` is the correct cross-format comparator (P2.1).
 */
import { describe, it, expect } from 'vitest';
import { computeRequestHash, digestsEqual } from '../index.js';

const REQ = { method: 'tools/call', params: { name: 'search', arguments: { q: 'ledgers' } } };

describe('digestsEqual (RFC 9421 vs legacy hex)', () => {
  it('the two formats of the SAME digest are unequal strings but digest-equal', async () => {
    const card = await computeRequestHash(REQ); // sha-256=:<base64>:
    const b64 = /^sha-256=:(.+):$/.exec(card)![1];
    const legacy = `sha256:${Buffer.from(b64, 'base64').toString('hex')}`; // sha256:<hex>, same bytes

    expect(card).not.toBe(legacy); // never string-equal — the whole point
    expect(digestsEqual(card, legacy)).toBe(true); // but the underlying digests match
    expect(digestsEqual(legacy, card)).toBe(true); // symmetric
    expect(digestsEqual(card, card)).toBe(true);
  });

  it('returns false for a different digest or malformed input (fail-closed)', async () => {
    const card = await computeRequestHash(REQ);
    expect(digestsEqual(card, `sha256:${'00'.repeat(32)}`)).toBe(false);
    expect(digestsEqual(card, 'not-a-digest')).toBe(false);
    expect(digestsEqual('', card)).toBe(false);
    expect(digestsEqual('md5:abc', card)).toBe(false);
  });
});
