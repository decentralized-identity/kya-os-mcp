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

describe('the §8.3 pre-signing transformation (strip params._meta)', () => {
  it('a request carrying params._meta hashes identically to the same request without it', async () => {
    const bare = await computeRequestHash(REQ);
    const carried = await computeRequestHash({
      method: REQ.method,
      params: {
        ...REQ.params,
        _meta: { 'org.kya-os/proof@1': { prf: 'org.kya-os/proof@1', jws: 'x..y' }, progressToken: 7 },
      },
    });
    expect(carried).toBe(bare); // the proof's own carrier is never part of the signed material
  });

  it('only the top-level _meta member of params is removed', async () => {
    const nested = { method: 'tools/call', params: { name: 'search', arguments: { _meta: 'payload data' } } };
    const withCarrier = await computeRequestHash({
      method: nested.method,
      params: { ...nested.params, _meta: { anything: true } },
    });
    expect(withCarrier).toBe(await computeRequestHash(nested)); // nested _meta-named data survives
    expect(withCarrier).not.toBe(await computeRequestHash(REQ)); // and still distinguishes bodies
  });

  it('requests without params (or with non-object params) are unchanged', async () => {
    const noParams = await computeRequestHash({ method: 'ping' });
    expect(noParams).toBe(await computeRequestHash({ method: 'ping' }));
    const arrayParams = await computeRequestHash({ method: 'x', params: [1, 2] });
    expect(arrayParams).not.toBe(noParams);
  });
});
