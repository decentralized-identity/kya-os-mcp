/**
 * The Card resolver maps a did:web DID to its URLs as the did:web resolver does
 * (`../../delegation/did-web-url`): a host that is a host and nothing more, and each path segment
 * one segment. A DID whose decoded host or segment would move the fetch elsewhere, by a
 * dot-segment, a separator, a query, userinfo or a second percent-decode, names no URL, so it
 * resolves no Card and fetches nothing, rather than reading the Card another home serves.
 */

import { describe, expect, it } from 'vitest';
import { didWebToCardUrl, didWebToDidDocUrl, resolveCard } from '../resolve.js';
import type { SafeFetch } from '../../utils/safe-fetch.js';

/**
 * A web server, as `new URL` and the server read each request: alice's home `/alice/` holds a
 * DID document and a Card whose `id` is whatever DID alice chose to write there.
 */
function aliceServes(cardId: string) {
  const requested: string[] = [];
  const homes: Record<string, unknown> = {
    'https://example.com/alice/did.json': {
      id: cardId,
      service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://example.com/alice/card.json' }],
    },
    'https://example.com/alice/card.json': { id: cardId, entityType: 'agent', name: 'Alice' },
  };
  const fetch: SafeFetch = async (url) => {
    const { origin, pathname, search } = new URL(url);
    requested.push(`${origin}${pathname}${search}`);
    const body = homes[`${origin}${pathname}`];
    return { ok: body !== undefined, status: body === undefined ? 404 : 200, json: async () => body };
  };
  return { fetch, requested };
}

const NAMING_NO_URL: Array<[string, string]> = [
  ['a dot-segment', 'did:web:example.com:bob:..:alice'],
  ['an encoded dot-segment', 'did:web:example.com:bob:%2E%2E:alice'],
  ['a double-encoded dot-segment', 'did:web:example.com:bob:%252E%252E:alice'],
  ['an encoded slash', 'did:web:example.com:bob%2F..%2Falice'],
  ['an encoded query', 'did:web:example.com:alice%3Fx'],
  ['userinfo in the host', 'did:web:example.org%40example.com:alice'],
  ['a path in the host', 'did:web:example.com%2Falice'],
  ['an empty segment', 'did:web:example.com::alice'],
];

describe('the Card resolver reads a did:web DID as the did:web resolver does', () => {
  it.each(NAMING_NO_URL)('resolves no Card and fetches nothing for a DID with %s', async (_label, did) => {
    const { fetch, requested } = aliceServes(did);
    await expect(resolveCard(did, { fetch })).rejects.toThrow(/^resolveCard: .* names no URL/);
    await expect(resolveCard({ serverMeta: { 'org.kya-os/card': { id: did } } }, { fetch })).rejects.toThrow(/^resolveCard: .* names no URL/);
    expect(requested).toEqual([]);
    expect(() => didWebToCardUrl(did)).toThrow(/^didWebToCardUrl: .* names no URL/);
    expect(() => didWebToDidDocUrl(did)).toThrow(/^didWebToDidDocUrl: .* names no URL/);
  });

  it("does not resolve a Card alice serves for a DID under bob's path", async () => {
    const underBob = 'did:web:example.com:bob:%2E%2E:alice';
    const { fetch, requested } = aliceServes(underBob);
    await expect(resolveCard(underBob, { fetch })).rejects.toThrow(/names no URL/);
    expect(requested).toEqual([]);
    // Alice's own DID still resolves her Card.
    const own = aliceServes('did:web:example.com:alice');
    expect((await resolveCard('did:web:example.com:alice', { fetch: own.fetch })).id).toBe('did:web:example.com:alice');
  });

  it('maps every DID that names a URL as before: a port, an IP literal, a name, an encoded colon', () => {
    expect(didWebToCardUrl('did:web:example.com%3A8443:agents:acme')).toBe('https://example.com:8443/agents/acme/card.json');
    expect(didWebToDidDocUrl('did:web:%5B%3A%3A1%5D')).toBe('https://[::1]/.well-known/did.json');
    expect(didWebToCardUrl('did:web:m%C3%BCnchen.example')).toBe('https://münchen.example/.well-known/kya-os-card.json');
    expect(didWebToCardUrl('did:web:host.example:users:alice%3Aagent')).toBe('https://host.example/users/alice:agent/card.json');
  });
});
