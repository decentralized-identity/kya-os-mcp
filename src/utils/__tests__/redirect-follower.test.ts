/**
 * The one redirect-following rule (`../redirect-follower`), under a policy that records what it is
 * asked: the hop limit and its default, the statuses that redirect, how `Location` is read, the
 * https-to-http refusal, and what a policy is told about each hop and each target.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  followRedirects, MAX_REDIRECTS, REDIRECT_STATUSES,
  type RedirectableResponse, type RedirectHop, type RedirectPolicy, type RedirectTarget,
} from '../redirect-follower.js';

interface Reply extends RedirectableResponse { readonly url: string }

const reply = (url: string, status: number, location?: string | null): Reply =>
  ({ url, status, headers: { get: name => (name === 'location' ? location ?? null : null) } });

/** A policy that answers each URL from `locations` with a 302 to it, and any other URL with a 200. */
function recording(locations: Record<string, string | null>, overrides: Partial<RedirectPolicy<Reply>> = {}) {
  const hops: RedirectHop[] = [];
  const targets: RedirectTarget[] = [];
  const discarded: string[] = [];
  const policy: RedirectPolicy<Reply> = {
    async request(hop) {
      hops.push(hop);
      return hop.url in locations ? reply(hop.url, 302, locations[hop.url]) : reply(hop.url, 200);
    },
    vetTarget: redirect => void targets.push(redirect),
    discard: redirect => void discarded.push(redirect.url),
    emptyLocationIsMissing: false,
    refusals: {
      limitExceeded: max => new Error(`limit ${max}`),
      missingLocation: status => new Error(`missing ${status}`),
      invalidLocation: location => new Error(`invalid ${location}`),
      httpsToHttp: target => new Error(`downgrade ${target.href}`),
    },
    ...overrides,
  };
  return { policy, hops, targets, discarded };
}

/** `count` redirects in a row from `https://a.example/0`. */
const chain = (count: number): Record<string, string> =>
  Object.fromEntries(Array.from({ length: count }, (_, i) => [`https://a.example/${i}`, `/${i + 1}`]));

describe('the redirect statuses', () => {
  it('are 301, 302, 303, 307 and 308, and no other status is followed', async () => {
    expect([...REDIRECT_STATUSES].sort()).toEqual([301, 302, 303, 307, 308]);
    for (const status of [200, 204, 300, 304, 305, 306, 309, 404, 500]) {
      const request = vi.fn(async (hop: RedirectHop) => reply(hop.url, status, '/next'));
      const { policy, discarded } = recording({}, { request });
      expect((await followRedirects('https://a.example/', policy)).status).toBe(status);
      expect(request).toHaveBeenCalledOnce();
      expect(discarded).toEqual([]);
    }
    for (const status of REDIRECT_STATUSES) {
      const request = vi.fn(async (hop: RedirectHop) => hop.url.endsWith('/next') ? reply(hop.url, 200) : reply(hop.url, status, '/next'));
      const { policy } = recording({}, { request });
      expect((await followRedirects('https://a.example/', policy)).url).toBe('https://a.example/next');
    }
  });
});

describe('the hop limit', () => {
  it('is 3 by default: three redirects are followed and a fourth refused, after four requests', async () => {
    expect(MAX_REDIRECTS).toBe(3);
    const at = recording(chain(MAX_REDIRECTS));
    expect((await followRedirects('https://a.example/0', at.policy)).url).toBe('https://a.example/3');
    expect(at.hops).toHaveLength(MAX_REDIRECTS + 1);

    const over = recording(chain(MAX_REDIRECTS + 1));
    await expect(followRedirects('https://a.example/0', over.policy)).rejects.toThrow('limit 3');
    expect(over.hops).toHaveLength(MAX_REDIRECTS + 1);
    expect(over.discarded).toHaveLength(MAX_REDIRECTS + 1);
  });

  it("is the policy's own when it sets one, zero and a negative limit refusing the first redirect", async () => {
    const one = recording(chain(1), { maxRedirects: 1 });
    expect((await followRedirects('https://a.example/0', one.policy)).url).toBe('https://a.example/1');
    const two = recording(chain(2), { maxRedirects: 1 });
    await expect(followRedirects('https://a.example/0', two.policy)).rejects.toThrow('limit 1');
    expect(two.hops).toHaveLength(2);
    for (const maxRedirects of [0, -1]) {
      const none = recording(chain(1), { maxRedirects });
      await expect(followRedirects('https://a.example/0', none.policy)).rejects.toThrow(`limit ${maxRedirects}`);
      expect(none.hops).toHaveLength(1);
    }
  });
});

describe('the Location header', () => {
  it('is refused when absent, with the status, before the target is vetted', async () => {
    const { policy, hops, targets, discarded } = recording({ 'https://a.example/': null });
    await expect(followRedirects('https://a.example/', policy)).rejects.toThrow('missing 302');
    expect(hops).toHaveLength(1);
    expect(targets).toEqual([]);
    expect(discarded).toEqual(['https://a.example/']);
  });

  it('is refused when empty under emptyLocationIsMissing, and otherwise names the URL that sent it', async () => {
    const missing = recording({ 'https://a.example/p?q': '' }, { emptyLocationIsMissing: true });
    await expect(followRedirects('https://a.example/p?q', missing.policy)).rejects.toThrow('missing 302');
    expect(missing.hops).toHaveLength(1);

    const relative = recording({ 'https://a.example/p?q': '' });
    await expect(followRedirects('https://a.example/p?q', relative.policy)).rejects.toThrow('limit 3');
    expect(relative.hops.map(hop => hop.url)).toEqual(Array(MAX_REDIRECTS + 1).fill('https://a.example/p?q'));
  });

  it('is resolved against the URL that sent it, and refused, quoted, when it does not parse', async () => {
    const { policy, hops } = recording({ 'https://a.example/dir/a': '../b', 'https://a.example/b': 'https://b.example/c' });
    expect((await followRedirects('https://a.example/dir/a', policy)).url).toBe('https://b.example/c');
    expect(hops.map(hop => hop.url)).toEqual(['https://a.example/dir/a', 'https://a.example/b', 'https://b.example/c']);

    const invalid = recording({ 'https://a.example/': 'https://[bad' });
    await expect(followRedirects('https://a.example/', invalid.policy)).rejects.toThrow('invalid https://[bad');
    expect(invalid.targets).toEqual([]);
  });
});

describe('a step between schemes', () => {
  it('is refused from https down to http, before the policy vets the target', async () => {
    const { policy, hops, targets } = recording({ 'https://a.example/': 'http://a.example/' });
    await expect(followRedirects('https://a.example/', policy)).rejects.toThrow('downgrade http://a.example/');
    expect(hops).toHaveLength(1);
    expect(targets).toEqual([]);
  });

  it('is followed from http to http and from http up to https, and any other scheme is left to the policy', async () => {
    const { policy, hops, targets } = recording({ 'http://a.example/': 'http://a.example/b', 'http://a.example/b': 'https://a.example/c' });
    expect((await followRedirects('http://a.example/', policy)).url).toBe('https://a.example/c');
    expect(hops).toHaveLength(3);
    expect(targets.map(({ target }) => target.href)).toEqual(['http://a.example/b', 'https://a.example/c']);

    const other = recording({ 'https://a.example/': 'ftp://a.example/' }, { vetTarget: ({ target }) => { throw new Error(`vetted ${target.protocol}`); } });
    await expect(followRedirects('https://a.example/', other.policy)).rejects.toThrow('vetted ftp:');
  });
});

describe('what the policy is told', () => {
  const route = { 'https://a.example/a': '/b', 'https://a.example/b': 'https://b.example/c', 'https://b.example/c': 'https://a.example/d' };

  it('is whether each hop, and each target, is at an origin other than the first', async () => {
    const { policy, hops, targets } = recording(route);
    await followRedirects('https://a.example/a', policy);
    expect(hops).toEqual([
      { url: 'https://a.example/a', crossOrigin: false }, { url: 'https://a.example/b', crossOrigin: false },
      { url: 'https://b.example/c', crossOrigin: true }, { url: 'https://a.example/d', crossOrigin: false },
    ]);
    expect(targets.map(({ target, from, crossOrigin }) => [from.href, target.href, crossOrigin])).toEqual([
      ['https://a.example/a', 'https://a.example/b', false],
      ['https://a.example/b', 'https://b.example/c', true],
      ['https://b.example/c', 'https://a.example/d', false],
    ]);
  });

  it('ends the read, with no further request, when vetTarget throws', async () => {
    const refused = new Error('refused by the policy');
    const { policy, hops } = recording(route, { vetTarget: ({ crossOrigin }) => { if (crossOrigin) throw refused; } });
    await expect(followRedirects('https://a.example/a', policy)).rejects.toBe(refused);
    expect(hops.map(hop => hop.url)).toEqual(['https://a.example/a', 'https://a.example/b']);
  });

  it('discards each redirect response and never the one returned, and needs no discard', async () => {
    const { policy, discarded } = recording(route);
    await followRedirects('https://a.example/a', policy);
    expect(discarded).toEqual(['https://a.example/a', 'https://a.example/b', 'https://b.example/c']);
    const { discard: _unused, ...withoutDiscard } = recording(route).policy;
    expect((await followRedirects('https://a.example/a', withoutDiscard)).url).toBe('https://a.example/d');
  });

  it('asks the first URL as given, and refuses one that does not parse before any request', async () => {
    const { policy, hops } = recording({});
    await followRedirects('https://A.example:443/x#top', policy);
    expect(hops).toEqual([{ url: 'https://A.example:443/x#top', crossOrigin: false }]);
    const none = recording({});
    await expect(followRedirects('not a url', none.policy)).rejects.toThrow(TypeError);
    expect(none.hops).toEqual([]);
  });
});
