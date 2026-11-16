/**
 * SafeFetch's policy for the one redirect-following rule (`../redirect-follower`): its own refusal
 * texts, its default limit, an empty Location refused as a missing one, and the refusal of every
 * target that is not https or is at another origin.
 */

import { describe, expect, it, vi } from 'vitest';
import { MAX_REDIRECTS } from '../redirect-follower.js';
import { createSafeFetch, type DnsLookup, type RawResponse, type TransportInit } from '../safe-fetch.js';

const lookup: DnsLookup = async () => [{ address: '93.184.216.34', family: 4 }];

const redirect = (location: string | null, status = 302): RawResponse => ({
  status,
  headers: { get: name => (name === 'location' ? location : null) },
  text: () => Promise.resolve(''),
});

const ok: RawResponse = { status: 200, headers: { get: () => null }, text: () => Promise.resolve('{"ok":true}') };

/** A SafeFetch whose transport answers each URL from `locations` with a redirect, any other with a 200. */
function safeFetchOver(locations: Record<string, string | null>, maxRedirects?: number) {
  const transport = vi.fn(async (url: string, _init: TransportInit) => (url in locations ? redirect(locations[url]!) : ok));
  return { transport, fetch: createSafeFetch({ lookup, transport, ...(maxRedirects === undefined ? {} : { maxRedirects }) }) };
}

describe("SafeFetch's redirect limit", () => {
  it('is the shared default: three same-origin redirects are followed, a fourth refused after four requests', async () => {
    const hop = (i: number) => `https://example.com/${i}`;
    const three = safeFetchOver({ [hop(0)]: hop(1), [hop(1)]: hop(2), [hop(2)]: hop(3) });
    expect(await (await three.fetch(hop(0))).json()).toEqual({ ok: true });
    expect(three.transport.mock.calls.map(([url]) => url)).toEqual([hop(0), hop(1), hop(2), hop(3)]);

    const four = safeFetchOver({ [hop(0)]: hop(1), [hop(1)]: hop(2), [hop(2)]: hop(3), [hop(3)]: hop(4) });
    await expect(four.fetch(hop(0))).rejects.toThrow(`safe-fetch: too many redirects (> ${MAX_REDIRECTS})`);
    expect(four.transport).toHaveBeenCalledTimes(MAX_REDIRECTS + 1);
  });

  it('is maxRedirects when that is set, zero refusing the first redirect', async () => {
    const { fetch, transport } = safeFetchOver({ 'https://example.com/a': '/b' }, 0);
    await expect(fetch('https://example.com/a')).rejects.toThrow('safe-fetch: too many redirects (> 0)');
    expect(transport).toHaveBeenCalledOnce();
  });
});

describe("SafeFetch's reading of Location", () => {
  it.each([[null], ['']])('refuses %j as a missing header, naming the status, after one request', async location => {
    const transport = vi.fn(async () => redirect(location, 307));
    const fetch = createSafeFetch({ lookup, transport });
    await expect(fetch('https://example.com/a')).rejects.toThrow('safe-fetch: 307 redirect without a Location header');
    expect(transport).toHaveBeenCalledOnce();
  });

  it('quotes a Location that does not parse', async () => {
    const { fetch } = safeFetchOver({ 'https://example.com/a': 'https://[' });
    await expect(fetch('https://example.com/a')).rejects.toThrow('safe-fetch: redirect location is not a valid URL "https://["');
  });
});

describe("SafeFetch's vetting of a target", () => {
  it.each([
    ['http://example.com/x', 'http:'], ['http://other.example/x', 'http:'],
    ['ftp://example.com/x', 'ftp:'], ['data:text/plain,x', 'data:'],
  ])('refuses %s as a non-https target, whatever its origin, with no further request', async (location, scheme) => {
    const { fetch, transport } = safeFetchOver({ 'https://example.com/a': location });
    await expect(fetch('https://example.com/a')).rejects.toThrow(`safe-fetch: redirect to non-https target "${scheme}" blocked`);
    expect(transport).toHaveBeenCalledOnce();
  });

  it.each(['https://other.example/x', 'https://example.com:8443/x', 'https://sub.example.com/x'])(
    'refuses %s as another origin, naming the origin it left, with no further request',
    async location => {
      const { fetch, transport } = safeFetchOver({ 'https://example.com/a': location });
      await expect(fetch('https://example.com/a')).rejects.toThrow(
        new Error('safe-fetch: cross-origin redirect from https://example.com blocked'),
      );
      expect(transport).toHaveBeenCalledOnce();
    },
  );
});
