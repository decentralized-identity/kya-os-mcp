/**
 * Redirects followed by hand (`../checked-redirects`), through the private-network rule that uses
 * them: the body of each redirect is cancelled, a response the provider reached by following a
 * redirect itself is refused, a redirect with no target is refused at once, and a hop to another
 * origin carries only the CORS-safelisted request headers and the request's cache directives. A
 * request other than GET or HEAD follows only a 307 or 308, which keep its method and body, and
 * only to its own origin.
 */

import { describe, expect, it, vi } from 'vitest';
import { MAX_REDIRECTS } from '../redirect-follower.js';
import { underPrivateNetworkRule } from '../private-network-rule.js';

/** A body that records its cancellation. */
function body() {
  const cancel = vi.fn();
  return { cancel, stream: new ReadableStream<Uint8Array>({ cancel }) };
}

/** `response`, reporting the URL it came from and whether a redirect led there, as a runtime does. */
const reporting = (response: Response, url: string | undefined, redirected: boolean): Response =>
  Object.defineProperties(response, { url: { value: url }, redirected: { value: redirected } });

const REQUESTED = 'https://public.example/list';

describe('a redirect the provider follows itself', () => {
  it('is refused, and its body cancelled, when the response says it was redirected or names another URL', async () => {
    const followed: [string, boolean][] = [['https://10.0.0.5/admin', true], [REQUESTED, true], ['https://public.example/other', false]];
    for (const [url, redirected] of followed) {
      const { cancel, stream } = body();
      const fetch = vi.fn(async () => reporting(new Response(stream), url, redirected));
      await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED)).rejects.toThrow('Redirect followed by the fetch provider refused');
      expect(cancel).toHaveBeenCalledOnce();
    }
  });

  it('is not suspected of a response that names no URL, or the one requested as the URL parser writes it', async () => {
    for (const url of ['', undefined, REQUESTED]) {
      const fetch = vi.fn(async () => reporting(new Response('{}'), url, false));
      await expect(underPrivateNetworkRule({ fetch }).fetch('https://Public.Example:443/list#top')).resolves.toBeInstanceOf(Response);
    }
  });
});

describe('a redirect followed by hand', () => {
  it('cancels the body of each redirect, and of the one past the limit', async () => {
    const cancels: ReturnType<typeof vi.fn>[] = [];
    const fetch = vi.fn(async (url: string) => {
      const { cancel, stream } = body();
      cancels.push(cancel);
      return new Response(stream, { status: 302, headers: { location: `${url}/next` } });
    });
    await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED)).rejects.toThrow(`Redirect limit of ${MAX_REDIRECTS} exceeded`);
    expect(fetch).toHaveBeenCalledTimes(MAX_REDIRECTS + 1);
    expect(cancels.map(cancel => cancel.mock.calls.length)).toEqual(Array(MAX_REDIRECTS + 1).fill(1));
  });

  it.each([307, 308])('follows a %i, asking the next URL with the same method and no body', async status => {
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => url === REQUESTED
      ? new Response(null, { status, headers: { location: '/moved' } })
      : new Response('{}'));
    const init = { method: 'GET', headers: { Accept: 'application/json' } };
    expect(await underPrivateNetworkRule({ fetch }).fetch(REQUESTED, init)).toBeInstanceOf(Response);
    const asked = { ...init, redirect: 'manual' };
    expect(fetch.mock.calls).toEqual([[REQUESTED, asked], ['https://public.example/moved', asked]]);
  });

  it.each([301, 302, 303, 307, 308])('refuses a %i with no Location at once, after one request, cancelling its body', async status => {
    const { cancel, stream } = body();
    const fetch = vi.fn(async () => new Response(stream, { status }));
    await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED)).rejects.toThrow('Redirect without a Location header');
    expect(fetch).toHaveBeenCalledOnce();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('reads an empty Location as the URL that sent it, asking it again until the limit', async () => {
    const fetch = vi.fn(async (_url: string) => new Response(null, { status: 302, headers: { location: '' } }));
    await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED)).rejects.toThrow(`Redirect limit of ${MAX_REDIRECTS} exceeded`);
    expect(fetch.mock.calls.map(([url]) => url)).toEqual(Array(MAX_REDIRECTS + 1).fill(REQUESTED));
  });

  it.each([
    ['http://public.example/list', 'Redirect from https to http refused'],
    ['https://[bad', 'Redirect to an invalid URL'],
    ['https://10.0.0.5/admin', 'Redirect to a private or local host refused. In local development, set development: true;'],
    ['ftp://public.example/list', 'Redirect to a "ftp:" URL refused'],
  ])('refuses a redirect to %s after one request: %s', async (location, refusal) => {
    const fetch = vi.fn(async () => new Response(null, { status: 302, headers: { location } }));
    await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED)).rejects.toThrow(refusal);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("sends another origin only the CORS-safelisted request headers and the request's cache directives, and the origin first asked all of them", async () => {
    const next: Record<string, string> = {
      'https://public.example/a': 'https://public.example/b',
      'https://public.example/b': 'https://other.example/c',
      'https://other.example/c': 'https://public.example/d',
    };
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => next[url] === undefined
      ? new Response('{}')
      : new Response(null, { status: 302, headers: { location: next[url] } }));
    const headers = {
      Accept: 'application/did+ld+json', 'Accept-Language': 'en-US,en;q=0.9', 'Content-Language': 'de/x',
      'Cache-Control': 'no-cache', Pragma: 'no-cache', Authorization: 'Bearer secret', 'X-Api-Key': 'key',
    };
    await underPrivateNetworkRule({ fetch }).fetch('https://public.example/a', { headers });
    const all = Object.fromEntries(new Headers(headers));
    const safelisted = {
      accept: headers.Accept, 'accept-language': headers['Accept-Language'], 'cache-control': 'no-cache', pragma: 'no-cache',
    };
    expect(fetch.mock.calls.map(([url, init]) => [url, Object.fromEntries(new Headers(init?.headers))])).toEqual([
      ['https://public.example/a', all], ['https://public.example/b', all],
      ['https://other.example/c', safelisted], ['https://public.example/d', all],
    ]);
  });
});

describe('a redirect of a request other than GET or HEAD', () => {
  const post = { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Key': 'key' }, body: '{"a":1}' };

  it.each([307, 308])("follows a %i to its own origin, sending the same method, headers and body", async status => {
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => url === REQUESTED
      ? new Response(null, { status, headers: { location: '/moved' } })
      : new Response('{}'));
    expect(await underPrivateNetworkRule({ fetch }).fetch(REQUESTED, post)).toBeInstanceOf(Response);
    const asked = { ...post, redirect: 'manual' };
    expect(fetch.mock.calls).toEqual([[REQUESTED, asked], ['https://public.example/moved', asked]]);
  });

  it.each([301, 302, 303])('refuses a %i, which would not send its body again, after one request, cancelling its body', async status => {
    const { cancel, stream } = body();
    const fetch = vi.fn(async () => new Response(stream, { status, headers: { location: '/moved' } }));
    await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED, post))
      .rejects.toThrow(`Redirect of a POST by HTTP ${status} refused: only a 307 or 308 keeps its method and body`);
    expect(fetch).toHaveBeenCalledOnce();
    expect(cancel).toHaveBeenCalledOnce();
  });

  it.each([
    [REQUESTED, 'https://other.example/moved'],
    [REQUESTED, 'https://public.example:8443/moved'],
    ['http://public.example/list', 'https://public.example/list'],
  ])('refuses a redirect from %s to another origin, %s, without asking it', async (requested, location) => {
    const fetch = vi.fn(async () => new Response(null, { status: 307, headers: { location } }));
    await expect(underPrivateNetworkRule({ fetch }).fetch(requested, post)).rejects.toThrow('Redirect of a POST to another origin refused');
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('reads the method in any case, and holds a PUT to the same rule', async () => {
    for (const method of ['post', 'PUT']) {
      const fetch = vi.fn(async () => new Response(null, { status: 302, headers: { location: '/moved' } }));
      await expect(underPrivateNetworkRule({ fetch }).fetch(REQUESTED, { ...post, method }))
        .rejects.toThrow(`Redirect of a ${method.toUpperCase()} by HTTP 302 refused`);
    }
  });

  it('follows a HEAD as it follows a GET, to another origin and by a 302', async () => {
    const fetch = vi.fn(async (url: string) => url === REQUESTED
      ? new Response(null, { status: 302, headers: { location: 'https://other.example/moved' } })
      : new Response(null));
    expect(await underPrivateNetworkRule({ fetch }).fetch(REQUESTED, { method: 'HEAD' })).toBeInstanceOf(Response);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
