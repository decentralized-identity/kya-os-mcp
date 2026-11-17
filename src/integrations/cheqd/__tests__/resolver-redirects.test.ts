/**
 * The cheqd resolver follows a redirect from its endpoint by hand, as a did:web or status-list read
 * does: at most 3, never from https down to http, and to an origin other than the resolver's with
 * only the CORS-safelisted request headers, so a key the operator configures in `headers` reaches
 * the resolver alone. The end-to-end tests read from real servers on 127.0.0.1 through
 * `RuntimeFetchProvider`, whose runtime would otherwise follow 20 redirects to any host and send
 * every header but `Authorization` along.
 */

import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cheqdResolver, createDidCheqdResolver } from '../resolver.js';
import { RuntimeFetchProvider } from '../../../providers/runtime-fetch.js';
import type { FetchProvider } from '../../../providers/base.js';
import { closeLoopback, listenOnLoopback } from '../../../__tests__/utils/loopback-server.js';
import { documentOf } from '../../../__tests__/utils/did-documents.js';

const DID = 'did:cheqd:testnet:6c9b1bbe-1a2c-4c1e-9d3c-2e0f0f0b0a01';
const document = documentOf({ verificationMethod: [] }, DID);
const headers = { 'x-api-key': 'operator-key', 'Accept-Language': 'en' };

/** A server on 127.0.0.1 that answers each request with `answer`, and records the headers of each. */
async function serving(answer: (path: string) => { status: number; location?: string; body?: string }) {
  const seen: { path: string; headers: IncomingHttpHeaders }[] = [];
  const server: Server = createServer((request, response) => {
    seen.push({ path: request.url ?? '', headers: request.headers });
    const { status, location, body } = answer(request.url ?? '');
    response.writeHead(status, location === undefined ? {} : { location });
    response.end(body);
  });
  const origin = `http://127.0.0.1:${await listenOnLoopback(server)}`;
  servers.push(server);
  return { origin, seen };
}

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(closeLoopback));
  vi.restoreAllMocks();
});

describe('the cheqd resolver, reading from a resolver that redirects', () => {
  it("sends the configured headers only to the resolver's own origin", async () => {
    const other = await serving(() => ({ status: 200, body: JSON.stringify(document) }));
    const endpoint = await serving(path => path.startsWith('/moved/')
      ? { status: 302, location: `${other.origin}/elsewhere` }
      : { status: 301, location: `/moved/${DID}` });
    const runtime = new RuntimeFetchProvider({ didResolvers: { cheqd: cheqdResolver({ resolverUrl: endpoint.origin, headers }) } });

    expect(await runtime.resolveDID(DID)).toEqual(document);
    expect(endpoint.seen.map(({ headers }) => headers['x-api-key'])).toEqual(['operator-key', 'operator-key']);
    expect(other.seen).toHaveLength(1);
    expect(other.seen[0]!.headers['x-api-key']).toBeUndefined();
    expect(other.seen[0]!.headers).toMatchObject({ accept: 'application/did+ld+json', 'accept-language': 'en' });
  });

  it('follows at most 3 redirects, and refuses the fourth without requesting it', async () => {
    const endpoint = await serving(path => {
      const hop = Number(/hop=(\d+)/.exec(path)?.[1] ?? 0);
      return { status: 302, location: `/1.0/identifiers/${DID}?hop=${hop + 1}` };
    });
    const resolver = createDidCheqdResolver(new RuntimeFetchProvider(), { resolverUrl: endpoint.origin, headers });

    expect(await resolver.resolve(DID)).toBeNull();
    expect(endpoint.seen).toHaveLength(4);
    expect(resolver.lastFailure?.(DID)).toEqual({ cause: 'unavailable', detail: 'Redirect limit of 3 exceeded' });
  });
});

describe('the cheqd resolver and its fetch provider', () => {
  /** A provider that answers each URL from `routes`, and records what it was asked. */
  function provider(routes: Record<string, () => Response>) {
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => routes[url]?.() ?? new Response(null, { status: 404 }));
    return { fetch, resolver: createDidCheqdResolver({ fetch } as unknown as FetchProvider, { resolverUrl: 'https://resolver.example', headers }) };
  }
  const first = `https://resolver.example/1.0/identifiers/${DID}`;

  it('asks it not to follow a redirect', async () => {
    const { fetch, resolver } = provider({ [first]: () => new Response(JSON.stringify(document)) });
    expect(await resolver.resolve(DID)).toEqual(document);
    expect(fetch.mock.calls.map(([, init]) => init?.redirect)).toEqual(['manual']);
  });

  it('refuses a redirect from https down to http without requesting it', async () => {
    const target = 'http://resolver.example/plain';
    const { fetch, resolver } = provider({
      [first]: () => new Response(null, { status: 302, headers: { location: target } }),
      [target]: () => new Response(JSON.stringify(document)),
    });
    expect(await resolver.resolve(DID)).toBeNull();
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([first]);
    expect(resolver.lastFailure?.(DID)?.cause).toBe('host_refused');
  });

  it('refuses a resolver URL that is not an absolute http or https URL, before any request', async () => {
    const fetch = vi.fn();
    const resolver = createDidCheqdResolver({ fetch } as unknown as FetchProvider, { resolverUrl: 'ftp://resolver.example' });
    expect(await resolver.resolve(DID)).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
    expect(resolver.lastFailure?.(DID)?.cause).toBe('host_refused');
  });

  it('refuses a response the provider reached by following a redirect itself', async () => {
    const followed = new Response(JSON.stringify(document));
    Object.defineProperty(followed, 'redirected', { value: true });
    const { resolver } = provider({ [first]: () => followed });
    expect(await resolver.resolve(DID)).toBeNull();
    expect(resolver.lastFailure?.(DID)).toEqual({ cause: 'host_refused', detail: 'Redirect followed by the fetch provider refused' });
  });
});
