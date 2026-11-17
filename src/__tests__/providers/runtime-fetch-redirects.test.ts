/**
 * RuntimeFetchProvider follows a did:web or status-list redirect by hand: at most three, each
 * target checked by the SSRF rule the first URL met, its host resolved and checked again before it
 * is requested, never from https down to http, and all within the one deadline. A runtime that
 * followed them itself would carry the request to a private host. The did:web tests resolve every
 * name to a public address and serve the read from a stubbed `fetch`. The status-list tests read
 * from a real https server on 127.0.0.1 through the library's own pinned `node:https` transport,
 * which a public name the lookup answers reaches; a provider of the host's own is read from a real
 * plain-http server, under the private-network rule's opt-out, since a status list is read over
 * http only from a private or local host.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import https from 'node:https';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { fetchDidJson } from '../../delegation/read-did-json.js';
import { fetchStatusListJson } from '../../delegation/status-list-fetch.js';
import { nodeHttpsTransport, type DnsLookup, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import { closeLoopback, listenOnLoopback } from '../utils/loopback-server.js';
import { documentOf } from '../utils/did-documents.js';
import { lookupOf, OVER_STUBBED_FETCH, PUBLIC_ADDRESS } from '../utils/runtime-network.js';
import { selfSignedTls } from '../utils/self-signed-tls.js';

const did = 'did:web:public.example';
const didUrl = 'https://public.example/.well-known/did.json';
const document = documentOf({}, did);
const list = {
  id: 'list', type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAA' },
};

/**
 * A global `fetch` that answers from `routes`, following redirects itself unless the request says
 * `redirect: 'manual'`, as the runtime's own does. `requested` lists every URL it was asked for.
 */
function serving(routes: Record<string, () => Response>) {
  const requested: string[] = [];
  const answer = (url: string): Response => {
    requested.push(url);
    const route = routes[url];
    return route ? route() : new Response(null, { status: 404 });
  };
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    let response = answer(url);
    for (let hops = 0; init?.redirect !== 'manual' && response.status === 302 && hops < 20; hops++) {
      response = answer(new URL(response.headers.get('location')!, url).href);
    }
    return response;
  });
  vi.stubGlobal('fetch', fetch);
  return requested;
}

const redirect = (location: string) => () => new Response(null, { status: 302, headers: { location } });
const json = (value: unknown) => () => new Response(JSON.stringify(value));

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('did:web redirects', () => {
  it.each([
    ['the link-local metadata address', 'http://169.254.169.254/latest/meta-data'],
    ['a loopback address', 'https://127.0.0.1/.well-known/did.json'],
    ['a private address', 'https://10.0.0.5/.well-known/did.json'],
    ['a scheme other than http and https', 'file:///etc/did.json'],
  ])('refuses one to %s without requesting it', async (_name, target) => {
    const requested = serving({ [didUrl]: redirect(target), [target]: json(document) });
    expect(await new RuntimeFetchProvider(OVER_STUBBED_FETCH).resolveDID(did)).toBeNull();
    expect(requested).toEqual([didUrl]);
  });

  it('refuses one from https down to http, even to a public host', async () => {
    const target = 'http://public.example/did.json';
    const requested = serving({ [didUrl]: redirect(target), [target]: json(document) });
    expect(await new RuntimeFetchProvider(OVER_STUBBED_FETCH).resolveDID(did)).toBeNull();
    expect(requested).toEqual([didUrl]);
  });

  it('follows three to public hosts, and refuses a fourth', async () => {
    const hops = ['https://a.example/1', 'https://b.example/2', 'https://c.example/3', 'https://d.example/4'];
    const routes = (followed: number) => Object.fromEntries([
      [didUrl, redirect(hops[0]!)],
      ...hops.slice(0, followed).map((hop, i) => [hop, i + 1 < followed ? redirect(hops[i + 1]!) : json(document)]),
    ]);
    serving(routes(3));
    expect(await new RuntimeFetchProvider(OVER_STUBBED_FETCH).resolveDID(did)).toEqual(document);
    const requested = serving(routes(4));
    expect(await new RuntimeFetchProvider(OVER_STUBBED_FETCH).resolveDID(did)).toBeNull();
    expect(requested).toEqual([didUrl, ...hops.slice(0, 3)]);
  });

  it('keeps one deadline across every hop', async () => {
    vi.useFakeTimers();
    const hops = ['https://a.example/1', 'https://b.example/2'];
    const slow = (response: () => Response) => () => response();
    const fetch = vi.fn((url: string) => new Promise<Response>(resolve => setTimeout(() => resolve(({
      [didUrl]: slow(redirect(hops[0]!)), [hops[0]!]: slow(redirect(hops[1]!)), [hops[1]!]: slow(json(document)),
    } as Record<string, () => Response>)[url]!()), 2_000)));
    vi.stubGlobal('fetch', fetch);
    let outcome: unknown = 'pending';
    const settled = new RuntimeFetchProvider(OVER_STUBBED_FETCH).resolveDID(did).then(value => { outcome = value; });
    await vi.advanceTimersByTimeAsync(5_000);
    await settled;
    expect(outcome).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('refuses one to a public name whose address is private, once it resolves it, without requesting it', async () => {
    const target = 'https://intranet.example/.well-known/did.json';
    const requested = serving({ [didUrl]: redirect(target), [target]: json(document) });
    const lookup = lookupOf({ 'intranet.example': [{ address: '10.0.0.9', family: 4 }] });
    expect(await new RuntimeFetchProvider({ ...OVER_STUBBED_FETCH, lookup }).resolveDID(did)).toBeNull();
    expect(requested).toEqual([didUrl]);
  });
});

describe('status-list redirects, against a real https server', () => {
  const PUBLIC = 'list-host.example';
  const INTERNAL = 'intranet.example';
  const tls = selfSignedTls(PUBLIC);
  const trusted = https.globalAgent.options.ca;
  let server: https.Server;
  let port: number;
  const served: string[] = [];
  /** Every request the pinned transport made: the URL, and the address it connected to. */
  const connected: [string, string][] = [];

  /** Every public name resolves to a public address, and `intranet.example` to a private one. */
  const lookup: DnsLookup = lookupOf({ [INTERNAL]: [{ address: '10.0.0.9', family: 4 }] });
  /** The library's pinned transport, on a network where the public address it checked reaches the server. */
  const transport: SafeFetchTransport = (url, init) => {
    connected.push([url, init.pinnedAddress]);
    return nodeHttpsTransport(url, { ...init, pinnedAddress: '127.0.0.1' });
  };

  beforeAll(async () => {
    server = https.createServer(tls, (request, response) => {
      served.push(request.url!);
      const hops: Record<string, string> = {
        '/moved': `https://${PUBLIC}:${port}/list`,
        '/to-loopback': `https://127.0.0.1:${port}/list`,
        '/to-localhost': `https://localhost:${port}/list`,
        '/to-internal': `https://${INTERNAL}:${port}/list`,
        '/to-http': `http://${PUBLIC}:${port}/list`,
      };
      if (hops[request.url!] !== undefined) response.writeHead(302, { location: hops[request.url!] }).end();
      else response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(list));
    });
    https.globalAgent.options.ca = [tls.cert];
    port = await listenOnLoopback(server as unknown as Server);
  });

  afterAll(async () => {
    https.globalAgent.options.ca = trusted;
    await closeLoopback(server as unknown as Server);
  });

  beforeEach(() => {
    served.length = 0;
    connected.length = 0;
  });

  it('follows a redirect the rule admits, each hop connected to the address it checked', async () => {
    const provider = new RuntimeFetchProvider({ lookup, transport });
    expect(await provider.fetchStatusList(`https://${PUBLIC}:${port}/moved`)).toMatchObject({ id: 'list' });
    expect(served).toEqual(['/moved', '/list']);
    expect(connected).toEqual([
      [`https://${PUBLIC}:${port}/moved`, PUBLIC_ADDRESS.address],
      [`https://${PUBLIC}:${port}/list`, PUBLIC_ADDRESS.address],
    ]);
  });

  it('refuses one to a loopback address, localhost, a name that resolves to a private address, or http, without requesting it', async () => {
    const provider = new RuntimeFetchProvider({ lookup, transport });
    for (const path of ['/to-loopback', '/to-localhost', '/to-internal', '/to-http']) {
      served.length = 0;
      expect(await provider.fetchStatusList(`https://${PUBLIC}:${port}${path}`)).toBeNull();
      expect(served).toEqual([path]);
    }
    expect(connected.map(([url]) => new URL(url).hostname)).toEqual([PUBLIC, PUBLIC, PUBLIC, PUBLIC]);
  });

  it('refuses a list on localhost, or over http from a public name, without requesting it', async () => {
    const provider = new RuntimeFetchProvider({ lookup, transport });
    expect(await provider.fetchStatusList(`https://localhost:${port}/list`)).toBeNull();
    expect(await provider.fetchStatusList(`http://${PUBLIC}:${port}/list`)).toBeNull();
    expect({ served, connected }).toEqual({ served: [], connected: [] });
  });
});

describe('a provider of the host\'s own, against a real plain-http server', () => {
  const PUBLIC = 'list-host.example';
  /** A local name, from which the opt-out admits a status list over http. */
  const LOCAL = 'list-host.localhost';
  const realFetch = globalThis.fetch;
  let server: Server;
  let port: number;
  const served: string[] = [];

  beforeAll(async () => {
    server = createServer((request: IncomingMessage, response: ServerResponse) => {
      served.push(request.url!);
      if (request.url === '/moved') response.writeHead(302, { location: '/list' }).end();
      else response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(list));
    });
    port = await listenOnLoopback(server);
  });

  afterAll(async () => {
    await closeLoopback(server);
  });

  beforeEach(() => {
    served.length = 0;
  });

  it('refuses every read through a provider that rewrites the URL it was asked for, and reads through one that rebuilds the response', async () => {
    // A gateway or proxy: it sends a name to another URL, and passes redirect on.
    const rewrite = (url: string) => url.replace(`//${PUBLIC}:`, '//127.0.0.1:').replace(`//${LOCAL}:`, '//127.0.0.1:');
    const rewriting = { fetch: (url: string, init?: RequestInit) => realFetch(rewrite(url), init) };
    await expect(fetchDidJson(rewriting, `http://${PUBLIC}:${port}/list`)).rejects.toThrow('Redirect followed by the fetch provider refused');
    await expect(fetchStatusListJson({ ...rewriting, allowPrivateNetworkHosts: true }, `http://${LOCAL}:${port}/list`, { development: true })).rejects.toThrow(
      'Redirect followed by the fetch provider refused',
    );
    // A response built from the one it received names no URL, so the read takes it, and follows its redirects by hand.
    const rebuilding = { fetch: async (url: string, init?: RequestInit) => {
      const response = await realFetch(rewrite(url), init);
      return new Response(response.body, response);
    } };
    expect(await fetchDidJson(rebuilding, `http://${PUBLIC}:${port}/moved`)).toMatchObject({ id: 'list' });
    expect(await fetchStatusListJson({ ...rebuilding, allowPrivateNetworkHosts: true }, `http://${LOCAL}:${port}/moved`, { development: true }))
      .toMatchObject({ id: 'list' });
    expect(served).toEqual(['/list', '/list', '/moved', '/list', '/moved', '/list']);
  });

  it('refuses a status list over http from a public name, even under the opt-out, without requesting it', async () => {
    const open = { fetch: (url: string, init?: RequestInit) => realFetch(url, init), allowPrivateNetworkHosts: true };
    await expect(fetchStatusListJson(open, `http://${PUBLIC}:${port}/list`)).rejects.toThrow('Request to a "http:" URL refused');
    expect(served).toEqual([]);
  });
});
