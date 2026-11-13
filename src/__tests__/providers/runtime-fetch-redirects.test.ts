/**
 * RuntimeFetchProvider follows a did:web or status-list redirect by hand: at most three, each
 * target checked by the SSRF rule the first URL met, never from https down to http, and all within
 * the one deadline. A runtime that followed them itself would carry the request to a private host.
 * The status-list tests read from a real server on 127.0.0.1, under a public name that a wrapped
 * `fetch` sends there, reporting the URL it was asked for unless the runtime followed a redirect.
 */

import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { fetchDidJson } from '../../delegation/read-did-json.js';
import { fetchStatusListJson } from '../../delegation/status-list-fetch.js';

const did = 'did:web:public.example';
const didUrl = 'https://public.example/.well-known/did.json';
const document = { id: did };
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
    expect(await new RuntimeFetchProvider().resolveDID(did)).toBeNull();
    expect(requested).toEqual([didUrl]);
  });

  it('refuses one from https down to http, even to a public host', async () => {
    const target = 'http://public.example/did.json';
    const requested = serving({ [didUrl]: redirect(target), [target]: json(document) });
    expect(await new RuntimeFetchProvider().resolveDID(did)).toBeNull();
    expect(requested).toEqual([didUrl]);
  });

  it('follows three to public hosts, and refuses a fourth', async () => {
    const hops = ['https://a.example/1', 'https://b.example/2', 'https://c.example/3', 'https://d.example/4'];
    const routes = (followed: number) => Object.fromEntries([
      [didUrl, redirect(hops[0]!)],
      ...hops.slice(0, followed).map((hop, i) => [hop, i + 1 < followed ? redirect(hops[i + 1]!) : json(document)]),
    ]);
    serving(routes(3));
    expect(await new RuntimeFetchProvider().resolveDID(did)).toEqual(document);
    const requested = serving(routes(4));
    expect(await new RuntimeFetchProvider().resolveDID(did)).toBeNull();
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
    const settled = new RuntimeFetchProvider().resolveDID(did).then(value => { outcome = value; });
    await vi.advanceTimersByTimeAsync(5_000);
    await settled;
    expect(outcome).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});

describe('status-list redirects, against a real server', () => {
  const PUBLIC = 'list-host.example';
  const realFetch = globalThis.fetch;
  let server: Server;
  let port: number;
  const served: string[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      served.push(request.url!);
      const hops: Record<string, string> = {
        '/moved': `http://${PUBLIC}:${port}/list`,
        '/to-loopback': `http://127.0.0.1:${port}/list`,
        '/to-localhost': `http://localhost:${port}/list`,
      };
      if (hops[request.url!] !== undefined) response.writeHead(302, { location: hops[request.url!] }).end();
      else response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(list));
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as { port: number }).port;
  });

  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });

  beforeEach(() => {
    served.length = 0;
    vi.stubGlobal('fetch', async (input: string, init?: RequestInit) => {
      const url = new URL(input);
      if (url.hostname === PUBLIC) url.hostname = '127.0.0.1';
      const response = await realFetch(url.href, init);
      return response.redirected ? response : Object.defineProperty(response, 'url', { value: input });
    });
  });

  it('follows a redirect the rule admits, and refuses one to a loopback address or localhost without requesting it', async () => {
    const provider = new RuntimeFetchProvider();
    expect(await provider.fetchStatusList(`http://${PUBLIC}:${port}/moved`)).toMatchObject({ id: 'list' });
    expect(served).toEqual(['/moved', '/list']);
    for (const path of ['/to-loopback', '/to-localhost']) {
      served.length = 0;
      expect(await provider.fetchStatusList(`http://${PUBLIC}:${port}${path}`)).toBeNull();
      expect(served).toEqual([path]);
    }
  });

  it('refuses a list on localhost without requesting it', async () => {
    expect(await new RuntimeFetchProvider().fetchStatusList(`http://localhost:${port}/list`)).toBeNull();
    expect(served).toEqual([]);
  });

  it('refuses every read through a provider that rewrites the URL it was asked for, and reads through one that rebuilds the response', async () => {
    // A gateway or proxy: it sends the public name to another URL, and passes redirect on.
    const rewrite = (url: string) => url.replace(`//${PUBLIC}:`, '//127.0.0.1:');
    const rewriting = { fetch: (url: string, init?: RequestInit) => realFetch(rewrite(url), init) };
    for (const read of [fetchStatusListJson, fetchDidJson]) {
      await expect(read(rewriting, `http://${PUBLIC}:${port}/list`)).rejects.toThrow('Redirect followed by the fetch provider refused');
    }
    // A response built from the one it received names no URL, so the read takes it, and follows its redirects by hand.
    const rebuilding = { fetch: async (url: string, init?: RequestInit) => {
      const response = await realFetch(rewrite(url), init);
      return new Response(response.body, response);
    } };
    expect(await fetchStatusListJson(rebuilding, `http://${PUBLIC}:${port}/moved`)).toMatchObject({ id: 'list' });
    expect(served).toEqual(['/list', '/list', '/moved', '/list']);
  });
});
