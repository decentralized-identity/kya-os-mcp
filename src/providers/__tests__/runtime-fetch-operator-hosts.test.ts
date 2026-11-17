/**
 * The hosts a verifier's operator names are its own to read wherever they are: the did:web
 * documents of the roots it pins in `trustedRootIssuers`, and the status lists its
 * `statusListIssuers` binds by URL or https origin. `allowPrivateNetworkHosts: true` and
 * `development: true` admit every private host. Each of those reads goes through the provider's own
 * `fetch` and resolves nothing. Every other host a counterparty names is resolved first, and refused
 * when it resolves to a private address. A provider whose `fetch` is its own, a subclass included,
 * and a runtime that resolves no name keep the rule on the URL alone.
 *
 * Every name under `corp.example` resolves to a private address here, and every other name to a
 * public one. The runtime's `fetch` is stubbed to serve every URL, and the pinned transport is
 * recorded, so each test tells a read through the provider's own `fetch` from a pinned one.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidWebResolver, fetchTransport, logger, RuntimeFetchProvider, type DnsLookup, type FetchProvider, type SafeFetchTransport } from '../../index.js';
import { documentOf } from '../../__tests__/utils/did-documents.js';
import { PUBLIC_ADDRESS } from '../../__tests__/utils/runtime-network.js';

const ROOT = 'did:web:root.corp.example';
const ROOT_URL = 'https://root.corp.example/.well-known/did.json';
/** A DID on the root's host that the operator does not pin. */
const AGENT = 'did:web:root.corp.example:agents:7';
const AGENT_URL = 'https://root.corp.example/agents/7/did.json';
const LIST_URL = 'https://status.corp.example/lists/1';
const list = {
  id: 'list', type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAA' },
};

/** Every URL the runtime's own `fetch` was asked for, every name the lookup was asked, and every URL the pinned transport connected. */
const fetched: string[] = [];
const asked: string[] = [];
const connected: string[] = [];

const lookup: DnsLookup = async (hostname) => {
  asked.push(hostname);
  return hostname.endsWith('corp.example') ? [{ address: '10.0.0.7', family: 4 }] : [PUBLIC_ADDRESS];
};
const transport: SafeFetchTransport = (url, init) => {
  connected.push(url);
  return fetchTransport(url, init);
};
const seams = { lookup, transport };

beforeEach(() => {
  for (const log of [fetched, asked, connected]) log.length = 0;
  vi.stubGlobal('fetch', async (url: string) => {
    fetched.push(url);
    const { host, pathname } = new URL(url);
    if (!pathname.endsWith('/did.json')) return Response.json(list);
    // The DID whose document lives at this URL, as did:web maps one to the other.
    const path = pathname.replace(/^\/\.well-known/, '').split('/').slice(1, -1);
    return Response.json(documentOf({}, ['did:web', encodeURIComponent(host), ...path].join(':')));
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.doUnmock('node:dns/promises');
  vi.resetModules();
});

describe('the hosts the operator names', () => {
  it('reads the document of a root it pins wherever it is, resolving nothing, and refuses an unpinned DID on the same host', async () => {
    const provider = new RuntimeFetchProvider({ ...seams, trustedRootIssuers: [ROOT] });
    expect((await provider.resolveDID(ROOT))?.id).toBe(ROOT);
    expect(await provider.resolveDID(AGENT)).toBeNull();
    expect({ fetched, asked, connected }).toEqual({ fetched: [ROOT_URL], asked: ['root.corp.example'], connected: [] });
  });

  it('reads a pinned root on a private IP literal through a provider of the host\'s own, and no other DID there', async () => {
    const own = { fetch: (url: string, init?: RequestInit) => globalThis.fetch(url, init) } as unknown as FetchProvider;
    const resolver = createDidWebResolver(own, { trustedRootIssuers: ['did:web:10.0.0.5'] });
    expect((await resolver.resolve('did:web:10.0.0.5'))?.id).toBe('did:web:10.0.0.5');
    expect(await resolver.resolve('did:web:10.0.0.6')).toBeNull();
    expect(fetched).toEqual(['https://10.0.0.5/.well-known/did.json']);
  });

  it('reads a status list statusListIssuers binds, by its URL or its https origin, wherever it is, and refuses one it does not bind', async () => {
    const statusListIssuers = { 'did:web:issuer.example': [LIST_URL], 'did:web:lists.example': ['https://lists.corp.example'] };
    const provider = new RuntimeFetchProvider({ ...seams, statusListIssuers });
    expect(await provider.fetchStatusList(LIST_URL)).toMatchObject({ id: 'list' });
    expect(await provider.fetchStatusList('https://lists.corp.example/7')).toMatchObject({ id: 'list' });
    expect(await provider.fetchStatusList('https://unbound.corp.example/1')).toBeNull();
    expect({ fetched, asked, connected }).toEqual({
      fetched: [LIST_URL, 'https://lists.corp.example/7'], asked: ['unbound.corp.example'], connected: [],
    });
  });

  it('refuses a malformed trustedRootIssuers or statusListIssuers when the provider or resolver is built', () => {
    expect(() => new RuntimeFetchProvider({ trustedRootIssuers: 'did:web:root.example' as unknown as string[] })).toThrow(TypeError);
    expect(() => createDidWebResolver(new RuntimeFetchProvider(), { trustedRootIssuers: [7] as unknown as string[] })).toThrow(TypeError);
    expect(() => new RuntimeFetchProvider({ statusListIssuers: { 'did:web:issuer.example': 'https://x.example' } as never })).toThrow(TypeError);
  });
});

describe('the opt-outs', () => {
  it('admit every private host under allowPrivateNetworkHosts or development, through the own fetch, resolving nothing', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    for (const optOut of [{ allowPrivateNetworkHosts: true }, { development: true }]) {
      const provider = new RuntimeFetchProvider({ ...seams, ...optOut });
      expect((await provider.resolveDID(AGENT))?.id).toBe(AGENT);
      expect(await provider.fetchStatusList('https://unbound.corp.example/1')).toMatchObject({ id: 'list' });
    }
    const developing = createDidWebResolver(new RuntimeFetchProvider(seams), { development: true });
    expect((await developing.resolve(AGENT))?.id).toBe(AGENT);
    expect({ asked, connected }).toEqual({ asked: [], connected: [] });
    expect(fetched).toHaveLength(5);
  });

  it('read a status list over http from a private or local host alone, and never from a public name', async () => {
    const open = new RuntimeFetchProvider({ ...seams, allowPrivateNetworkHosts: true });
    expect(await open.fetchStatusList('http://status.localhost/list')).toMatchObject({ id: 'list' });
    expect(await open.fetchStatusList('http://10.0.0.5/list')).toMatchObject({ id: 'list' });
    expect(await open.fetchStatusList('http://status.example/list')).toBeNull();
    expect(await new RuntimeFetchProvider(seams).fetchStatusList('http://status.example/list')).toBeNull();
    expect({ fetched, asked, connected }).toEqual({ fetched: ['http://status.localhost/list', 'http://10.0.0.5/list'], asked: [], connected: [] });
  });
});

describe('the rule on the URL alone', () => {
  it('holds a provider whose fetch is its own, a subclass included, since that fetch makes its own connections', async () => {
    class Proxied extends RuntimeFetchProvider {
      override fetch(url: string, init?: RequestInit): Promise<Response> {
        return globalThis.fetch(url, init);
      }
    }
    expect((await new Proxied(seams).resolveDID(AGENT))?.id).toBe(AGENT);
    expect(await new Proxied(seams).resolveDID('did:web:10.0.0.5')).toBeNull();
    const own = { fetch: (url: string, init?: RequestInit) => globalThis.fetch(url, init) } as unknown as FetchProvider;
    expect((await createDidWebResolver(own).resolve(AGENT))?.id).toBe(AGENT);
    expect({ fetched, asked, connected }).toEqual({ fetched: [AGENT_URL, AGENT_URL], asked: [], connected: [] });
  });

  it('holds RuntimeFetchProvider on a runtime whose node:dns resolves no name, as a Worker\'s throws "Not implemented"', async () => {
    vi.resetModules();
    vi.doMock('node:dns/promises', () => ({ lookup: async () => { throw new Error('Not implemented'); } }));
    const { RuntimeFetchProvider: Fresh } = await import('../runtime-fetch.js');
    const provider = new Fresh();
    expect((await provider.resolveDID(AGENT))?.id).toBe(AGENT);
    expect(await provider.resolveDID('did:web:10.0.0.5')).toBeNull();
    expect(fetched).toEqual([AGENT_URL]);
  });

  it('resolves through node:dns where it answers, with no lookup given, and refuses a name it resolves to a private address', async () => {
    vi.resetModules();
    const dnsLookup = vi.fn(async (hostname: string) =>
      [{ address: hostname === 'localhost' ? '127.0.0.1' : '10.0.0.7', family: 4 }]);
    vi.doMock('node:dns/promises', () => ({ lookup: dnsLookup }));
    const { RuntimeFetchProvider: Fresh } = await import('../runtime-fetch.js');
    expect(await new Fresh().resolveDID(AGENT)).toBeNull();
    expect(dnsLookup.mock.calls.map(([hostname]) => hostname)).toEqual(['localhost', 'root.corp.example']);
    expect(fetched).toEqual([]);
  });
});
