/**
 * Status lists are read over https. Over http, an on-path party can replay an older signed list
 * from before a revocation. So a list a presenter names, and every redirect of any list's read, is
 * read over https alone, on a private host and under `allowPrivateNetworkHosts: true` too. The one
 * http URL read is one the operator chose: an exact URL its `statusListIssuers` binds, on any host,
 * public or private; an origin binding is `https://` alone. `development: true` still reads http
 * from a private or local host, for a local demo, and throws in production as it always has.
 *
 * The runtime's `fetch` is stubbed to serve every URL, and the provider's lookup and pinned
 * transport are recorded, so a read that was refused is one that reached neither.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger, RuntimeFetchProvider, type DnsLookup, type SafeFetchTransport } from '../../index.js';
import { assertStatusListIssuers } from '../../utils/statuslist-keeper.js';
import { PUBLIC_ADDRESS } from '../../__tests__/utils/runtime-network.js';

const KEEPER = 'did:web:keeper.example';
const LIST = {
  id: 'list', type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAA' },
};

/** Every URL the runtime's own `fetch` was asked for, every name looked up, and every pinned connection. */
const fetched: string[] = [];
const asked: string[] = [];
const connected: string[] = [];

const lookup: DnsLookup = async (name) => {
  asked.push(name);
  return [PUBLIC_ADDRESS];
};
const transport: SafeFetchTransport = async (url) => {
  connected.push(url);
  return { status: 200, headers: { get: () => null }, text: async () => JSON.stringify(LIST) };
};
const seams = { lookup, transport };
const bound = (...urls: string[]) => ({ ...seams, statusListIssuers: { [KEEPER]: urls } });

/** The runtime's `fetch`, serving the list at every URL but those `redirects` sends on. */
function serving(redirects: Record<string, string> = {}) {
  vi.stubGlobal('fetch', async (url: string) => {
    fetched.push(url);
    const location = redirects[url];
    return location === undefined ? Response.json(LIST) : new Response(null, { status: 302, headers: { location } });
  });
}

beforeEach(() => {
  for (const log of [fetched, asked, connected]) log.length = 0;
  vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  serving();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const reached = () => ({ fetched, asked, connected });
const NOTHING = { fetched: [], asked: [], connected: [] };

describe('a status list a presenter names over http', () => {
  it.each([
    ['a private IP literal, under allowPrivateNetworkHosts: true', { allowPrivateNetworkHosts: true }, 'http://10.0.0.7/list'],
    ['a local name, under allowPrivateNetworkHosts: true', { allowPrivateNetworkHosts: true }, 'http://lists.internal/list'],
    ['a public name', {}, 'http://lists.example/list'],
    ['a public name, under allowPrivateNetworkHosts: true', { allowPrivateNetworkHosts: true }, 'http://lists.example/list'],
    ['a URL at an https origin the operator binds, but over http', bound('https://lists.example'), 'http://lists.example/list'],
  ])('is refused on %s, never requested', async (_case, options, url) => {
    expect(await new RuntimeFetchProvider({ ...seams, ...options }).fetchStatusList(url)).toBeNull();
    expect(reached()).toEqual(NOTHING);
  });
});

describe('an exact http URL the operator binds in statusListIssuers', () => {
  it.each([
    ['a public name', 'http://lists.corp.example/list'],
    ['a local name', 'http://lists.internal/list'],
    ['a private IP literal', 'http://10.0.0.7/list'],
  ])('is read on %s, through the provider\'s own fetch', async (_case, url) => {
    expect(await new RuntimeFetchProvider(bound(url)).fetchStatusList(url)).toEqual(LIST);
    expect(reached()).toEqual({ fetched: [new URL(url).href], asked: [], connected: [] });
  });

  it('is one statusListIssuers accepts, as the read does', () => {
    expect(() => assertStatusListIssuers({ [KEEPER]: ['http://lists.corp.example/list', 'http://10.0.0.7/list'] })).not.toThrow();
  });

  it('is read for itself alone: a redirect from it to http is refused, even to another http URL the operator binds', async () => {
    const [first, second] = ['http://lists.corp.example/old', 'http://lists.corp.example/new'];
    serving({ [first]: second });
    expect(await new RuntimeFetchProvider(bound(first, second)).fetchStatusList(first)).toBeNull();
    expect(reached()).toEqual({ fetched: [first], asked: [], connected: [] });
  });

  it('may redirect to https, which is held to the rule', async () => {
    const first = 'http://lists.corp.example/old';
    serving({ [first]: 'https://cdn.example/list' });
    expect(await new RuntimeFetchProvider(bound(first)).fetchStatusList(first)).toEqual(LIST);
    expect(reached()).toEqual({ fetched: [first], asked: ['cdn.example'], connected: ['https://cdn.example/list'] });
  });
});

describe('development: true', () => {
  it('still reads http from a private or local host, and a redirect there, but never from a public name', async () => {
    serving({ 'http://status.localhost/old': 'http://10.0.0.7/list' });
    const developing = new RuntimeFetchProvider({ ...seams, development: true });
    expect(await developing.fetchStatusList('http://status.localhost/old')).toEqual(LIST);
    expect(await developing.fetchStatusList('http://lists.example/list')).toBeNull();
    expect(reached()).toEqual({ fetched: ['http://status.localhost/old', 'http://10.0.0.7/list'], asked: [], connected: [] });
  });

  it('still throws in production', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => new RuntimeFetchProvider({ development: true })).toThrow('development: true reads private and local hosts');
  });
});
