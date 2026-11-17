/**
 * The hosts the operator names are read wherever they are: a status-list URL `statusListIssuers`
 * binds, exactly or by its https origin, and the did:web document of a DID in `trustedRootIssuers`.
 * That is decided request by request, on the URL each request asks for, as SafeFetch decides its
 * `allowOrigins`. With an origin binding the presenter still writes the path, so an open redirect on
 * the operator's host, a CDN rule or a compromised list host must not carry the read to a private
 * literal, to a name that resolves to a private address, or to the cloud metadata address: each
 * redirect to a URL the operator did not name is held to the rule, resolved, checked and pinned.
 *
 * The provider's `lookup` and `transport` seams stand for DNS and the pinned connection, and the
 * runtime's `fetch`, which reads an operator's URL, is stubbed to serve each route.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger, RuntimeFetchProvider } from '../../index.js';
import type { DnsLookup, SafeFetchTransport } from '../../index.js';

const PRIVATE = { address: '10.0.0.7', family: 4 } as const;
const PUBLIC = { address: '93.184.216.34', family: 4 } as const;
const KEEPER = 'did:web:keeper.example';
const PRESENTED = 'https://lists.example/go?to=x';

/** A list for the read to find; the provider only retrieves it. */
const LIST = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  id: 'https://lists.example/r',
  type: ['VerifiableCredential', 'StatusList2021Credential'],
  issuer: KEEPER,
  credentialSubject: { id: 'https://lists.example/r#list', type: 'StatusList2021', statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA' },
};

const redirectTo = (location: string) => () => new Response(null, { status: 302, headers: { location } });

/** Every URL the runtime's own `fetch` was asked for, every name looked up, and every pinned connection. */
const fetched: string[] = [];
const looked: string[] = [];
const connected: string[] = [];

const lookup: DnsLookup = async (name) => {
  looked.push(name);
  return [name === 'intranet.example' ? PRIVATE : PUBLIC];
};
const transport: SafeFetchTransport = async (url) => {
  connected.push(url);
  return { status: 200, headers: { get: () => null }, text: async () => JSON.stringify(LIST) };
};

/** The runtime's `fetch` serving `routes`, looked up by own key alone, and 404 for any other URL. */
function serving(routes: Record<string, () => Response>) {
  const served = new Map(Object.entries(routes));
  vi.stubGlobal('fetch', async (url: string) => {
    fetched.push(url);
    return served.get(url)?.() ?? new Response('not found', { status: 404 });
  });
}

beforeEach(() => {
  fetched.length = 0;
  looked.length = 0;
  connected.length = 0;
  vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('a status-list origin the operator binds, and a path the presenter writes that redirects', () => {
  const provider = () => new RuntimeFetchProvider({ lookup, transport, statusListIssuers: { [KEEPER]: ['https://lists.example'] } });

  it.each([
    ['a private IP literal', 'https://10.0.0.7/list', []],
    ['the cloud metadata address', 'https://169.254.169.254/list', []],
    ['a name that resolves to a private address', 'https://intranet.example/list', ['intranet.example']],
  ])('refuses the redirect to %s, never reading it', async (_what, target, lookups) => {
    serving({ [PRESENTED]: redirectTo(target), [target]: () => Response.json(LIST) });
    expect(await provider().fetchStatusList(PRESENTED)).toBeNull();
    expect({ fetched, looked, connected }).toEqual({ fetched: [PRESENTED], looked: lookups, connected: [] });
  });

  it('resolves, checks and pins a redirect to a public name it does not bind', async () => {
    serving({ [PRESENTED]: redirectTo('https://cdn.example/list') });
    expect(await provider().fetchStatusList(PRESENTED)).toEqual(LIST);
    expect({ fetched, looked, connected }).toEqual({ fetched: [PRESENTED], looked: ['cdn.example'], connected: ['https://cdn.example/list'] });
  });

  it('reads a redirect to another URL at the origin it binds as its own', async () => {
    serving({ [PRESENTED]: redirectTo('https://lists.example/r'), 'https://lists.example/r': () => Response.json(LIST) });
    expect(await provider().fetchStatusList(PRESENTED)).toEqual(LIST);
    expect({ fetched, looked, connected }).toEqual({ fetched: [PRESENTED, 'https://lists.example/r'], looked: [], connected: [] });
  });

  it('holds a redirect from a URL it binds exactly to any other URL at that origin', async () => {
    const exact = new RuntimeFetchProvider({ lookup, transport, statusListIssuers: { [KEEPER]: [PRESENTED] } });
    serving({ [PRESENTED]: redirectTo('https://lists.example/r') });
    expect(await exact.fetchStatusList(PRESENTED)).toEqual(LIST);
    expect({ fetched, looked, connected }).toEqual({ fetched: [PRESENTED], looked: ['lists.example'], connected: ['https://lists.example/r'] });
  });
});

describe('the document of a DID the operator pins, whose host redirects', () => {
  const ROOT = 'did:web:root.example';
  const ROOT_URL = 'https://root.example/.well-known/did.json';
  const provider = () => new RuntimeFetchProvider({ lookup, transport, trustedRootIssuers: [ROOT] });

  it('refuses the redirect to a private literal, never reading it', async () => {
    serving({ [ROOT_URL]: redirectTo('https://10.0.0.7/did.json'), 'https://10.0.0.7/did.json': () => Response.json({ id: ROOT }) });
    expect(await provider().resolveDID(ROOT)).toBeNull();
    expect({ fetched, looked, connected }).toEqual({ fetched: [ROOT_URL], looked: [], connected: [] });
  });

  it('refuses the redirect to a name that resolves to a private address after looking it up', async () => {
    serving({ [ROOT_URL]: redirectTo('https://intranet.example/did.json') });
    expect(await provider().resolveDID(ROOT)).toBeNull();
    expect({ fetched, looked, connected }).toEqual({ fetched: [ROOT_URL], looked: ['intranet.example'], connected: [] });
  });

  it('still reads the document at its own URL on a private host', async () => {
    const lookupPrivate: DnsLookup = async (name) => {
      looked.push(name);
      return [PRIVATE];
    };
    serving({ [ROOT_URL]: () => Response.json({ '@context': 'https://www.w3.org/ns/did/v1', id: ROOT }) });
    const document = await new RuntimeFetchProvider({ lookup: lookupPrivate, transport, trustedRootIssuers: [ROOT] }).resolveDID(ROOT);
    expect(document?.id).toBe(ROOT);
    expect({ fetched, looked, connected }).toEqual({ fetched: [ROOT_URL], looked: [], connected: [] });
  });
});
