/**
 * A read under the private-network rule, request by request, through a transport that offers its
 * connections: what reaches the pinned connection, how a name with no public address or a redirect
 * to one is refused and what each refusal says, and how a read held to https refuses http, first or
 * redirected. The lookup and the connection are stand-ins; nothing here resolves or connects.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { fetchStatusListJson } from '../../delegation/status-list-fetch.js';
import { checkResolvedAddresses } from '../address-check.js';
import { ADDRESS_PINNING, type PrivateNetworkTransport } from '../fetch-port.js';
import { underPrivateNetworkRead } from '../private-network-read.js';
import { ReadFailureError } from '../read-failure.js';
import { fetchTransport, type DnsLookup, type RawResponse, type SafeFetchTransport, type TransportInit } from '../safe-fetch.js';

const PUBLIC = { address: '93.184.216.34', family: 4 };
const PRIVATE = { address: '10.0.0.7', family: 4 };

/** A raw answer of `status`, `headers` and the body `bytes`. */
const raw = (status: number, headers: Record<string, string> = {}, bytes = new Uint8Array()): RawResponse => ({
  status,
  headers: { get: (name) => headers[name.toLowerCase()] ?? null },
  text: async () => new TextDecoder().decode(bytes),
  bytes: async () => bytes,
});

/** A transport whose names resolve as `addresses` says, public otherwise, and whose pinned connections `answer`. */
function offering(addresses: Record<string, (typeof PUBLIC)[]>, answer: (url: string) => RawResponse = () => raw(200)) {
  const asked: string[] = [];
  const connections: { url: string; init: TransportInit }[] = [];
  const own = vi.fn(async (_url: string, _init?: unknown) => new Response('{}'));
  const lookup: DnsLookup = async (name) => {
    asked.push(name);
    return addresses[name] ?? [PUBLIC];
  };
  const connect: SafeFetchTransport = async (url, init) => {
    connections.push({ url, init });
    return answer(url);
  };
  const transport: PrivateNetworkTransport = { fetch: own, [ADDRESS_PINNING]: async () => ({ lookup, transport: connect }) };
  return { transport, asked, connections, own };
}

/** What `read` rejects with. */
async function refusalOf(read: Promise<unknown>): Promise<ReadFailureError> {
  const error = await read.then(() => undefined, (thrown: unknown) => thrown);
  expect(error).toBeInstanceOf(ReadFailureError);
  return error as ReadFailureError;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('checkResolvedAddresses', () => {
  it('pins the first address when every one is public, and names the first that is not otherwise', () => {
    expect(checkResolvedAddresses([PUBLIC, { address: '2606:2800:220:1::', family: 6 }])).toEqual({ pinned: PUBLIC });
    expect(checkResolvedAddresses([PUBLIC, PRIVATE, { address: '::1', family: 6 }])).toEqual({ nonPublic: '10.0.0.7' });
    expect(checkResolvedAddresses([PUBLIC, PRIVATE], true)).toEqual({ pinned: PUBLIC });
    expect(checkResolvedAddresses([])).toEqual({ unresolved: true });
  });
});

describe('a read through a transport that offers its connections', () => {
  it('connects to the address it checked, with the reader\'s headers and signal and the read\'s byte cap', async () => {
    const { transport, asked, connections, own } = offering({}, () => raw(200, { 'content-type': 'application/json' }, new TextEncoder().encode('{"a":1}')));
    const signal = new AbortController().signal;
    const response = await underPrivateNetworkRead(transport, { maxBytes: 77 }).fetch('https://docs.example./a', {
      headers: { accept: 'application/json' }, signal,
    });
    expect(asked).toEqual(['docs.example']);
    expect(connections).toEqual([{
      url: 'https://docs.example./a',
      init: { signal, hostname: 'docs.example', pinnedAddress: PUBLIC.address, family: 4, maxBytes: 77, headers: { accept: 'application/json' } },
    }]);
    expect({ status: response.status, ok: response.ok, type: response.headers.get('content-type') }).toEqual({ status: 200, ok: true, type: 'application/json' });
    expect(await response.text()).toBe('{"a":1}');
    expect(own).not.toHaveBeenCalled();
  });

  it('hands the bounded reader the bytes that were sent, so a status list that is not UTF-8 is refused', async () => {
    const { transport } = offering({}, () => raw(200, {}, new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])));
    await expect(fetchStatusListJson(transport, 'https://status.example/list')).rejects.toThrow('not valid UTF-8');
  });

  it('reads a host written as an IP literal through its own fetch, resolving nothing', async () => {
    const { transport, asked, connections, own } = offering({});
    await underPrivateNetworkRead(transport).fetch('https://93.184.216.34/a');
    expect({ asked, connections: connections.length, own: own.mock.calls.map(([url]) => url) }).toEqual({
      asked: [], connections: 0, own: ['https://93.184.216.34/a'],
    });
  });

  it('refuses a name that resolves to no address, or to any address that is not public, without connecting, and says only what the URL says', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { transport, connections } = offering({ 'none.example': [], 'split.example': [PUBLIC, PRIVATE] });
    const read = underPrivateNetworkRead(transport);
    await expect(read.fetch('https://none.example/a')).rejects.toThrow('DNS lookup for "none.example" returned no addresses');
    const refused = await refusalOf(read.fetch('https://split.example/a'));
    expect({ kind: refused.kind, beforeRequest: refused.beforeRequest }).toEqual({ kind: 'host_refused', beforeRequest: false });
    expect(refused.message).toMatch(/^Request to "split\.example" refused: it resolves to a private or local address\. /);
    expect(refused.message).not.toContain(PRIVATE.address);
    expect(warn).toHaveBeenCalledWith('[kya-os] Request to "split.example" refused: it resolves to the non-public address 10.0.0.7');
    expect(connections).toEqual([]);
  });

  it('refuses a redirect to a name that resolves to a private address without naming it, and logs it with the address', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { transport, connections } = offering({ 'intranet.example': [PRIVATE] }, () => raw(302, { location: 'https://intranet.example/doc' }));
    const refused = await refusalOf(underPrivateNetworkRead(transport).fetch('https://public.example/doc'));
    expect(refused.message).toMatch(/^Redirect to a host that resolves to a private or local address refused\. /);
    expect(refused.message).not.toContain('intranet');
    expect(warn).toHaveBeenCalledWith('[kya-os] Redirect to "intranet.example" refused: it resolves to the non-public address 10.0.0.7');
    expect(connections.map(({ url }) => url)).toEqual(['https://public.example/doc']);
  });

  it('connects nothing once the read is aborted while its name resolves', async () => {
    const controller = new AbortController();
    const connections: string[] = [];
    const transport: PrivateNetworkTransport = {
      fetch: async () => new Response(),
      [ADDRESS_PINNING]: async () => ({
        lookup: async () => (controller.abort(new Error('deadline')), [PUBLIC]),
        transport: async (url) => (connections.push(url), raw(200)),
      }),
    };
    await expect(underPrivateNetworkRead(transport).fetch('https://slow.example/a', { signal: controller.signal })).rejects.toThrow('deadline');
    expect(connections).toEqual([]);
  });
});

describe('a read held to https', () => {
  const held = { httpsOnly: true } as const;

  it('refuses an http URL before any lookup, as decided from the URL alone, on a private host and under the opt-out too', async () => {
    const { transport, asked, own } = offering({});
    const opened = { ...transport, allowPrivateNetworkHosts: true };
    // Without the opt-out, the rule refuses a private host first, from its URL.
    const cases: [PrivateNetworkTransport, string][] = [
      [transport, 'http://status.example/list'],
      [opened, 'http://status.example/list'],
      [opened, 'http://status.localhost/list'],
      [opened, 'http://10.0.0.7/list'],
    ];
    for (const [reader, url] of cases) {
      const refused = await refusalOf(underPrivateNetworkRead(reader, held).fetch(url));
      expect({ message: refused.message, beforeRequest: refused.beforeRequest }).toEqual({
        message: 'Request to a "http:" URL refused: this read takes https, and http only at a URL the operator binds exactly, ' +
          'or from a private or local host under development: true',
        beforeRequest: true,
      });
    }
    expect({ asked, own: own.mock.calls.length }).toEqual({ asked: [], own: 0 });
  });

  it('reads http from a local host where it takes http there, and refuses its redirect to http on a public name', async () => {
    const own = vi.fn(async (url: string) =>
      url.startsWith('http://status.localhost/') ? new Response(null, { status: 302, headers: { location: 'http://status.example/list' } }) : Response.json({}));
    const opened: PrivateNetworkTransport = { fetch: own, allowPrivateNetworkHosts: true };
    const read = underPrivateNetworkRead(opened, { ...held, httpOnPrivateHosts: true });
    const refused = await refusalOf(read.fetch('http://status.localhost/moved', { redirect: 'manual' }));
    expect({ message: refused.message, beforeRequest: refused.beforeRequest }).toEqual({
      message: 'Redirect to a "http:" URL refused: this read takes https for every redirect, and http only from a private or local ' +
        'host under development: true',
      beforeRequest: false,
    });
    expect(own.mock.calls.map(([url]) => url)).toEqual(['http://status.localhost/moved']);
  });

  it('reads the first request over http when the operator names its URL, on any host, and never a redirect it did not choose', async () => {
    const own = vi.fn(async (url: string) =>
      url === 'http://status.example/old' ? new Response(null, { status: 302, headers: { location: 'http://status.example/new' } }) : Response.json({}));
    const read = underPrivateNetworkRead({ fetch: own }, { ...held, operatorNamed: (url) => url.startsWith('http://status.example/') });
    expect(await (await read.fetch('http://status.example/list')).json()).toEqual({});
    const refused = await refusalOf(read.fetch('http://status.example/old', { redirect: 'manual' }));
    expect(refused.message.split(' URL refused')[0]).toBe('Redirect to a "http:"');
    expect(own.mock.calls.map(([url]) => url)).toEqual(['http://status.example/list', 'http://status.example/old']);
  });
});

describe('fetchTransport', () => {
  it('sends the headers it is given, and hands back the body as the bytes that were sent', async () => {
    const sent = new Uint8Array([0x7b, 0xff, 0x7d]);
    const fetch = vi.fn(async (_url: string, _init?: RequestInit) => new Response(sent));
    vi.stubGlobal('fetch', fetch);
    const init: TransportInit = {
      signal: new AbortController().signal, hostname: 'status.example', pinnedAddress: PUBLIC.address, family: 4, maxBytes: 64,
      headers: { accept: 'application/json' },
    };
    const answer = await fetchTransport('https://status.example/list', init);
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ redirect: 'manual', headers: { accept: 'application/json' } });
    expect([...(await answer.bytes!())]).toEqual([...sent]);
  });
});
