/**
 * SafeFetch's `operatorNamed`: the caller says, hop by hop, which URLs of a read its operator named,
 * as the status-list checker does for the lists `statusListIssuers` binds and a verified pinned
 * root's own list. A hop it names is read on any host, still pinned to the address looked up; every
 * other hop, a redirect from a named URL included, is held to the rule. The first request may be
 * http when it names that URL, as the operator binds a list's exact http URL; a redirect is https
 * alone. Only the caller's own `true` names a hop, so an answer of any other kind, a predicate that
 * throws and an init member that is not a function all name none.
 */

import { describe, expect, it, vi } from 'vitest';
import { createSafeFetch, type DnsLookup, type RawResponse, type TransportInit } from '../safe-fetch.js';

const PRIVATE = '10.0.0.7';
const NAMED = 'https://lists.corp.example/named';
const OTHER = 'https://lists.corp.example/other';

const lookup: DnsLookup = async () => [{ address: PRIVATE, family: 4 }];

/** A SafeFetch over a network that redirects `NAMED` to `OTHER` when `redirects`, and serves every other URL. */
function overPrivateHosts({ redirects = false } = {}) {
  const transport = vi.fn(async (url: string, _init: TransportInit): Promise<RawResponse> =>
    redirects && url === NAMED
      ? { status: 302, headers: { get: (name) => (name === 'location' ? OTHER : null) }, text: async () => '' }
      : { status: 200, headers: { get: () => null }, text: async () => '{"ok":true}' });
  const connected = () => transport.mock.calls.map(([url, init]) => [url, init.pinnedAddress]);
  return { fetch: createSafeFetch({ lookup, transport }), connected };
}

describe("SafeFetch's operatorNamed", () => {
  it('reads a hop it names on a private host, pinned to the address looked up', async () => {
    const net = overPrivateHosts();
    expect(await (await net.fetch(NAMED, { operatorNamed: (url) => url === NAMED })).json()).toEqual({ ok: true });
    expect(net.connected()).toEqual([[NAMED, PRIVATE]]);
  });

  it('holds a redirect from a named URL to one it does not name to the rule', async () => {
    const net = overPrivateHosts({ redirects: true });
    await expect(net.fetch(NAMED, { operatorNamed: (url) => url === NAMED })).rejects.toThrow(/non-public address/);
    expect(net.connected()).toEqual([[NAMED, PRIVATE]]);
  });

  it.each<[string, unknown]>([
    ['an answer other than true', () => 'yes'],
    ['a predicate that throws', () => { throw new Error('no'); }],
    ['a member that is not a function', true],
  ])('names no hop for %s', async (_case, operatorNamed) => {
    const net = overPrivateHosts();
    await expect(net.fetch(NAMED, { operatorNamed } as never)).rejects.toThrow(/non-public address/);
    expect(net.connected()).toEqual([]);
  });
});

describe('an http URL', () => {
  const HTTP = 'http://lists.corp.example/named';

  /** A SafeFetch over private hosts that answers `HTTP` with the list, and `NAMED` with a redirect to `HTTP`. */
  function overHttp() {
    const looked: string[] = [];
    const transport = vi.fn(async (url: string, _init: TransportInit): Promise<RawResponse> =>
      url === NAMED
        ? { status: 302, headers: { get: (name) => (name === 'location' ? HTTP : null) }, text: async () => '' }
        : { status: 200, headers: { get: () => null }, text: async () => '{"ok":true}' });
    const fetch = createSafeFetch({ lookup: async (name) => (looked.push(name), lookup(name)), transport });
    const connected = () => transport.mock.calls.map(([url, init]) => [url, init.pinnedAddress]);
    return { fetch, looked, connected };
  }

  it('is read as the first request when operatorNamed names it, on any host, pinned', async () => {
    const net = overHttp();
    expect(await (await net.fetch(HTTP, { operatorNamed: (url) => url === HTTP })).json()).toEqual({ ok: true });
    expect(net.connected()).toEqual([[HTTP, PRIVATE]]);
  });

  it('is refused before any lookup when operatorNamed does not name it', async () => {
    const net = overHttp();
    await expect(net.fetch(HTTP, { operatorNamed: (url) => url === NAMED })).rejects.toMatchObject({ kind: 'host_refused' });
    await expect(net.fetch(HTTP)).rejects.toThrow(/only https/);
    expect({ looked: net.looked, connected: net.connected() }).toEqual({ looked: [], connected: [] });
  });

  it('is no redirect target, even one operatorNamed names', async () => {
    const net = overHttp();
    await expect(net.fetch(NAMED, { operatorNamed: () => true })).rejects.toMatchObject({ kind: 'host_refused' });
    expect(net.connected()).toEqual([[NAMED, PRIVATE]]);
  });
});
