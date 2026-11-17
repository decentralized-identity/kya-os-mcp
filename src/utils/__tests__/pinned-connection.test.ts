/**
 * One request through a pinned transport, answered as the `Response` a provider's `fetch` answers:
 * a real one, with the transport's status, the headers a read under the rule reads, and the body as
 * the bytes that were sent, so the bounded reader reads it as it reads any provider's.
 */

import { describe, expect, it } from 'vitest';
import { requestPinned } from '../pinned-connection.js';
import type { RawResponse, SafeFetchTransport, TransportInit } from '../safe-fetch-types.js';

const PIN = { address: '93.184.216.34', family: 4 } as const;

/** A transport that answers `raw` and records what it was asked. */
function answering(raw: RawResponse) {
  const asked: [string, TransportInit][] = [];
  const transport: SafeFetchTransport = async (url, init) => {
    asked.push([url, init]);
    return raw;
  };
  return { transport, asked };
}

const headersOf = (values: Record<string, string>): RawResponse['headers'] => ({ get: (name) => values[name] ?? null });

const pinned = (transport: SafeFetchTransport) =>
  requestPinned(transport, {
    url: 'https://lists.example/l',
    init: { headers: { accept: 'application/json' } },
    hostname: 'lists.example',
    pin: PIN,
    maxBytes: 1024,
  });

describe('a pinned request', () => {
  it('connects to the pinned address under the name, with the request headers, and answers a real Response', async () => {
    const bytes = new TextEncoder().encode('{"ok":true}');
    const { transport, asked } = answering({
      status: 200,
      headers: headersOf({ 'content-type': 'application/json', 'set-cookie': 'a=b' }),
      text: async () => '{"ok":true}',
      bytes: async () => bytes,
    });
    const response = await pinned(transport);
    expect(response).toBeInstanceOf(Response);
    expect({ ok: response.ok, status: response.status, redirected: response.redirected, url: response.url }).toEqual({
      ok: true, status: 200, redirected: false, url: '',
    });
    expect([...response.headers]).toEqual([['content-type', 'application/json']]);
    expect(await response.json()).toEqual({ ok: true });
    expect(asked.map(([url, init]) => [url, init.hostname, init.pinnedAddress, init.family, init.headers])).toEqual([
      ['https://lists.example/l', 'lists.example', PIN.address, 4, { accept: 'application/json' }],
    ]);
  });

  it('answers a redirect with its Location, and a status with no body without one', async () => {
    const redirect = await pinned(answering({ status: 302, headers: headersOf({ location: '/next' }), text: async () => 'moved' }).transport);
    expect([redirect.status, redirect.headers.get('location')]).toEqual([302, '/next']);
    const empty = await pinned(answering({ status: 204, headers: headersOf({}), text: async () => '' }).transport);
    expect([empty.status, empty.body]).toEqual([204, null]);
  });

  it.each([0, 103, 600, 999])('answers HTTP %i, which no final response has, as the host being unavailable', async (status) => {
    await expect(pinned(answering({ status, headers: headersOf({}), text: async () => '' }).transport)).rejects.toThrow(
      `The host answered HTTP ${status}, which is no final response`,
    );
  });
});
