/**
 * The pinned transport, `nodeHttpsTransport`, reads a host as honestly as the runtime's `fetch` it
 * replaced for every did:web and status-list read on Node. That `fetch` sends `Accept: *\/*`, a
 * `User-Agent` and `Accept-Encoding`, and decodes the body, so a host that serves its JSON gzipped
 * whatever the request says, as an object store or a CDN rule does, was read. The pinned transport
 * sends the same `Accept`, a `User-Agent` and `Accept-Encoding: gzip`, and decodes gzip through the
 * package's one capped decompressor, so the byte cap holds the decoded body. An encoding it does not
 * decode is refused, and the log says which.
 *
 * A real https server on 127.0.0.1 answers under a public name: the lookup answers a public address,
 * and the transport connects to 127.0.0.1.
 */

import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from 'node:http';
import https from 'node:https';
import { brotliCompressSync, gzipSync } from 'node:zlib';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidWebResolver, logger, RuntimeFetchProvider } from '../../index.js';
import { createSafeFetch, nodeHttpsTransport, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import { closeLoopback, listenOnLoopback } from '../utils/loopback-server.js';
import { publicLookup } from '../utils/runtime-network.js';
import { selfSignedTls } from '../utils/self-signed-tls.js';

const HOST = 'did-host.example';
const tls = selfSignedTls(HOST);
const trusted = https.globalAgent.options.ca;
let server: https.Server;
let port: number;
/** The headers of each request the server was sent. */
const seen: IncomingHttpHeaders[] = [];

const LIST = {
  id: 'list', type: ['VerifiableCredential', 'StatusList2021Credential'],
  credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAA' },
};

/**
 * Each path's body and the encoding it is served in, whatever the request asked for. A `Map`, so a
 * request's path names one of these routes or none, never a property every object has.
 */
const ROUTES: ReadonlyMap<string, () => [string, Buffer]> = new Map([
  ['/.well-known/did.json', () => ['gzip', gzipSync(JSON.stringify({ '@context': 'https://www.w3.org/ns/did/v1', id: didOf(port) }))]],
  ['/list', () => ['gzip', gzipSync(JSON.stringify(LIST))]],
  ['/x-gzip', () => ['x-gzip', gzipSync('{"ok":true}')]],
  ['/plain', () => ['identity', Buffer.from('{"ok":true}')]],
  ['/bomb', () => ['gzip', gzipSync(' '.repeat(2 * 1024 * 1024))]],
  ['/brotli', () => ['br', brotliCompressSync('{"ok":true}')]],
  ['/twice', () => ['gzip, gzip', gzipSync(gzipSync('{"ok":true}'))]],
  ['/not-gzip', () => ['gzip', Buffer.from('{"ok":true}')]],
]);

const didOf = (at: number) => `did:web:${HOST}%3A${at}`;

beforeAll(async () => {
  server = https.createServer(tls, (request: IncomingMessage, response: ServerResponse) => {
    seen.push(request.headers);
    const route = ROUTES.get(request.url ?? '');
    if (route === undefined) {
      response.writeHead(404).end();
      return;
    }
    const [encoding, body] = route();
    response.writeHead(200, { 'content-type': 'application/json', 'content-encoding': encoding, 'content-length': body.length }).end(body);
  });
  https.globalAgent.options.ca = [tls.cert];
  port = await listenOnLoopback(server as unknown as Server);
});

afterAll(async () => {
  https.globalAgent.options.ca = trusted;
  await closeLoopback(server as unknown as Server);
});

beforeEach(() => {
  seen.length = 0;
  vi.restoreAllMocks();
});

/** The library's pinned transport, on a network where the public address it checked reaches the server. */
const transport: SafeFetchTransport = (url, init) => nodeHttpsTransport(url, { ...init, pinnedAddress: '127.0.0.1' });
const url = (path: string) => `https://${HOST}:${port}${path}`;
const read = (path: string, headers?: Record<string, string>) =>
  transport(url(path), { signal: new AbortController().signal, hostname: HOST, pinnedAddress: '93.184.216.34', family: 4, maxBytes: 1024 * 1024, ...(headers ? { headers } : {}) });

describe('a host that serves gzip whatever the request asks', () => {
  it('is read, its did:web document and its status list, as the runtime fetch read it', async () => {
    const provider = new RuntimeFetchProvider({ lookup: publicLookup, transport });
    const resolver = createDidWebResolver(provider);
    expect((await resolver.resolve(didOf(port)))?.id).toBe(didOf(port));
    expect(await provider.fetchStatusList(url('/list'))).toEqual(LIST);
  });

  it('is read through SafeFetch too, which shares the transport', async () => {
    const fetch = createSafeFetch({ lookup: publicLookup, transport });
    expect(await (await fetch(url('/list'))).json()).toEqual(LIST);
  });

  it('is read as x-gzip, which says no encoding or length once decoded, and as identity, as sent', async () => {
    const decoded = await read('/x-gzip');
    expect([await decoded.text(), decoded.headers.get('content-encoding'), decoded.headers.get('content-length')]).toEqual(['{"ok":true}', null, null]);
    const plain = await read('/plain');
    expect([await plain.text(), plain.headers.get('content-encoding'), plain.headers.get('content-length')]).toEqual(['{"ok":true}', 'identity', '11']);
  });
});

describe('the request the pinned transport sends', () => {
  it("sends the runtime fetch's Accept, a User-Agent, and the one encoding it decodes", async () => {
    await read('/plain');
    expect(seen[0]).toMatchObject({ accept: '*/*', 'user-agent': 'node', 'accept-encoding': 'gzip' });
  });

  it("keeps the reader's own Accept, in any case", async () => {
    await read('/plain', { Accept: 'application/json' });
    expect(seen[0]).toMatchObject({ accept: 'application/json', 'user-agent': 'node', 'accept-encoding': 'gzip' });
  });
});

describe('a body the pinned transport cannot read as sent', () => {
  it('is refused as too large when it inflates past the cap, which holds the decoded body', async () => {
    await expect(read('/bomb')).rejects.toMatchObject({ kind: 'too_large' });
  });

  it.each([
    ['br', '/brotli'],
    ['gzip, gzip', '/twice'],
  ])('is refused when encoded as "%s", which it does not decode, and the log says so', async (encoding, path) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await expect(read(path)).rejects.toMatchObject({ kind: 'unavailable' });
    expect(warn.mock.calls.map(([line]) => String(line))).toEqual([
      `[kya-os] safe-fetch: ${HOST} answered with Content-Encoding "${encoding}", which is not decoded, so the response is refused`,
    ]);
  });

  it('is refused as unreadable when it says gzip and is not', async () => {
    await expect(read('/not-gzip')).rejects.toMatchObject({ kind: 'unavailable' });
  });
});
