/**
 * A URL that includes credentials, `https://user:secret@host/`, is refused by every reader before
 * any request, as the runtime's `fetch` refuses it. The pinned transport would otherwise send them
 * as Basic credentials to the host the URL names, which a presenter chose; and a redirect could name
 * such a URL on the same origin. The refusal never echoes them.
 *
 * A real https server on 127.0.0.1 answers under a public name, and notes every request and the
 * credentials it carried.
 */

import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import https from 'node:https';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger, RuntimeFetchProvider } from '../../index.js';
import { createSafeFetch, nodeHttpsTransport, type DnsLookup, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import { closeLoopback, listenOnLoopback } from '../utils/loopback-server.js';
import { selfSignedTls } from '../utils/self-signed-tls.js';

const HOST = 'lists.example';
const LIST = { type: ['VerifiableCredential', 'StatusList2021Credential'], credentialSubject: { type: 'StatusList2021', encodedList: 'x' } };
const tls = selfSignedTls(HOST);
const trusted = https.globalAgent.options.ca;
/** Every request the server answered: its path, and the Authorization it carried. */
const served: { path: string; authorization?: string }[] = [];
let server: https.Server;
let port: number;

beforeAll(async () => {
  server = https.createServer(tls, (request: IncomingMessage, response: ServerResponse) => {
    served.push({ path: String(request.url), ...(request.headers.authorization ? { authorization: request.headers.authorization } : {}) });
    if (request.url === '/moves') return void response.writeHead(302, { location: `https://user:secret@${HOST}:${port}/list` }).end();
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(LIST));
  });
  https.globalAgent.options.ca = [tls.cert];
  port = await listenOnLoopback(server as unknown as Server);
});

beforeEach(() => {
  served.length = 0;
  vi.restoreAllMocks();
});

afterAll(async () => {
  https.globalAgent.options.ca = trusted;
  await closeLoopback(server as unknown as Server);
});

/** Every host the lookup was asked for. */
const looked: string[] = [];
const lookup: DnsLookup = async (hostname) => {
  looked.push(hostname);
  return [{ address: '93.184.216.34', family: 4 }];
};
/** The library's pinned transport, on a network where the public address it checked reaches the server. */
const transport: SafeFetchTransport = (url, init) => nodeHttpsTransport(url, { ...init, pinnedAddress: '127.0.0.1' });
const url = (path: string, userinfo = '') => `https://${userinfo}${HOST}:${port}${path}`;

describe('a URL that includes credentials', () => {
  beforeEach(() => {
    looked.length = 0;
  });

  it.each(['user:secret@', 'user@', ':secret@'])('is refused by SafeFetch before any lookup or request, as %s', async (userinfo) => {
    const safeFetch = createSafeFetch({ lookup, transport });
    for (const init of [undefined, { operatorNamed: () => true }]) {
      const refused = await safeFetch(url('/list', userinfo), init).then(() => undefined, (error: unknown) => error);
      expect(refused).toMatchObject({ kind: 'host_refused', beforeRequest: true, message: 'safe-fetch: refusing a URL that includes credentials' });
    }
    expect([looked, served]).toEqual([[], []]);
  });

  it('is refused by SafeFetch as a redirect target on the same origin', async () => {
    const refused = await createSafeFetch({ lookup, transport })(url('/moves')).then(() => undefined, (error: unknown) => error);
    expect(refused).toMatchObject({ kind: 'host_refused', message: 'safe-fetch: redirect to a URL that includes credentials blocked' });
    expect(served).toEqual([{ path: '/moves' }]);
  });

  it('is refused by RuntimeFetchProvider before any lookup or request, as a status list and as a redirect target', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const provider = new RuntimeFetchProvider({ lookup, transport });
    expect(await provider.fetchStatusList(url('/list', 'user:secret@'))).toBeNull();
    expect([looked, served]).toEqual([[], []]);
    expect(await provider.fetchStatusList(url('/moves'))).toBeNull();
    expect(served).toEqual([{ path: '/moves' }]);
    expect(warn.mock.calls.flat().map(String).filter((line) => line.includes('secret'))).toEqual([]);
  });
});
