/**
 * SafeFetch's two real transports, over real sockets, refuse a body larger than the cap as a read
 * that came back too large (`too_large`), as SafeFetch refuses a declared length over the cap, so a
 * verifier codes the two alike: a DID document over the cap is `did_invalid` either way, never
 * `did_unavailable` for the one whose server streamed it without a length. `nodeHttpsTransport` is
 * read over TLS, from a server with a certificate made for the test that the default agent trusts
 * while the test runs; `fetchTransport`, which is scheme-agnostic, over plain HTTP on loopback.
 */
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import https from 'node:https';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createSafeFetch, fetchTransport, nodeHttpsTransport, type SafeFetchTransport, type TransportInit } from '../safe-fetch.js';
import { readFailureKind } from '../read-failure.js';
import { selfSignedTls } from '../../__tests__/utils/self-signed-tls.js';
import { safeFetchProvider } from '../../__tests__/utils/adopter-providers.js';
import { createDidWebResolver } from '../../delegation/did-web-resolver.js';

const HOST = 'status.example';
const CAP = 100;
const BODY = 'x'.repeat(5_000);

/** Answers a path under `/big` with {@link BODY} in chunks and no declared length, and anything else with `{}`. */
function serve(req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, { 'content-type': 'application/json' });
  if (!req.url?.startsWith('/big')) {
    res.end('{}');
    return;
  }
  for (let at = 0; at < BODY.length; at += 500) res.write(BODY.slice(at, at + 500));
  res.end();
}

const tls = selfSignedTls(HOST);
const httpsServer = https.createServer(tls, serve);
const httpServer = createHttpServer(serve);
const trusted = https.globalAgent.options.ca;
let httpsBase = '';
let httpBase = '';

/** Start `server` on 127.0.0.1 and resolve with its port. */
async function listen(server: https.Server | ReturnType<typeof createHttpServer>): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return (server.address() as { port: number }).port;
}

beforeAll(async () => {
  https.globalAgent.options.ca = [tls.cert];
  httpsBase = `https://${HOST}:${await listen(httpsServer)}`;
  httpBase = `http://127.0.0.1:${await listen(httpServer)}`;
});

afterAll(async () => {
  https.globalAgent.options.ca = trusted;
  for (const server of [httpsServer, httpServer]) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

/** What a transport is given for one hop to the loopback server, its body capped at {@link CAP} bytes. */
const init = (): TransportInit => ({ signal: new AbortController().signal, hostname: HOST, pinnedAddress: '127.0.0.1', family: 4, maxBytes: CAP });

/** What `read` rejected with, or `undefined` when it resolved. */
const rejection = (read: Promise<unknown>): Promise<unknown> => read.then(() => undefined, (error: unknown) => error);

describe.each<[string, SafeFetchTransport, () => string]>([
  ['nodeHttpsTransport, over TLS', nodeHttpsTransport, () => httpsBase],
  ['fetchTransport, over plain HTTP', fetchTransport, () => httpBase],
])('%s', (_name, transport, base) => {
  it('reads a body within the cap', async () => {
    expect(await (await transport(`${base()}/small`, init())).text()).toBe('{}');
  });

  it('refuses a body over the cap, streamed with no declared length, as too_large', async () => {
    const error = await rejection(transport(`${base()}/big`, init()));
    expect(error).toEqual(new Error(`safe-fetch: response body exceeds size cap ${CAP}`));
    expect(readFailureKind(error)).toBe('too_large');
  });
});

describe('createSafeFetch over the node:https transport', () => {
  /** SafeFetch over the real pinned transport, every name resolving to the loopback server, which `development: true` admits. */
  const loopbackSafeFetch = () =>
    createSafeFetch({ lookup: async () => [{ address: '127.0.0.1', family: 4 }], transport: nodeHttpsTransport, maxBytes: CAP, development: true });

  it('rejects a body over the cap as too_large', async () => {
    const safeFetch = loopbackSafeFetch();
    expect(await (await safeFetch(`${httpsBase}/small`)).json()).toEqual({});
    expect(readFailureKind(await rejection(safeFetch(`${httpsBase}/big`)))).toBe('too_large');
  });

  it('has the did:web resolver over it record a DID document over the cap as too large, which is no outage', async () => {
    const did = `did:web:${HOST}%3A${new URL(httpsBase).port}:big`;
    const resolver = createDidWebResolver(safeFetchProvider(loopbackSafeFetch()));
    expect(await resolver.resolve(did)).toBeNull();
    expect(resolver.lastFailure?.(did)?.cause).toBe('too_large');
  });
});
