/**
 * A pinned read connects to the address it checked over a connection of its own. `https.globalAgent`
 * keeps the sockets of the application's own requests alive and hands one to the next request for
 * the same host and port, whatever address that socket reached; and an application, or a package
 * such as global-agent, may replace that agent, or `https.request`, with one that sends every request
 * through a proxy, which resolves the host again. Either would carry a pinned read somewhere its
 * check never looked. So a pinned request takes an agent of its own, never pooled and never the
 * global one, keeping only the TLS settings an application gives `https.globalAgent`, such as a `ca`.
 *
 * A real https server on 127.0.0.1 answers under a public name, and real sockets throughout.
 */

import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createSafeFetch, nodeHttpsTransport, type DnsLookup, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import { closeLoopback, listenOnLoopback } from '../utils/loopback-server.js';
import { selfSignedTls } from '../utils/self-signed-tls.js';

const HOST = 'lists.example';
const PUBLIC = { address: '93.184.216.34', family: 4 } as const;
const LIST = { id: 'list', type: ['VerifiableCredential', 'StatusList2021Credential'] };

const tls = selfSignedTls(HOST);
const trusted = https.globalAgent.options.ca;
const original = { globalAgent: https.globalAgent, request: https.request, get: https.get };
/** The path of every request the server answered. */
const served: string[] = [];
let server: https.Server;
let port: number;

beforeAll(async () => {
  server = https.createServer(tls, (request: IncomingMessage, response: ServerResponse) => {
    served.push(String(request.url));
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(LIST));
  });
  https.globalAgent.options.ca = [tls.cert];
  port = await listenOnLoopback(server as unknown as Server);
});

beforeEach(() => {
  // No socket a test before this one left in the pool.
  https.globalAgent.destroy();
  served.length = 0;
});

afterEach(() => {
  Object.assign(https, original);
  https.globalAgent.destroy();
});

afterAll(async () => {
  https.globalAgent.options.ca = trusted;
  await closeLoopback(server as unknown as Server);
});

/** The application's own lookup of the host: 127.0.0.1, where the server listens. */
const toLoopback: LookupFunction = (_host, options, callback) => {
  if (typeof options === 'object' && options?.all) {
    (callback as unknown as (error: null, all: { address: string; family: number }[]) => void)(null, [{ address: '127.0.0.1', family: 4 }]);
  } else callback(null, '127.0.0.1', 4);
};

/** The application's own request for `path` on the host, through `https.globalAgent`, which keeps its socket alive after. */
function applicationReads(path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    https
      .get(`https://${HOST}:${port}${path}`, { lookup: toLoopback }, (response) => {
        response.resume();
        response.on('end', () => resolve());
      })
      .on('error', reject);
  });
}

/** A read pinned to `reaches`, which stands for the public address the lookup checked. */
function pinnedRead(path: string, reaches: { address: string; family: 4 | 6 }): Promise<string> {
  const lookup: DnsLookup = async () => [PUBLIC];
  const transport: SafeFetchTransport = (url, init) =>
    nodeHttpsTransport(url, { ...init, pinnedAddress: reaches.address, family: reaches.family, fallbackAddresses: [] });
  return createSafeFetch({ lookup, transport, timeoutMs: 5000 })(`https://${HOST}:${port}${path}`).then(
    (response) => `status ${response.status}`,
    () => 'refused',
  );
}

describe('a pinned read, beside the application’s own requests', () => {
  it('never reuses a socket the application left open to the same host, at another address', async () => {
    await applicationReads('/application');
    expect(Object.keys(https.globalAgent.freeSockets)).not.toEqual([]);
    // Pinned to ::1, where nothing listens: only a reused socket would reach the server.
    expect(await pinnedRead('/pinned', { address: '::1', family: 6 })).toBe('refused');
    expect(served).toEqual(['/application']);
  });

  it('leaves no socket of its own open after it is read', async () => {
    expect(await pinnedRead('/pinned', { address: '127.0.0.1', family: 4 })).toBe('status 200');
    expect(served).toEqual(['/pinned']);
    expect(Object.keys(https.globalAgent.freeSockets)).toEqual([]);
  });
});

describe('a pinned read, where the application replaces node:https’s global agent or request', () => {
  it('connects to its checked address, not through the agent or request installed in their place', async () => {
    const routed: string[] = [];
    /** An agent that would send each request to a proxy, as global-agent's does, and here refuses it. */
    class ProxyingAgent extends https.Agent {
      override addRequest(request: { destroy(error: Error): void }, options: { host?: string }): void {
        routed.push(String(options.host));
        request.destroy(new Error('sent to the proxy'));
      }
    }
    const replaced = (name: 'request' | 'get') => (...args: unknown[]) => {
      routed.push(`https.${name}`);
      return (original[name] as (...a: unknown[]) => unknown)(...args);
    };
    Object.assign(https, { globalAgent: new ProxyingAgent({ ca: [tls.cert] }), request: replaced('request'), get: replaced('get') });
    expect(await pinnedRead('/pinned', { address: '127.0.0.1', family: 4 })).toBe('status 200');
    expect(served).toEqual(['/pinned']);
    expect(routed).toEqual([]);
  });

  it('keeps the TLS settings the application gives the global agent, and nothing that routes', async () => {
    https.globalAgent.options.ca = undefined;
    expect(await pinnedRead('/untrusted', { address: '127.0.0.1', family: 4 })).toBe('refused');
    https.globalAgent.options.ca = [tls.cert];
    expect(await pinnedRead('/trusted', { address: '127.0.0.1', family: 4 })).toBe('status 200');
    expect(served).toEqual(['/trusted']);
  });
});
