/**
 * The cheqd registrar client posts through the checked redirects the cheqd resolver reads through
 * (`../../../utils/checked-redirects`). A POST follows only a 307 or 308, which keep its method and
 * body, only to the registrar's own origin, and at most 3 times, so the operator's headers and the
 * request body reach the registrar alone. The end-to-end tests post to real servers on 127.0.0.1
 * through `RuntimeFetchProvider`, whose runtime would otherwise follow 20 redirects to any host and
 * send every header but `Authorization` along.
 */

import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CheqdDidRegistrarClient, type CheqdRegistrarSigner } from '../registrar.js';
import { RuntimeFetchProvider } from '../../../providers/runtime-fetch.js';
import type { FetchProvider } from '../../../providers/base.js';
import { closeLoopback, listenOnLoopback } from '../../../__tests__/utils/loopback-server.js';

const DID = 'did:cheqd:testnet:6c9b1bbe-1a2c-4c1e-9d3c-2e0f0f0b0a01';
const didDocument = { '@context': ['https://www.w3.org/ns/did/v1'], id: DID, verificationMethod: [{ id: `${DID}#key-1` }] };
const FINISHED = JSON.stringify({ jobId: 'job-1', didState: { state: 'finished', did: DID } });
const headers = { 'x-api-key': 'operator-key' };
const signer: CheqdRegistrarSigner = async () => {
  throw new Error('a finished request asks for no signature');
};

interface Seen {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
}

/** A server on 127.0.0.1 that answers each request with `answer`, and records each. */
async function serving(answer: (path: string) => { status: number; location?: string; body?: string }) {
  const seen: Seen[] = [];
  const server: Server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk: Buffer) => (body += chunk.toString()));
    request.on('end', () => {
      seen.push({ method: request.method ?? '', path: request.url ?? '', headers: request.headers, body });
      const { status, location, body: answered } = answer(request.url ?? '');
      response.writeHead(status, location === undefined ? {} : { location, 'content-type': 'application/json' });
      response.end(answered);
    });
  });
  const origin = `http://127.0.0.1:${await listenOnLoopback(server)}`;
  servers.push(server);
  return { origin, seen };
}

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map(closeLoopback));
  vi.restoreAllMocks();
});

const client = (registrarUrl: string, fetchProvider: FetchProvider = new RuntimeFetchProvider()) =>
  new CheqdDidRegistrarClient({ registrarUrl, fetchProvider, headers });

describe('the cheqd registrar client, posting to a registrar that redirects', () => {
  it("sends its headers and body to no origin but the registrar's", async () => {
    const other = await serving(() => ({ status: 200, body: FINISHED }));
    const registrar = await serving(() => ({ status: 307, location: `http://localhost:${new URL(other.origin).port}/create` }));

    await expect(client(`${registrar.origin}/1.0`).createDid({ didDocument, signer }))
      .rejects.toThrow('Redirect of a POST to another origin refused');
    expect(registrar.seen).toHaveLength(1);
    expect(other.seen).toEqual([]);
  });

  it.each([307, 308])("follows a %i on the registrar's own origin, sending the same headers and body", async status => {
    const registrar = await serving(path => path === '/1.0/create'
      ? { status, location: '/2.0/create' }
      : { status: 200, body: FINISHED });

    const result = await client(`${registrar.origin}/1.0`).createDid({ didDocument, signer });

    expect(result).toMatchObject({ success: true, stage: 'complete' });
    expect(registrar.seen.map(({ method, path }) => [method, path])).toEqual([['POST', '/1.0/create'], ['POST', '/2.0/create']]);
    const [first, second] = registrar.seen;
    expect(second!.headers['x-api-key']).toBe('operator-key');
    expect(second!.body).toBe(first!.body);
    expect(JSON.parse(second!.body)).toEqual({ didDocument });
  });

  it('follows at most 3 redirects', async () => {
    const registrar = await serving(path => ({ status: 307, location: `${path}x` }));

    await expect(client(`${registrar.origin}/1.0`).createDid({ didDocument, signer })).rejects.toThrow('Redirect limit of 3 exceeded');
    expect(registrar.seen).toHaveLength(4);
  });

  it.each([301, 302, 303])('refuses a %i, which would not send the body again, after one request', async status => {
    const registrar = await serving(() => ({ status, location: '/2.0/create' }));

    await expect(client(`${registrar.origin}/1.0`).createDid({ didDocument, signer }))
      .rejects.toThrow(`Redirect of a POST by HTTP ${status} refused`);
    expect(registrar.seen).toHaveLength(1);
  });
});

describe("the cheqd registrar client's requests", () => {
  const stub = (respond: () => Response) => {
    const fetch = vi.fn(async (_url: string, _init?: RequestInit) => respond());
    return { fetch, provider: { fetch, resolveDID: vi.fn(), fetchStatusList: vi.fn(), fetchDelegationChain: vi.fn() } as FetchProvider };
  };

  it("ask the fetch provider for redirect: 'manual'", async () => {
    const { fetch, provider } = stub(() => new Response(FINISHED));
    await client('https://registrar.example/1.0', provider).createDid({ didDocument, signer });
    expect(fetch.mock.calls[0]![1]).toMatchObject({ method: 'POST', redirect: 'manual' });
  });

  it('refuse a response the provider reached by following a redirect itself', async () => {
    const { provider } = stub(() => Object.defineProperty(new Response(FINISHED), 'redirected', { value: true }));
    await expect(client('https://registrar.example/1.0', provider).createDid({ didDocument, signer }))
      .rejects.toThrow('Redirect followed by the fetch provider refused');
  });

  it('refuse a registrar URL that is not http or https, before any request', async () => {
    const { fetch, provider } = stub(() => new Response(FINISHED));
    await expect(client('ftp://registrar.example/1.0', provider).createDid({ didDocument, signer }))
      .rejects.toThrow('Request to a "ftp:" URL refused');
    expect(fetch).not.toHaveBeenCalled();
  });
});
