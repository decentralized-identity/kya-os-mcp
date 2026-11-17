/**
 * One rule for a status list over http, on the Card checker's path as on the provider's. Over http,
 * an on-path party can replay an older signed list from before a revocation, so a list a presenter
 * names is read over https alone. The one http URL read is one the operator chose: an exact URL its
 * `statusListIssuers` binds, on any host, public or private, and for itself alone, so a redirect from
 * it is held to https. An origin binding is `https://` alone, and a pinned root's own list, which
 * the root's credential names and the operator does not, is read over https alone too.
 *
 * Every list is signed by a real key and checked by the shipped verifiers. DNS and the connection
 * are faked, except in the last case, where a real http server on 127.0.0.1 serves the list through
 * SafeFetch's default transport.
 */

import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { createSafeFetch, type DnsLookup, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import type { StatusCheckContext } from '../../utils/statuslist-keeper.js';
import { verifiedRootContext } from '../../utils/verified-root.js';
import { closeLoopback, listenOnLoopback } from '../../__tests__/utils/loopback-server.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { now, parties, statusList, type TestIdentity } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const PRIVATE = '10.0.0.7';
const PUBLIC = '93.184.216.34';

/** The list at `url` that `signer` signed, with `revoked` bits set. */
const listAt = (signer: TestIdentity, url: string, revoked: number[] = []) =>
  statusList(signer, revoked, { id: url, credentialSubject: { id: `${url}#list` } });

/** A revocation entry at bit 3 of the list at `url`. */
const entryAt = (url: string) => ({ statusListCredential: url, statusListIndex: '3', statusPurpose: 'revocation' });

/** A redirect the network answers in place of a list. */
type Moved = { readonly location: string };

/** A network on which every name under corp.example is private, serving `lists` and recording each lookup and connection. */
function network(lists: Record<string, Record<string, unknown> | Moved>) {
  const connected: [string, string][] = [];
  const looked: string[] = [];
  const lookup: DnsLookup = async (name) => {
    looked.push(name);
    return [{ address: name.endsWith('corp.example') ? PRIVATE : PUBLIC, family: 4 }];
  };
  const transport: SafeFetchTransport = async (url, init) => {
    connected.push([url, init.pinnedAddress]);
    const body = lists[url];
    if (body !== undefined && 'location' in body) {
      const { location } = body as Moved;
      return { status: 302, headers: { get: (name) => (name === 'location' ? location : null) }, text: async () => '' };
    }
    return { status: body ? 200 : 404, headers: { get: () => null }, text: async () => JSON.stringify(body ?? {}) };
  };
  const checker = (statusListIssuers?: Record<string, string[]>) =>
    createRevocationChecker({
      fetch: createSafeFetch({ lookup, transport }),
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
      ...(statusListIssuers ? { statusListIssuers } : {}),
    });
  return { connected, looked, checker };
}

describe('an exact http URL statusListIssuers binds, read by the Card checker', () => {
  it.each([
    ['a public name', 'http://lists.example/agent', PUBLIC],
    ['a private host', 'http://lists.corp.example/agent', PRIVATE],
  ])('is read on %s, pinned to the address looked up', async (_case, url, address) => {
    const p = parties();
    const net = network({ [url]: listAt(p.agent, url) });
    const verdict = await net.checker({ [p.agent.did]: [url] })(entryAt(url), { credentialIssuer: p.agent.did });
    expect(verdict).toMatchObject({ revoked: false, fresh: true });
    expect(net.connected).toEqual([[url, address]]);
  });

  it('is read for itself alone: a redirect from it is refused, even to another http URL the operator binds', async () => {
    const p = parties();
    const [first, second] = ['http://lists.corp.example/old', 'http://lists.corp.example/new'];
    const net = network({ [first]: { location: second }, [second]: listAt(p.agent, second) });
    const verdict = await net.checker({ [p.agent.did]: [first, second] })(entryAt(first), { credentialIssuer: p.agent.did });
    expect(verdict).toMatchObject({ revoked: true, fresh: false });
    expect(net.connected).toEqual([[first, PRIVATE]]);
  });
});

describe('a status list over http the operator did not bind exactly', () => {
  it.each([
    ['a presenter names on a public name', 'http://lists.example/agent', undefined],
    ['a presenter names on a private host', 'http://lists.corp.example/agent', undefined],
    ['sits at an https origin the operator binds', 'http://lists.example/agent', ['https://lists.example']],
  ])('is refused when %s, before any lookup or connection', async (_case, url, bound) => {
    const p = parties();
    const net = network({ [url]: listAt(p.agent, url) });
    const verdict = await net.checker(bound ? { [p.agent.did]: bound } : undefined)(entryAt(url), { credentialIssuer: p.agent.did });
    expect(verdict).toMatchObject({ revoked: true, fresh: false, code: 'host_refused' });
    expect({ looked: net.looked, connected: net.connected }).toEqual({ looked: [], connected: [] });
  });

  it("is refused when a verified pinned root's own credential names it", async () => {
    const p = parties();
    const url = 'http://lists.corp.example/acme';
    const net = network({ [url]: listAt(p.acme, url) });
    const context = verifiedRootContext<StatusCheckContext>({
      credentialIssuer: p.acme.did, trustedRootIssuer: p.acme.did, trustedRootStatusList: url,
    });
    expect(await net.checker()(entryAt(url), context)).toMatchObject({ revoked: true, fresh: false, code: 'host_refused' });
    expect({ looked: net.looked, connected: net.connected }).toEqual({ looked: [], connected: [] });
  });
});

describe("SafeFetch's default transport and a bound http list", () => {
  let server: Server;
  let port: number;
  let served: Record<string, unknown> = {};
  const requested: string[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      requested.push(request.url ?? '');
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(served));
    });
    port = await listenOnLoopback(server);
  });

  afterAll(async () => {
    await closeLoopback(server);
  });

  it('reads it over node:http, connected to the address looked up', async () => {
    const p = parties();
    const url = `http://lists.corp.example:${port}/agent`;
    served = listAt(p.agent, url);
    const lookup: DnsLookup = async () => [{ address: '127.0.0.1', family: 4 }];
    const checker = createRevocationChecker({
      fetch: createSafeFetch({ lookup }),
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
      statusListIssuers: { [p.agent.did]: [url] },
    });
    expect(await checker(entryAt(url), { credentialIssuer: p.agent.did })).toMatchObject({ revoked: false, fresh: true });
    expect(requested).toEqual(['/agent']);
  });
});
