/**
 * The delegation gate reads an issuer's did:web document under the package's private-network rule,
 * whichever fetch provider it reads through: a DID whose host is a private IP literal or a local
 * name is refused before any request, and a redirect is followed by hand, its target held to the
 * same rule, so the read never reaches a loopback address. A provider that follows a redirect
 * itself has made that request before the gate sees the response, so the gate refuses the document
 * it returns. The one opt-out, `allowPrivateNetworkHosts`, is honoured on the provider the host
 * supplies. `RuntimeFetchProvider.resolveDID`, and `ProofVerifier` through it, apply the same rule.
 * The document of a root the operator pins in `trustedRootIssuers` is read wherever it is, so each
 * other case lets the gate admit any root instead, as the rule binds every DID the operator did not name.
 *
 * A real server on 127.0.0.1 stands in for every host. The gate reads through a `RuntimeFetchProvider`
 * as it builds one, its every name resolved to a public address and each request sent through the
 * runtime's `fetch`. That `fetch` is wrapped only so that it speaks plain HTTP to that server: it
 * keeps the host, port, path and redirect mode it is given, sends the one public name below and the
 * local names to 127.0.0.1, and reports the URL it was asked for unless the runtime followed a redirect.
 */

import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDelegationVerification } from '../with-kya-os.delegation-verify.js';
import type { MiddlewareDeps } from '../with-kya-os.deps.js';
import type { KyaOsDelegationConfig } from '../with-kya-os.config-types.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { AgentIdentity, FetchProvider } from '../../providers/base.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { ProofVerifier } from '../../proof/verifier.js';
import { SystemClockProvider } from '../../providers/system-clock.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import { LOCAL_HOST_NAMES } from '../../__tests__/utils/local-host-names.js';
import { closeLoopback, listenOnLoopback } from '../../__tests__/utils/loopback-server.js';
import { OVER_STUBBED_FETCH } from '../../__tests__/utils/runtime-network.js';

const crypto = new NodeCryptoProvider();
const SERVER = 'did:web:server.example';
/** A name the wrapped `fetch` sends to 127.0.0.1, standing for a public host. */
const PUBLIC = 'did-host.example';
const realFetch = globalThis.fetch;

let server: Server;
let port: number;
/** The one key every DID in this file publishes and signs with; each names it `<did>#key`. */
let key: AgentIdentity;
/** The path of every request the server received. */
const served: string[] = [];
/**
 * Where the server redirects each path it redirects, written once the port is known. Every target
 * is one the test names: nothing a request states reaches a `Location` header.
 */
const hops = new Map<string, string>();

const didOf = (host: string, ...path: string[]) => ['did:web', encodeURIComponent(host), ...path].join(':');
const redirectDid = () => didOf(`${PUBLIC}:${port}`, 'hop');
/** A DID on the public name whose document the server serves without a redirect. */
const directDid = () => didOf(`${PUBLIC}:${port}`, 'direct');

/** The DID document of `did`, publishing `key` under assertionMethod. */
const documentOf = (did: string) => issuerDidDocument(methodOf({ ...key, did, kid: `${did}#key` }));

beforeAll(async () => {
  key = await keyOf(SERVER, 'key');
  server = createServer((request, response) => {
    served.push(request.url!);
    const location = hops.get(request.url!);
    if (location !== undefined) {
      response.writeHead(302, { location }).end();
      return;
    }
    const did = request.url === '/internal/did.json' ? redirectDid() : request.url === '/direct/did.json' ? directDid() : didOf(request.headers.host!);
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(documentOf(did)));
  });
  port = await listenOnLoopback(server);
  hops.set('/hop/did.json', `http://127.0.0.1:${port}/internal/did.json`);
  hops.set('/hop-localhost/did.json', `https://localhost:${port}/internal/did.json`);
  for (const name of LOCAL_HOST_NAMES) hops.set(`/hop-to/${name}/did.json`, `https://${name}:${port}/internal/did.json`);
});

afterAll(async () => {
  await closeLoopback(server);
});

beforeEach(() => {
  served.length = 0;
  vi.stubGlobal('fetch', async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    url.protocol = 'http:';
    if (url.hostname === PUBLIC || (LOCAL_HOST_NAMES as readonly string[]).includes(url.hostname)) url.hostname = '127.0.0.1';
    const response = await realFetch(url.href, init);
    return response.redirected ? response : Object.defineProperty(response, 'url', { value: input });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** A root delegation `did` issues and signs with the one key, under the id `documentOf(did)` publishes it by. */
function credential(did: string): Promise<DelegationCredential> {
  return signedCredential({ ...key, did, kid: `${did}#key` }, {
    record: delegationRecord(did, {
      id: 'del-1', vcId: 'urn:uuid:del-1',
      constraints: { scopes: ['tools:read'], audience: SERVER, notAfter: Math.floor(Date.now() / 1000) + 3600 },
    }),
  });
}

/** Whether the gate, admitting any root and reading through the provider it builds unless `config` says otherwise, accepts a delegation `did` issues. */
async function accepts(did: string, config: KyaOsDelegationConfig = {}): Promise<boolean> {
  const { verifyDelegation } = createDelegationVerification({
    identity: { did: SERVER }, cryptoProvider: crypto,
    delegationConfig: { allowAnyRootIssuer: true, fetchProvider: new RuntimeFetchProvider(OVER_STUBBED_FETCH), ...config },
  } as unknown as MiddlewareDeps);
  return (await verifyDelegation(await credential(did))).valid;
}

describe("the gate's did:web read", () => {
  it('reads the document of a root the operator pins wherever it is, and holds the same DID to the rule unpinned', async () => {
    const did = didOf(`127.0.0.1:${port}`);
    const pinned = { allowAnyRootIssuer: undefined, trustedRootIssuers: [did] };
    const accepted = [await accepts(did, pinned), await accepts(did)];
    expect({ accepted, served }).toEqual({ accepted: [true, false], served: ['/.well-known/did.json'] });
  });

  it('refuses a DID whose host is a private IP literal, IPv4 or IPv4-mapped IPv6, without a request', async () => {
    const accepted = [await accepts(didOf(`127.0.0.1:${port}`)), await accepts(didOf(`[::ffff:7f00:1]:${port}`))];
    expect({ accepted, served }).toEqual({ accepted: [false, false], served: [] });
  });

  it('refuses a DID whose host is localhost or a name under it, in any case and with a trailing dot, without a request', async () => {
    const hosts = ['localhost', 'LocalHost', 'localhost.', 'api.localhost', 'api.LOCALHOST.'];
    const accepted = [];
    for (const host of hosts) accepted.push(await accepts(didOf(`${host}:${port}`)));
    expect({ accepted, served }).toEqual({ accepted: hosts.map(() => false), served: [] });
  });

  it('refuses a DID whose host is another local name, a single label or a name under a special-use domain, without a request', async () => {
    const accepted = [];
    for (const name of LOCAL_HOST_NAMES) accepted.push(await accepts(didOf(`${name}:${port}`)));
    expect({ accepted, served }).toEqual({ accepted: LOCAL_HOST_NAMES.map(() => false), served: [] });
  });

  it('refuses a redirect to a local name without following it', async () => {
    const accepted = [];
    for (const name of LOCAL_HOST_NAMES) accepted.push(await accepts(didOf(`${PUBLIC}:${port}`, 'hop-to', name)));
    expect({ accepted, served }).toEqual({
      accepted: LOCAL_HOST_NAMES.map(() => false), served: LOCAL_HOST_NAMES.map(name => `/hop-to/${name}/did.json`),
    });
  });

  it('refuses a redirect to a loopback address or to localhost without following it', async () => {
    const accepted = [await accepts(redirectDid()), await accepts(didOf(`${PUBLIC}:${port}`, 'hop-localhost'))];
    expect({ accepted, served }).toEqual({ accepted: [false, false], served: ['/hop/did.json', '/hop-localhost/did.json'] });
  });

  it('refuses a document that a provider which drops the request options reached by following a redirect itself', async () => {
    // A provider written as many adapters are: it passes on the URL alone, so the runtime follows the
    // redirect, and the request to the loopback address is made before the gate sees the response.
    const dropsInit = { fetch: (url: string) => globalThis.fetch(url) } as unknown as FetchProvider;
    const accepted = [await accepts(redirectDid(), { fetchProvider: dropsInit }), await accepts(directDid(), { fetchProvider: dropsInit })];
    expect({ accepted, served }).toEqual({ accepted: [false, true], served: ['/hop/did.json', '/internal/did.json', '/direct/did.json'] });
  });

  it('holds a provider the host supplies to the same rule, and honours its allowPrivateNetworkHosts', async () => {
    const custom = (members: object = {}) =>
      ({ fetch: (url: string, init?: RequestInit) => globalThis.fetch(url, init), ...members }) as unknown as FetchProvider;
    const did = didOf(`127.0.0.1:${port}`);
    const accepted = [await accepts(did, { fetchProvider: custom() }), await accepts(redirectDid(), { fetchProvider: custom() })];
    expect({ accepted, served }).toEqual({ accepted: [false, false], served: ['/hop/did.json'] });
    served.length = 0;
    const optedOut = [new RuntimeFetchProvider({ allowPrivateNetworkHosts: true }), custom({ allowPrivateNetworkHosts: true })];
    const acceptedOptedOut = [await accepts(did, { fetchProvider: optedOut[0] }), await accepts(did, { fetchProvider: optedOut[1] })];
    expect({ acceptedOptedOut, served }).toEqual({ acceptedOptedOut: [true, true], served: ['/.well-known/did.json', '/.well-known/did.json'] });
  });
});

describe('RuntimeFetchProvider.resolveDID, and ProofVerifier through it', () => {
  it('refuses an IPv4-mapped IPv6 loopback literal, localhost and the other local names, as it refuses 127.0.0.1, without a request', async () => {
    const provider = new RuntimeFetchProvider();
    const hosts = ['127.0.0.1', '[::ffff:7f00:1]', 'localhost', 'api.localhost.', ...LOCAL_HOST_NAMES];
    const resolved = [];
    for (const host of hosts) resolved.push(await provider.resolveDID(didOf(`${host}:${port}`)));
    expect({ resolved, served }).toEqual({ resolved: hosts.map(() => null), served: [] });
  });

  it("refuses a proof signer's DID on localhost or another local name without a request", async () => {
    const verifier = new ProofVerifier({
      fetchProvider: new RuntimeFetchProvider(), cryptoProvider: crypto,
      clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(),
    });
    for (const name of ['localhost', ...LOCAL_HOST_NAMES]) {
      await expect(verifier.fetchPublicKeyFromDID(didOf(`${name}:${port}`))).rejects.toThrow();
    }
    expect(served).toEqual([]);
  });
});
