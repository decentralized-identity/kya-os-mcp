/**
 * A did:web DID whose name looks public may resolve to a private address, as
 * `did:web:169.254.169.254.nip.io` resolves to the cloud metadata address. The library's own
 * runtime transport, `RuntimeFetchProvider`, resolves every host a presenter names before it reads,
 * checks every address it resolves to, and connects only to a checked address, pinned so that a
 * second lookup cannot move the connection. DNS and the connection are the provider's `lookup` and
 * `transport` seams here, as SafeFetch's tests inject them, and the runtime's `fetch` is stubbed to
 * serve every URL, standing for a network where the name reaches the address the lookup answers.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createDidWebResolver,
  DelegationCredentialVerifier,
  logger,
  RuntimeFetchProvider,
  type DIDDocument,
} from '../../index.js';
import type { DnsAddress, DnsLookup, RawResponse, SafeFetchTransport, TransportInit } from '../../card/index.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';

const METADATA = '169.254.169.254';
const PUBLIC: DnsAddress = { address: '93.184.216.34', family: 4 };
const REBOUND: DnsAddress = { address: '10.0.0.7', family: 4 };
/** A name that looks public and resolves to the cloud metadata address, as nip.io answers it. */
const ISSUER = 'did:web:169.254.169.254.nip.io';
const ISSUER_URL = 'https://169.254.169.254.nip.io/.well-known/did.json';

/** The documents the stubbed network serves, by URL. */
const served = new Map<string, unknown>();
/** Every URL the runtime's own `fetch` was asked for. */
const runtimeFetched: string[] = [];

beforeEach(() => {
  served.clear();
  runtimeFetched.length = 0;
  vi.stubGlobal('fetch', async (url: string) => {
    runtimeFetched.push(url);
    return served.has(url) ? Response.json(served.get(url)) : new Response('not found', { status: 404 });
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

/** A lookup that answers each name in `answers` with its addresses, in turn for a name given more than one answer. */
function lookupAnswering(answers: Readonly<Record<string, readonly (readonly DnsAddress[])[]>>) {
  const asked: string[] = [];
  const lookup: DnsLookup = async (hostname) => {
    const turns = answers[hostname] ?? [[PUBLIC]];
    const turn = asked.filter((name) => name === hostname).length;
    asked.push(hostname);
    return [...(turns[Math.min(turn, turns.length - 1)] ?? [])];
  };
  return { lookup, asked };
}

/** A transport that serves {@link served} and records what it was asked to connect to. */
function recordingTransport() {
  const connections: { url: string; init: TransportInit }[] = [];
  const transport: SafeFetchTransport = async (url, init): Promise<RawResponse> => {
    connections.push({ url, init });
    const body = served.has(url) ? JSON.stringify(served.get(url)) : undefined;
    return { status: body === undefined ? 404 : 200, headers: { get: () => null }, text: async () => body ?? 'not found' };
  };
  return { transport, connections };
}

/** A root delegation `did` issues, and its DID document served at `url`. */
async function issuedBy(did: string, url: string) {
  const key = await keyOf(did, 'key-1');
  const document: DIDDocument = issuerDidDocument(methodOf({ ...key, did, kid: `${did}#key-1` }));
  served.set(url, document);
  return signedCredential({ ...key, kid: `${did}#key-1` }, { record: delegationRecord(did) });
}

describe('a verifier on the default runtime transport, given a did:web whose name resolves to a private address', () => {
  it('refuses the DID before any connection, and tells the presenter only that it could not be resolved', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { lookup, asked } = lookupAnswering({ '169.254.169.254.nip.io': [[{ address: METADATA, family: 4 }]] });
    const { transport, connections } = recordingTransport();
    const provider = new RuntimeFetchProvider({ lookup, transport });
    const verifier = new DelegationCredentialVerifier({ didResolver: createDidWebResolver(provider), signatureVerifier: async () => ({ valid: true }) });

    const result = await verifier.verifyDelegationCredential(await issuedBy(ISSUER, ISSUER_URL), { skipCache: true });

    expect({ runtimeFetched, connections }).toEqual({ runtimeFetched: [], connections: [] });
    expect(asked).toEqual(['169.254.169.254.nip.io']);
    expect(result.valid).toBe(false);
    // Coded as a name that does not resolve is, so the code says nothing the lookup answered.
    expect(result.code).toBe('did_unavailable');
    // The DID's own name is what the presenter sent; what the name resolved to is not said.
    expect(result.reason).toBe(`Could not resolve issuer DID: "${ISSUER}"`);
    const logged = warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n');
    expect(logged).toContain(`refused (host_refused): it resolves to the non-public address ${METADATA}`);
  });

  it('refuses a name with any address that is not public, whatever the others are', async () => {
    const { lookup } = lookupAnswering({ 'split.example': [[PUBLIC, { address: '::1', family: 6 }]] });
    const { transport, connections } = recordingTransport();
    const resolver = createDidWebResolver(new RuntimeFetchProvider({ lookup, transport }));
    expect(await resolver.resolve('did:web:split.example')).toBeNull();
    expect(resolver.lastFailure?.('did:web:split.example')?.cause).toBe('unavailable');
    expect({ runtimeFetched, connections }).toEqual({ runtimeFetched: [], connections: [] });
  });

  it('connects a public name to the address it checked, once per read, so a lookup that answers otherwise later cannot move it', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const did = 'did:web:rebinding.example';
    const url = 'https://rebinding.example/.well-known/did.json';
    await issuedBy(did, url);
    const { lookup, asked } = lookupAnswering({ 'rebinding.example': [[PUBLIC], [REBOUND]] });
    const { transport, connections } = recordingTransport();
    const resolver = createDidWebResolver(new RuntimeFetchProvider({ lookup, transport }));

    expect((await resolver.resolve(did))?.id).toBe(did);
    expect(asked).toEqual(['rebinding.example']);
    expect(connections.map(({ url: asked, init }) => [asked, init.hostname, init.pinnedAddress, init.family])).toEqual([
      [url, 'rebinding.example', PUBLIC.address, 4],
    ]);
    expect(runtimeFetched).toEqual([]);

    // The next read resolves the name again, and refuses the address it now answers.
    resolver.clearCache();
    expect(await resolver.resolve(did)).toBeNull();
    expect(resolver.lastFailure?.(did)?.cause).toBe('unavailable');
    expect(connections).toHaveLength(1);
  });
});
