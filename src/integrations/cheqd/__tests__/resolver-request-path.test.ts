/**
 * A did:cheqd DID is the counterparty's to write, and the resolver sends it, with the operator's
 * headers, to the operator's cheqd resolver. So the DID chooses nothing about that request but the
 * identifier: a DID outside the method's syntax is refused before any request, and the URL built
 * for any string keeps it inside one path segment. The WHATWG URL parser reads `\` as `/` in an
 * http(s) URL, so `did:cheqd:mainnet:x\..\..\admin` would otherwise ask the resolver's host for
 * `/admin`. Tested on the helpers, on the resolver, and on the two callers that hand it a DID a
 * counterparty chose: the delegation gate and `ProofVerifier`.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { cheqdResolver, didCheqdToResolverUrl, DidCheqdResolver, parseDidCheqd } from '../resolver.js';
import { delegationGate, type Resolution } from '../../../middleware/__tests__/helpers/delegation-gate.js';
import { keyOf, signedCredential } from '../../../__tests__/utils/delegation-credentials.js';
import { NodeCryptoProvider } from '../../../__tests__/utils/node-crypto-provider.js';
import { MemoryNonceCacheProvider } from '../../../providers/memory.js';
import { RuntimeFetchProvider } from '../../../providers/runtime-fetch.js';
import { SystemClockProvider } from '../../../providers/system-clock.js';
import { ProofVerifier } from '../../../proof/verifier.js';
import type { FetchProvider } from '../../../providers/base.js';

const UUID = '11111111-1111-4111-8111-111111111111';
/** Unique ids outside the method's syntax, each of which would steer or split the request URL. */
const HOSTILE_IDS = [
  'x\\..\\..\\..\\internal\\admin',
  '..',
  'a%2F..%2Fadmin',
  'a$&b',
  "a$'b",
  'a b',
  'a.b',
  'a:b',
  'a@evil.example',
  `${UUID}\\..`,
  `${UUID}x`,
];
const hostile = HOSTILE_IDS.map((id) => `did:cheqd:mainnet:${id}`);
const BASES = ['https://resolver.example', 'https://resolver.example/1.0/identifiers', 'https://resolver.example/1.0/identifiers/{did}'];
const HEADERS = { Authorization: 'Bearer operator-key' };

/** A provider that records each URL it is asked for and answers 404. */
function recordingProvider(): { provider: FetchProvider; requested: string[] } {
  const requested: string[] = [];
  const provider = {
    resolveDID: vi.fn(),
    fetchStatusList: vi.fn(),
    fetchDelegationChain: vi.fn(),
    fetch: async (url: string) => {
      requested.push(url);
      return new Response('not found', { status: 404 });
    },
  } as unknown as FetchProvider;
  return { provider, requested };
}

afterEach(() => vi.unstubAllGlobals());

describe('parseDidCheqd and the method-specific identifier', () => {
  it('reads a UUID, in either case, or letters and digits, and refuses every other identifier', () => {
    // The second UUID holds every hex digit, zero included, in each of its five groups.
    for (const id of [UUID, '0a1B2c3D-40e5-6078-9A0b-cD0e1F203a4B', 'zF7rhDBfUt9d1gJPjx7s1J', 'abc']) {
      expect(parseDidCheqd(`did:cheqd:testnet:${id}`), id).toEqual({ network: 'testnet', uniqueId: id });
    }
    for (const did of hostile) expect(parseDidCheqd(did), did).toBeNull();
    expect(parseDidCheqd(`did:cheqd:mainnet:${UUID.slice(1)}`)).toBeNull();
    expect(parseDidCheqd(`did:cheqd:mainnet:${UUID}\n`)).toBeNull();
  });
});

describe('didCheqdToResolverUrl', () => {
  it('keeps any string it is given inside one path segment of the configured resolver', () => {
    for (const base of BASES) {
      for (const did of [...hostile, `did:cheqd:mainnet:${UUID}`]) {
        const url = new URL(didCheqdToResolverUrl(did, base));
        expect(url.origin, did).toBe('https://resolver.example');
        expect(url.search + url.hash, did).toBe('');
        const segments = url.pathname.split('/');
        expect(decodeURIComponent(segments.at(-1) ?? ''), did).toBe(did);
        expect(segments.slice(0, -1).join('/'), did).toBe('/1.0/identifiers');
      }
      // A DID of the method is written as it stands, colons included.
      expect(didCheqdToResolverUrl(`did:cheqd:mainnet:${UUID}`, base)).toBe(`https://resolver.example/1.0/identifiers/did:cheqd:mainnet:${UUID}`);
    }
  });

  it('puts the DID where a template names it, reading no replacement pattern from it', () => {
    expect(didCheqdToResolverUrl('did:cheqd:mainnet:a$&b', 'https://resolver.example/r/{did}/doc')).toBe(
      'https://resolver.example/r/did:cheqd:mainnet:a%24%26b/doc',
    );
  });
});

describe('a did:cheqd DID outside the syntax costs no request', () => {
  it('through DidCheqdResolver, for each form of resolver URL', async () => {
    for (const resolverUrl of BASES) {
      const { provider, requested } = recordingProvider();
      const resolver = new DidCheqdResolver(provider, { resolverUrl, headers: HEADERS });
      for (const did of hostile) expect(await resolver.resolve(did), did).toBeNull();
      expect(requested).toEqual([]);
      expect(await resolver.resolve(`did:cheqd:mainnet:${UUID}`)).toBeNull();
      expect(requested).toEqual([`https://resolver.example/1.0/identifiers/did:cheqd:mainnet:${UUID}`]);
    }
  });

  it('through the delegation gate, which resolves the issuer a credential names', async () => {
    for (const resolverUrl of BASES) {
      const { provider, requested } = recordingProvider();
      const resolution = { fetchProvider: provider, didResolvers: { cheqd: cheqdResolver({ resolverUrl, headers: HEADERS }) } } as Resolution;
      const gate = await delegationGate({ trustedRootIssuers: undefined as never, resolution });
      for (const did of hostile) {
        expect(await gate.call(await signedCredential(await keyOf(did, 'key-1'))), did).toBe('delegation_invalid');
      }
      expect(requested).toEqual([]);
      expect(gate.runs()).toBe(0);
    }
  });

  it('through ProofVerifier, which resolves the DID a request proof names', async () => {
    const requested: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      requested.push(String(url));
      return new Response('not found', { status: 404 });
    });
    for (const resolverUrl of BASES) {
      const fetchProvider = new RuntimeFetchProvider({ didResolvers: { cheqd: cheqdResolver({ resolverUrl, headers: HEADERS }) } });
      const verifier = new ProofVerifier({
        cryptoProvider: new NodeCryptoProvider(),
        clockProvider: new SystemClockProvider(),
        nonceCacheProvider: new MemoryNonceCacheProvider(),
        fetchProvider,
      });
      for (const did of hostile) {
        await expect(verifier.fetchPublicKeyFromDID(did, `${did}#key-1`), did).rejects.toThrow();
      }
    }
    expect(requested).toEqual([]);
  });
});
