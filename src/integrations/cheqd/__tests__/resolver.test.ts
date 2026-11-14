import { describe, it, expect, vi } from 'vitest';
import {
  DidCheqdResolver,
  didCheqdToResolverUrl,
  isDidCheqd,
  parseDidCheqd,
} from '../resolver.js';
import type { FetchProvider } from '../../../providers/base.js';
import type { DIDDocument } from '../../../delegation/vc-verifier.js';

/** The URL and the headers, by lowercase name, of each request `provider` was asked to make. */
function requests(provider: FetchProvider) {
  return vi.mocked(provider.fetch).mock.calls.map(([url, init]) => {
    const { headers, ...rest } = init as RequestInit;
    return [url, { ...rest, headers: Object.fromEntries(new Headers(headers)) }];
  });
}

function fetchProvider(response: unknown, status = 200): FetchProvider {
  return {
    resolveDID: vi.fn(),
    fetchStatusList: vi.fn(),
    fetchDelegationChain: vi.fn(),
    fetch: vi.fn().mockImplementation(async () => new Response(JSON.stringify(response), { status })),
  };
}

function networkErrorFetchProvider(): FetchProvider {
  return {
    resolveDID: vi.fn(),
    fetchStatusList: vi.fn(),
    fetchDelegationChain: vi.fn(),
    fetch: vi.fn().mockRejectedValue(new Error('network down')),
  };
}

function invalidJsonFetchProvider(): FetchProvider {
  return {
    resolveDID: vi.fn(),
    fetchStatusList: vi.fn(),
    fetchDelegationChain: vi.fn(),
    fetch: vi.fn().mockImplementation(async () => new Response('not json')),
  };
}

describe('did:cheqd helpers', () => {
  it('identifies and parses mainnet and testnet did:cheqd DIDs', () => {
    expect(isDidCheqd('did:cheqd:testnet:11111111-1111-4111-8111-111111111111')).toBe(true);
    expect(parseDidCheqd('did:cheqd:mainnet:22222222-2222-4222-8222-222222222222')).toEqual({
      network: 'mainnet',
      uniqueId: '22222222-2222-4222-8222-222222222222',
    });
  });

  it('rejects malformed or non-cheqd DID values', () => {
    expect(parseDidCheqd('did:web:example.com')).toBeNull();
    expect(parseDidCheqd('did:cheqd:devnet:abc')).toBeNull();
    expect(parseDidCheqd('did:cheqd:testnet:')).toBeNull();
    expect(parseDidCheqd('did:cheqd:testnet:abc/resources/123')).toBeNull();
  });

  it('builds resolver URLs from base URLs and templates', () => {
    const did = 'did:cheqd:testnet:abc';
    expect(didCheqdToResolverUrl(did, 'https://resolver.cheqd.net')).toBe(
      'https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:abc',
    );
    expect(didCheqdToResolverUrl(did, 'https://resolver.cheqd.net/1.0/identifiers')).toBe(
      'https://resolver.cheqd.net/1.0/identifiers/did:cheqd:testnet:abc',
    );
    expect(didCheqdToResolverUrl(did, 'https://resolver.test/{did}')).toBe(
      'https://resolver.test/did:cheqd:testnet:abc',
    );
  });
});

describe('DidCheqdResolver', () => {
  const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
  const didDocument: DIDDocument = {
    id: did,
    verificationMethod: [
      {
        id: `${did}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' },
      },
    ],
    authentication: [`${did}#key-1`],
  };

  it('resolves a raw DID Document response', async () => {
    const provider = fetchProvider(didDocument);
    const resolver = new DidCheqdResolver(provider, { resolverUrl: 'https://resolver.cheqd.net' });

    const resolved = await resolver.resolve(did);

    expect(resolved?.id).toBe(did);
    expect(requests(provider)).toEqual([[
      `https://resolver.cheqd.net/1.0/identifiers/${did}`,
      { method: 'GET', headers: { accept: 'application/did+ld+json' }, signal: expect.any(AbortSignal) },
    ]]);
  });

  it('resolves a DID Resolution Result response', async () => {
    const resolver = new DidCheqdResolver(fetchProvider({ didDocument }), {
      resolverUrl: 'https://resolver.cheqd.net',
    });

    await expect(resolver.resolve(did)).resolves.toEqual(didDocument);
  });

  it('uses configured headers and caches successful results', async () => {
    const provider = fetchProvider({ didDocument });
    const resolver = new DidCheqdResolver(provider, {
      resolverUrl: 'https://resolver.cheqd.net',
      headers: async () => ({ Authorization: 'Bearer token' }),
      cacheTtl: 1000,
    });

    await resolver.resolve(did);
    await resolver.resolve(did);

    expect(requests(provider)).toEqual([[
      `https://resolver.cheqd.net/1.0/identifiers/${did}`,
      {
        method: 'GET',
        headers: { accept: 'application/did+ld+json', authorization: 'Bearer token' },
        signal: expect.any(AbortSignal),
      },
    ]]);
  });

  it("asks for the document alone, replacing a configured Accept in any case, and sends the other configured headers", async () => {
    for (const name of ['accept', 'Accept', 'ACCEPT']) {
      const provider = fetchProvider(didDocument);
      const headers = { [name]: 'application/json', Authorization: 'Bearer token' };
      await new DidCheqdResolver(provider, { resolverUrl: 'https://resolver.cheqd.net', headers }).resolve(did);
      expect(requests(provider).map(([, init]) => (init as { headers: unknown }).headers)).toEqual([
        { accept: 'application/did+ld+json', authorization: 'Bearer token' },
      ]);
    }
  });

  it('returns null on invalid DID, fetch errors, HTTP errors, invalid documents, and id mismatch', async () => {
    expect(await new DidCheqdResolver(fetchProvider(didDocument), { resolverUrl: 'https://r' }).resolve('did:web:x')).toBeNull();
    expect(await new DidCheqdResolver(networkErrorFetchProvider(), { resolverUrl: 'https://r' }).resolve(did)).toBeNull();
    expect(await new DidCheqdResolver(fetchProvider({}, 500), { resolverUrl: 'https://r' }).resolve(did)).toBeNull();
    expect(await new DidCheqdResolver(invalidJsonFetchProvider(), { resolverUrl: 'https://r' }).resolve(did)).toBeNull();
    expect(await new DidCheqdResolver(fetchProvider({ didDocument: null }), { resolverUrl: 'https://r' }).resolve(did)).toBeNull();
    expect(await new DidCheqdResolver(fetchProvider({ didDocument: { verificationMethod: [] } }), { resolverUrl: 'https://r' }).resolve(did)).toBeNull();
    expect(await new DidCheqdResolver(fetchProvider({ didDocument: { ...didDocument, id: 'did:cheqd:testnet:other' } }), { resolverUrl: 'https://r' }).resolve(did)).toBeNull();
  });

  it('returns null for a document with a verification method that lacks a non-empty id, type or controller', async () => {
    const [method] = didDocument.verificationMethod ?? [];
    const malformed: unknown[] = [{ ...method, id: '' }, { ...method, type: undefined }, { ...method, controller: 7 }, `${did}#key-1`];
    for (const entry of malformed) {
      const document = { ...didDocument, verificationMethod: [entry] };
      const resolver = new DidCheqdResolver(fetchProvider({ didDocument: document }), { resolverUrl: 'https://r' });
      expect(await resolver.resolve(did), JSON.stringify(entry)).toBeNull();
    }
  });
});
