import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  DidWebResolver,
  buildDidWebDocument,
  createDidWebResolver,
  isDidWeb,
  parseDidWeb,
  didWebToUrl,
} from '../did-web-resolver.js';
import { base58Decode } from '../../utils/base58.js';
import { bytesToBase64 } from '../../utils/base64.js';
import type { FetchProvider, Identity } from '../../providers/base.js';
import type { DIDDocument } from '../vc-verifier.js';

/**
 * Tests for did:web resolver
 *
 * These tests verify the did:web resolution functionality:
 * - URL construction for root domain DIDs
 * - URL construction for path-based DIDs
 * - Successful resolution with mocked fetch
 * - Null return on 404
 * - Null return on invalid JSON
 * - Null return on missing `id` field in response
 */

describe('did:web URL Construction', () => {
  describe('isDidWeb', () => {
    it('should return true for did:web DIDs', () => {
      expect(isDidWeb('did:web:example.com')).toBe(true);
      expect(isDidWeb('did:web:example.com:path')).toBe(true);
      expect(isDidWeb('did:web:sub.example.com')).toBe(true);
    });

    it('should return false for non-did:web DIDs', () => {
      expect(isDidWeb('did:key:z6Mk...')).toBe(false);
      expect(isDidWeb('did:example:123')).toBe(false);
      expect(isDidWeb('not-a-did')).toBe(false);
      expect(isDidWeb('')).toBe(false);
    });
  });

  describe('parseDidWeb', () => {
    it('should parse root domain DID', () => {
      const result = parseDidWeb('did:web:example.com');
      expect(result).not.toBeNull();
      expect(result?.domain).toBe('example.com');
      expect(result?.path).toEqual([]);
    });

    it('should parse path-based DID', () => {
      const result = parseDidWeb('did:web:example.com:path:to:doc');
      expect(result).not.toBeNull();
      expect(result?.domain).toBe('example.com');
      expect(result?.path).toEqual(['path', 'to', 'doc']);
    });

    it('should handle URL-encoded components', () => {
      // %3A is URL-encoded colon, which would be used for port numbers
      const result = parseDidWeb('did:web:example.com%3A8080');
      expect(result).not.toBeNull();
      expect(result?.domain).toBe('example.com:8080');
      expect(result?.path).toEqual([]);
    });

    it('should return null for invalid DIDs', () => {
      expect(parseDidWeb('did:key:z6Mk...')).toBeNull();
      expect(parseDidWeb('did:web:')).toBeNull();
      expect(parseDidWeb('')).toBeNull();
    });
  });

  describe('didWebToUrl', () => {
    it('should convert root domain DID to .well-known URL', () => {
      const url = didWebToUrl('did:web:example.com');
      expect(url).toBe('https://example.com/.well-known/did.json');
    });

    it('should convert subdomain DID to .well-known URL', () => {
      const url = didWebToUrl('did:web:agents.example.com');
      expect(url).toBe('https://agents.example.com/.well-known/did.json');
    });

    it('should convert single path component DID to path URL', () => {
      const url = didWebToUrl('did:web:example.com:user');
      expect(url).toBe('https://example.com/user/did.json');
    });

    it('should convert multi-path DID to path URL', () => {
      const url = didWebToUrl('did:web:example.com:path:to:doc');
      expect(url).toBe('https://example.com/path/to/doc/did.json');
    });

    it('should handle agents path pattern', () => {
      const url = didWebToUrl('did:web:example.com:agents:bot1');
      expect(url).toBe('https://example.com/agents/bot1/did.json');
    });

    it('should handle URL-encoded port number', () => {
      const url = didWebToUrl('did:web:example.com%3A8080');
      expect(url).toBe('https://example.com:8080/.well-known/did.json');
    });

    it('should handle URL-encoded port number with path', () => {
      const url = didWebToUrl('did:web:example.com%3A3000:users:alice');
      expect(url).toBe('https://example.com:3000/users/alice/did.json');
    });

    it('should return null for invalid DIDs', () => {
      expect(didWebToUrl('did:key:z6Mk...')).toBeNull();
      expect(didWebToUrl('did:web:')).toBeNull();
      expect(didWebToUrl('')).toBeNull();
    });
  });
});

describe('DidWebResolver', () => {
  let mockFetchProvider: FetchProvider;
  let resolver: DidWebResolver;

  const validDIDDocument: DIDDocument = {
    id: 'did:web:example.com',
    verificationMethod: [
      {
        id: 'did:web:example.com#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: 'did:web:example.com',
        publicKeyJwk: {
          kty: 'OKP',
          crv: 'Ed25519',
          x: 'test-public-key-base64url',
        },
      },
    ],
    authentication: ['did:web:example.com#key-1'],
    assertionMethod: ['did:web:example.com#key-1'],
  };

  const createMockFetchProvider = (
    responseBody: unknown,
    status = 200
  ): FetchProvider => {
    return {
      resolveDID: vi.fn(),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch: vi.fn().mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        json: vi.fn().mockResolvedValue(responseBody),
      }),
    };
  };

  const createMockFetchProviderWithJsonError = (): FetchProvider => {
    return {
      resolveDID: vi.fn(),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockRejectedValue(new Error('Invalid JSON')),
      }),
    };
  };

  const createMockFetchProviderWithNetworkError = (): FetchProvider => {
    return {
      resolveDID: vi.fn(),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch: vi.fn().mockRejectedValue(new Error('Network error')),
    };
  };

  beforeEach(() => {
    mockFetchProvider = createMockFetchProvider(validDIDDocument);
    resolver = new DidWebResolver(mockFetchProvider, { cacheTtl: 1000 });
  });

  describe('successful resolution', () => {
    it('should resolve did:web:example.com', async () => {
      const result = await resolver.resolve('did:web:example.com');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('did:web:example.com');
      expect(result?.verificationMethod).toHaveLength(1);
      expect(result?.verificationMethod?.[0]?.type).toBe('Ed25519VerificationKey2020');
      expect(mockFetchProvider.fetch).toHaveBeenCalledWith(
        'https://example.com/.well-known/did.json'
      );
    });

    it('should resolve path-based DID', async () => {
      const pathDIDDocument: DIDDocument = {
        ...validDIDDocument,
        id: 'did:web:example.com:agents:bot1',
        verificationMethod: [
          {
            ...validDIDDocument.verificationMethod![0]!,
            id: 'did:web:example.com:agents:bot1#key-1',
            controller: 'did:web:example.com:agents:bot1',
          },
        ],
      };

      mockFetchProvider = createMockFetchProvider(pathDIDDocument);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com:agents:bot1');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('did:web:example.com:agents:bot1');
      expect(mockFetchProvider.fetch).toHaveBeenCalledWith(
        'https://example.com/agents/bot1/did.json'
      );
    });

    it('should cache successful resolutions', async () => {
      await resolver.resolve('did:web:example.com');
      await resolver.resolve('did:web:example.com');

      // Should only fetch once due to caching
      expect(mockFetchProvider.fetch).toHaveBeenCalledTimes(1);
    });

    it('should return cached result', async () => {
      const result1 = await resolver.resolve('did:web:example.com');
      const result2 = await resolver.resolve('did:web:example.com');

      expect(result1).toEqual(result2);
    });
  });

  describe('null return on 404', () => {
    it('should return null for 404 response', async () => {
      mockFetchProvider = createMockFetchProvider({}, 404);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });

    it('should return null for 500 response', async () => {
      mockFetchProvider = createMockFetchProvider({}, 500);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });
  });

  describe('null return on invalid JSON', () => {
    it('should return null when JSON parsing fails', async () => {
      mockFetchProvider = createMockFetchProviderWithJsonError();
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });
  });

  describe('null return on missing id field', () => {
    it('should return null when id field is missing', async () => {
      const invalidDocument = {
        verificationMethod: [],
      };

      mockFetchProvider = createMockFetchProvider(invalidDocument);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });

    it('should return null when id field is empty string', async () => {
      const invalidDocument = {
        id: '',
        verificationMethod: [],
      };

      mockFetchProvider = createMockFetchProvider(invalidDocument);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });

    it('should return null when id does not match requested DID', async () => {
      const mismatchedDocument: DIDDocument = {
        ...validDIDDocument,
        id: 'did:web:other.com',
      };

      mockFetchProvider = createMockFetchProvider(mismatchedDocument);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });
  });

  describe('null return on network error', () => {
    it('should return null when fetch throws', async () => {
      mockFetchProvider = createMockFetchProviderWithNetworkError();
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });
  });

  describe('null return for non-did:web', () => {
    it('should return null for did:key', async () => {
      const result = await resolver.resolve(
        'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
      );

      expect(result).toBeNull();
      expect(mockFetchProvider.fetch).not.toHaveBeenCalled();
    });

    it('should return null for invalid DID format', async () => {
      const result = await resolver.resolve('not-a-did');

      expect(result).toBeNull();
      expect(mockFetchProvider.fetch).not.toHaveBeenCalled();
    });
  });

  describe('invalid DID document structure', () => {
    it('should return null when response is not an object', async () => {
      mockFetchProvider = createMockFetchProvider('not an object');
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });

    it('should return null when response is null', async () => {
      mockFetchProvider = createMockFetchProvider(null);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });

    it('should return null when verificationMethod is not an array', async () => {
      const invalidDocument = {
        id: 'did:web:example.com',
        verificationMethod: 'not an array',
      };

      mockFetchProvider = createMockFetchProvider(invalidDocument);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });

    it('should return null when verificationMethod entry is invalid', async () => {
      const invalidDocument = {
        id: 'did:web:example.com',
        verificationMethod: [
          {
            // Missing required id field
            type: 'Ed25519VerificationKey2020',
            controller: 'did:web:example.com',
          },
        ],
      };

      mockFetchProvider = createMockFetchProvider(invalidDocument);
      resolver = new DidWebResolver(mockFetchProvider);

      const result = await resolver.resolve('did:web:example.com');

      expect(result).toBeNull();
    });
  });

  describe('cache management', () => {
    it('should clear all cache entries', async () => {
      await resolver.resolve('did:web:example.com');

      resolver.clearCache();

      // Next call should fetch again
      await resolver.resolve('did:web:example.com');

      expect(mockFetchProvider.fetch).toHaveBeenCalledTimes(2);
    });

    it('should clear specific cache entry', async () => {
      await resolver.resolve('did:web:example.com');

      resolver.clearCacheEntry('did:web:example.com');

      // Next call should fetch again
      await resolver.resolve('did:web:example.com');

      expect(mockFetchProvider.fetch).toHaveBeenCalledTimes(2);
    });

    it('should expire cached entries after TTL', async () => {
      // Use very short TTL
      resolver = new DidWebResolver(mockFetchProvider, { cacheTtl: 10 });

      await resolver.resolve('did:web:example.com');

      // Wait for cache to expire
      await new Promise((resolve) => setTimeout(resolve, 15));

      await resolver.resolve('did:web:example.com');

      expect(mockFetchProvider.fetch).toHaveBeenCalledTimes(2);
    });
  });
});

describe('buildDidWebDocument', () => {
  /** Multicodec prefix for Ed25519 public keys (matches the resolver). */
  const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

  /**
   * Construct a deterministic 32-byte test key and the matching
   * Identity bundle. Returning the raw bytes too makes round-trip
   * assertions on `publicKeyMultibase` straightforward.
   */
  const buildIdentity = (
    did: string,
    fragment = 'keys-1'
  ): { identity: Identity; publicKeyBytes: Uint8Array } => {
    const publicKeyBytes = new Uint8Array(32).map((_, i) => (i * 7) & 0xff);
    return {
      publicKeyBytes,
      identity: {
        did,
        kid: `${did}#${fragment}`,
        publicKey: bytesToBase64(publicKeyBytes),
        privateKey: undefined,
        createdAt: '2026-01-01T00:00:00.000Z',
      },
    };
  };

  describe('happy path', () => {
    it('produces a DID Document whose id matches the identity DID', () => {
      const { identity } = buildIdentity('did:web:example.com');

      const doc = buildDidWebDocument(identity);

      expect(doc.id).toBe('did:web:example.com');
    });

    it('emits the default JSON-LD contexts in spec-required order', () => {
      const { identity } = buildIdentity('did:web:example.com');

      const doc = buildDidWebDocument(identity);

      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ]);
    });

    it('appends additional contexts after the defaults', () => {
      const { identity } = buildIdentity('did:web:example.com');

      const doc = buildDidWebDocument(identity, {
        additionalContexts: ['https://example.com/custom/v1'],
      });

      expect(doc['@context']).toEqual([
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
        'https://example.com/custom/v1',
      ]);
    });

    it('can publish alsoKnownAs linkage entries', () => {
      const { identity } = buildIdentity('did:web:example.com');
      const cheqdDid = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';

      const doc = buildDidWebDocument(identity, { alsoKnownAs: [cheqdDid] });

      expect(doc.alsoKnownAs).toEqual([cheqdDid]);
    });

    it('emits a single Ed25519VerificationKey2020 method controlled by the DID', () => {
      const { identity } = buildIdentity('did:web:example.com:agents:bot1');

      const doc = buildDidWebDocument(identity);

      expect(doc.verificationMethod).toHaveLength(1);
      const vm = doc.verificationMethod?.[0];
      expect(vm?.id).toBe(identity.kid);
      expect(vm?.type).toBe('Ed25519VerificationKey2020');
      expect(vm?.controller).toBe(identity.did);
    });

    it('publishes the verification method under both authentication and assertionMethod', () => {
      const { identity } = buildIdentity('did:web:example.com');

      const doc = buildDidWebDocument(identity);

      expect(doc.authentication).toEqual([identity.kid]);
      expect(doc.assertionMethod).toEqual([identity.kid]);
    });

    it('emits publicKeyJwk in OKP/Ed25519 form', () => {
      const { identity } = buildIdentity('did:web:example.com');

      const doc = buildDidWebDocument(identity);

      const jwk = doc.verificationMethod?.[0]?.publicKeyJwk as {
        kty: string;
        crv: string;
        x: string;
      };
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('emits publicKeyMultibase that decodes back to the original key bytes', () => {
      const { identity, publicKeyBytes } = buildIdentity('did:web:example.com');

      const doc = buildDidWebDocument(identity);

      const multibase = doc.verificationMethod?.[0]?.publicKeyMultibase;
      expect(multibase).toBeDefined();
      expect(multibase?.startsWith('z')).toBe(true);

      const decoded = base58Decode(multibase!.slice(1));
      expect(decoded.slice(0, 2)).toEqual(ED25519_MULTICODEC_PREFIX);
      expect(decoded.slice(2)).toEqual(publicKeyBytes);
    });
  });

  describe('round-trip with DidWebResolver', () => {
    it('produces a document the resolver accepts as valid', async () => {
      const did = 'did:web:example.com:u:alice';
      const { identity } = buildIdentity(did);
      const document = buildDidWebDocument(identity);

      const fetchProvider: FetchProvider = {
        resolveDID: vi.fn(),
        fetchStatusList: vi.fn(),
        fetchDelegationChain: vi.fn(),
        fetch: vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue(document),
        }),
      };

      const resolved = await new DidWebResolver(fetchProvider).resolve(did);

      expect(resolved).not.toBeNull();
      expect(resolved?.id).toBe(did);
      expect(resolved?.verificationMethod?.[0]?.controller).toBe(did);
    });
  });

  describe('input validation', () => {
    it('throws when identity.did is not a did:web DID', () => {
      const { identity } = buildIdentity('did:web:example.com');
      const bad: Identity = { ...identity, did: 'did:key:z6MkInvalid' };

      expect(() => buildDidWebDocument(bad)).toThrow(/must be a did:web DID/);
    });

    it('throws when identity.kid does not reference identity.did', () => {
      const { identity } = buildIdentity('did:web:example.com');
      const bad: Identity = { ...identity, kid: 'did:web:other.com#keys-1' };

      expect(() => buildDidWebDocument(bad)).toThrow(/does not reference/);
    });

    it('throws when publicKey is not 32 bytes after base64 decode', () => {
      const { identity } = buildIdentity('did:web:example.com');
      const bad: Identity = { ...identity, publicKey: bytesToBase64(new Uint8Array(16)) };

      expect(() => buildDidWebDocument(bad)).toThrow(/expected 32-byte/);
    });
  });
});

describe('createDidWebResolver', () => {
  it('should create a resolver instance', () => {
    const mockFetchProvider: FetchProvider = {
      resolveDID: vi.fn(),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch: vi.fn(),
    };

    const resolver = createDidWebResolver(mockFetchProvider);

    expect(resolver).toBeDefined();
    expect(typeof resolver.resolve).toBe('function');
  });

  it('should pass options to resolver', async () => {
    const validDIDDocument: DIDDocument = {
      id: 'did:web:example.com',
      verificationMethod: [],
    };

    const mockFetchProvider: FetchProvider = {
      resolveDID: vi.fn(),
      fetchStatusList: vi.fn(),
      fetchDelegationChain: vi.fn(),
      fetch: vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue(validDIDDocument),
      }),
    };

    const resolver = createDidWebResolver(mockFetchProvider, { cacheTtl: 5000 });

    const result = await resolver.resolve('did:web:example.com');

    expect(result).not.toBeNull();
  });
});
