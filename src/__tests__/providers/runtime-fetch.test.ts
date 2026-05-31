import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';

describe('RuntimeFetchProvider', () => {
  let provider: RuntimeFetchProvider;

  beforeEach(() => {
    provider = new RuntimeFetchProvider();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('resolveDID', () => {
    it('resolves a did:key locally, with no network, to an Ed25519 publicKeyJwk', async () => {
      const crypto = new NodeCryptoProvider();
      const kp = await crypto.generateKeyPair();
      const did = generateDidKeyFromBase64(kp.publicKey);
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);

      const doc = await provider.resolveDID(did);

      expect(doc).not.toBeNull();
      expect(doc?.id).toBe(did);
      expect(doc?.verificationMethod?.[0]?.publicKeyJwk).toMatchObject({
        kty: 'OKP',
        crv: 'Ed25519',
      });
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('returns null for an unsupported DID method', async () => {
      expect(await provider.resolveDID('did:example:abc')).toBeNull();
    });

    it('resolves a did:web over the HTTPS .well-known fetch path', async () => {
      const did = 'did:web:example.com';
      const didDoc = {
        id: did,
        verificationMethod: [
          { id: `${did}#key-1`, type: 'Ed25519VerificationKey2020', controller: did },
        ],
      };
      const fetchSpy = vi.fn(async (url: string) => {
        expect(url).toBe('https://example.com/.well-known/did.json');
        return new Response(JSON.stringify(didDoc), { status: 200 });
      });
      vi.stubGlobal('fetch', fetchSpy);

      const doc = await provider.resolveDID(did);

      expect(doc?.id).toBe(did);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it('returns null when did:web resolution fails (non-ok response)', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 404 })));
      expect(await provider.resolveDID('did:web:example.com')).toBeNull();
    });
  });

  describe('fetch', () => {
    it('delegates to the global fetch with url and options', async () => {
      const res = new Response('ok', { status: 200 });
      const fetchSpy = vi.fn(async () => res);
      vi.stubGlobal('fetch', fetchSpy);

      const out = await provider.fetch('https://x.test/y', { method: 'GET' });

      expect(out).toBe(res);
      expect(fetchSpy).toHaveBeenCalledWith('https://x.test/y', { method: 'GET' });
    });

    it('throws when no global fetch is available', async () => {
      vi.stubGlobal('fetch', undefined);
      await expect(provider.fetch('https://x.test')).rejects.toThrow(/fetch is not available/i);
    });
  });

  describe('fetchStatusList', () => {
    const cred = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'https://issuer.test/status/1',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:web:issuer.test',
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: {
        type: 'StatusList2021',
        statusPurpose: 'revocation',
        encodedList: 'H4sIAAAAAAAA',
      },
    };

    it('fetches and returns a StatusList2021Credential', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(cred), { status: 200 })));
      const out = await provider.fetchStatusList('https://issuer.test/status/1');
      expect(out?.credentialSubject.encodedList).toBe('H4sIAAAAAAAA');
    });

    it('returns null on a non-ok response', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => new Response('x', { status: 500 })));
      expect(await provider.fetchStatusList('https://issuer.test/status/1')).toBeNull();
    });

    it('returns null when the payload is not a StatusList2021Credential', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn(async () => new Response(JSON.stringify({ id: 'x', type: ['Other'] }), { status: 200 })),
      );
      expect(await provider.fetchStatusList('https://issuer.test/status/1')).toBeNull();
    });

    it('returns null (never throws) when the underlying fetch rejects', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
      expect(await provider.fetchStatusList('https://issuer.test/status/1')).toBeNull();
    });
  });

  describe('fetchDelegationChain', () => {
    it('returns an empty array (no remote chain resolution is shipped)', async () => {
      expect(await provider.fetchDelegationChain('urn:delegation:1')).toEqual([]);
    });
  });

  describe('SSRF guard (private/loopback targets blocked by default)', () => {
    it('refuses a did:web whose host is the link-local metadata IP, without fetching', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      expect(await provider.resolveDID('did:web:169.254.169.254')).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('refuses loopback and RFC1918 did:web hosts by default, without fetching', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      expect(await provider.resolveDID('did:web:127.0.0.1')).toBeNull();
      expect(await provider.resolveDID('did:web:10.0.0.5')).toBeNull();
      expect(await provider.resolveDID('did:web:192.168.1.1')).toBeNull();
      expect(await provider.resolveDID('did:web:172.16.0.9')).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('refuses a status list on a private host by default, without fetching', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      expect(await provider.fetchStatusList('http://169.254.169.254/status')).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('refuses an IPv6 loopback host (bracketed) by default, without fetching', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      expect(await provider.fetchStatusList('http://[::1]/status')).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('still resolves public did:web hosts (domain names are not IP-blocked)', async () => {
      const did = 'did:web:example.com';
      vi.stubGlobal(
        'fetch',
        vi.fn(async () =>
          new Response(
            JSON.stringify({
              id: did,
              verificationMethod: [
                { id: `${did}#k`, type: 'Ed25519VerificationKey2020', controller: did },
              ],
            }),
            { status: 200 },
          ),
        ),
      );
      expect((await provider.resolveDID(did))?.id).toBe(did);
    });

    it('allows private targets when explicitly opted in', async () => {
      const open = new RuntimeFetchProvider({ allowPrivateNetworkHosts: true });
      const did = 'did:web:127.0.0.1';
      const fetchSpy = vi.fn(async () =>
        new Response(
          JSON.stringify({
            id: did,
            verificationMethod: [
              { id: `${did}#k`, type: 'Ed25519VerificationKey2020', controller: did },
            ],
          }),
          { status: 200 },
        ),
      );
      vi.stubGlobal('fetch', fetchSpy);
      expect((await open.resolveDID(did))?.id).toBe(did);
      expect(fetchSpy).toHaveBeenCalled();
    });
  });
});
