import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { NodeCryptoProvider } from '../../providers/node-crypto.js';
import { generateDidKeyFromBase64 } from '../../utils/did-helpers.js';
import { cheqdResolver } from '../../integrations/cheqd/index.js';
import type { FetchProvider } from '../../providers/base.js';
import { LOCAL_HOST_NAMES, PUBLIC_NAME_FOR_LOOPBACK } from '../utils/local-host-names.js';

const statusList = { type: ['StatusList2021Credential'], credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAA' } };

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

    it('refuses a DID over 2,048 units before decoding a did:key or fetching a did:web', async () => {
      const didKey = (provider as unknown as { didKeyResolver: { resolve(did: string): unknown } }).didKeyResolver;
      const decode = vi.spyOn(didKey, 'resolve');
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      expect(await provider.resolveDID(`did:key:z${'6'.repeat(2_040)}`)).toBeNull();
      expect(await provider.resolveDID(`did:web:${'a'.repeat(2_041)}.example`)).toBeNull();
      expect(decode).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('spends one 5,000 ms deadline across a configured resolver and the did:web fallback, and none after a miss', async () => {
      vi.useFakeTimers();
      try {
        // The configured resolver answers nothing after 4,900 ms, and the fallback's body never arrives.
        const answer = (after: number) => () => new Promise<null>(resolve => setTimeout(() => resolve(null), after));
        const slow = new RuntimeFetchProvider({ didResolvers: { web: { resolve: answer(4_900) } } });
        vi.spyOn(slow, 'fetch').mockImplementation(async () => new Response(new ReadableStream()));
        let outcome: unknown = 'pending';
        void slow.resolveDID('did:web:slow.example').then(value => { outcome = value; });
        await vi.advanceTimersByTimeAsync(4_999);
        expect(outcome).toBe('pending');
        await vi.advanceTimersByTimeAsync(1);
        expect(outcome).toBeNull();
        // A configured resolver that misses the deadline ends the resolution: the fallback is not asked.
        const missing = new RuntimeFetchProvider({ didResolvers: { web: { resolve: answer(60_000) } } });
        const fetch = vi.spyOn(missing, 'fetch');
        let missed: unknown = 'pending';
        void missing.resolveDID('did:web:missing.example').then(value => { missed = value; });
        await vi.advanceTimersByTimeAsync(5_000);
        expect(missed).toBeNull();
        expect(fetch).not.toHaveBeenCalled();
      } finally {
        vi.useRealTimers();
      }
    });

    it('leaves no timer behind once a resolution answers in time', async () => {
      vi.useFakeTimers();
      try {
        const did = 'did:web:quick.example';
        const quick = new RuntimeFetchProvider({ didResolvers: { web: { resolve: async () => ({ id: did }) } } });
        expect(await quick.resolveDID(did)).toEqual({ id: did });
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        vi.useRealTimers();
      }
    });

    it('falls back to a built-in resolver after a configured one finds nothing, and not after the limits refuse its document', async () => {
      const crypto = new NodeCryptoProvider();
      const didKey = generateDidKeyFromBase64((await crypto.generateKeyPair()).publicKey);
      const didWeb = 'did:web:fallback.example';
      const overLimit = { id: 'd'.repeat(2_049) };
      for (const [did, method] of [[didWeb, 'web'], [didKey, 'key']] as const) {
        for (const answer of [null, overLimit]) {
          const configured = new RuntimeFetchProvider({ didResolvers: { [method]: { resolve: async () => answer } } });
          const fetch = vi.spyOn(configured, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ id: did })));
          const resolved = await configured.resolveDID(did);
          expect(resolved === null ? null : resolved.id).toBe(answer === null ? did : null);
          expect(fetch).toHaveBeenCalledTimes(answer === null && method === 'web' ? 1 : 0);
        }
      }
    });

    it('returns null for an unsupported DID method', async () => {
      expect(await provider.resolveDID('did:example:abc')).toBeNull();
    });

    it('returns null for did:cheqd unless a cheqd resolver is configured', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);

      expect(
        await provider.resolveDID('did:cheqd:testnet:11111111-1111-4111-8111-111111111111'),
      ).toBeNull();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('resolves did:cheqd through an explicitly configured method resolver', async () => {
      const did = 'did:cheqd:testnet:11111111-1111-4111-8111-111111111111';
      const cheqdProvider = new RuntimeFetchProvider({
        didResolvers: {
          cheqd: cheqdResolver({ resolverUrl: 'https://resolver.cheqd.net' }),
        },
      });
      const fetchSpy = vi.fn(async (url: string) => {
        expect(url).toBe(`https://resolver.cheqd.net/1.0/identifiers/${did}`);
        return new Response(
          JSON.stringify({
            didDocument: {
              id: did,
              verificationMethod: [
                { id: `${did}#key-1`, type: 'Ed25519VerificationKey2020', controller: did },
              ],
            },
          }),
          { status: 200 },
        );
      });
      vi.stubGlobal('fetch', fetchSpy);

      const doc = await cheqdProvider.resolveDID(did);

      expect(doc?.id).toBe(did);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
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

    it('refuses a did:web or status list on localhost, a name under it, or another local name, without fetching', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);
      for (const host of ['localhost', 'LOCALHOST', 'localhost.', 'api.localhost', 'api.localhost.', ...LOCAL_HOST_NAMES]) {
        expect(await provider.resolveDID(`did:web:${host}`)).toBeNull();
        expect(await provider.fetchStatusList(`https://${host}/status`)).toBeNull();
      }
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('reads a status list from a public name whatever address it has, since the rule resolves no name', async () => {
      const fetchSpy = vi.fn(async () => new Response(JSON.stringify(statusList)));
      vi.stubGlobal('fetch', fetchSpy);
      const url = `https://${PUBLIC_NAME_FOR_LOOPBACK}/status`;
      expect(await provider.fetchStatusList(url)).toMatchObject(statusList);
      expect(fetchSpy).toHaveBeenCalledWith(url, expect.objectContaining({ redirect: 'manual' }));
    });

    it('refuses a status list whose URL scheme is not http or https, without fetching, even when opted in', async () => {
      const fetchSpy = vi.fn(async () => new Response(JSON.stringify(statusList)));
      vi.stubGlobal('fetch', fetchSpy);
      const open = new RuntimeFetchProvider({ allowPrivateNetworkHosts: true });
      const data = `data:application/json,${encodeURIComponent(JSON.stringify(statusList))}`;
      for (const url of [data, 'file:///etc/status.json', 'ftp://status.example/list']) {
        expect(await provider.fetchStatusList(url)).toBeNull();
        expect(await open.fetchStatusList(url)).toBeNull();
      }
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
      // The opt-out is a documented member of every FetchProvider, which RuntimeFetchProvider sets from its option.
      const declared: FetchProvider[] = [open, provider];
      expect(declared.map(each => each.allowPrivateNetworkHosts)).toEqual([true, false]);
    });

    it('opts in only for allowPrivateNetworkHosts: true, as the rule reads it, and refuses for any other value', async () => {
      const fetchSpy = vi.fn(async () => new Response(JSON.stringify(statusList), { status: 200 }));
      vi.stubGlobal('fetch', fetchSpy);
      for (const value of [1, 'true', 'yes', {}]) {
        const truthy = new RuntimeFetchProvider({ allowPrivateNetworkHosts: value as unknown as boolean });
        expect(truthy.allowPrivateNetworkHosts).toBe(false);
        expect(await truthy.fetchStatusList('http://169.254.169.254/status')).toBeNull();
      }
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('reads a status list on a private host when explicitly opted in', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(statusList), { status: 200 })));
      const open = new RuntimeFetchProvider({ allowPrivateNetworkHosts: true });
      expect((await open.fetchStatusList('http://169.254.169.254/status'))?.credentialSubject.encodedList).toBe('H4sIAAAAAAAA');
    });
  });
});
