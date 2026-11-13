import { describe, expect, it, vi } from 'vitest';
import { ProofVerifier } from '../verifier.js';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { SystemClockProvider } from '../../providers/system-clock.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import type { FetchProvider } from '../../providers/base.js';
import type { DIDDocument } from '../../delegation/vc-verifier.js';
import {
  admitParsedDidDocument, DID_RESOLUTION_TIMEOUT_MS, MAX_DID_DOCUMENT_BYTES, MAX_DID_LENGTH, MAX_KEY_ID_LENGTH,
} from '../../delegation/did-resource-limits.js';
import { resolveProofDid } from '../proof-did.js';

const did = 'did:web:proof.example';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ' };
const document = (): DIDDocument => ({
  id: did, verificationMethod: [{ id: `${did}#key`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk }],
});
function verifier(fetchProvider: FetchProvider) {
  return new ProofVerifier({
    fetchProvider, cryptoProvider: new NodeCryptoProvider(),
    clockProvider: new SystemClockProvider(), nonceCacheProvider: new MemoryNonceCacheProvider(),
  });
}

/** A provider that answers every call by asking `inner`, as an application's wrapper does. */
const wrapping = (inner: FetchProvider): FetchProvider => ({
  resolveDID: did => inner.resolveDID(did), fetch: (url, init) => inner.fetch(url, init),
  fetchStatusList: url => inner.fetchStatusList(url), fetchDelegationChain: id => inner.fetchDelegationChain(id),
});

/** A subclass that resolves through RuntimeFetchProvider's own `resolveDID`. */
class Delegating extends RuntimeFetchProvider {
  override async resolveDID(value: string) { return super.resolveDID(value); }
}

describe('proof DID resource boundary', () => {
  it.each(['runtime', 'custom', 'subclass', 'wrapper'] as const)('%s: walks a document no built-in resolver admitted on every resolution, and rechecks a reused mutable object', async kind => {
    // Instrument the boundary's own-key enumeration, not wall-clock time.
    // Application proxies are trusted code; this proxy only counts visits.
    const doc = document();
    const ownKeys = vi.fn(Reflect.ownKeys);
    const observed = new Proxy<DIDDocument>(doc, { ownKeys });
    class Override extends RuntimeFetchProvider {
      override async resolveDID() { return observed; }
    }
    const custom: FetchProvider = {
      resolveDID: async () => observed, fetch: async () => new Response(null, { status: 404 }),
      fetchStatusList: async () => null, fetchDelegationChain: async () => [],
    };
    const runtime = new RuntimeFetchProvider({ didResolvers: { web: { resolve: async () => observed } } });
    // Nothing here reaches the network: a did:web fallback, were there one, would read this.
    const fetch = vi.spyOn(runtime, 'fetch').mockImplementation(async () => new Response(null, { status: 404 }));
    const fetcher = kind === 'runtime' ? runtime : kind === 'subclass' ? new Override() : kind === 'wrapper' ? wrapping(runtime) : custom;
    // RuntimeFetchProvider walks a configured resolver's document for each of its callers, and the verifier walks it again.
    const walks = kind === 'runtime' || kind === 'wrapper' ? 2 : 1;
    const check = verifier(fetcher);
    expect(await check.fetchPublicKeyFromDID(did)).toMatchObject(jwk);
    expect(ownKeys).toHaveBeenCalledTimes(walks);
    ownKeys.mockClear();
    doc.id = 'd'.repeat(MAX_DID_LENGTH + 1);
    await expect(check.fetchPublicKeyFromDID(did)).rejects.toThrow();
    expect(ownKeys).toHaveBeenCalledOnce();
    // A refused document ends the resolution: RuntimeFetchProvider does not fall back to its did:web read.
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['runtime', 'subclass', 'wrapper'] as const)('%s: takes a document a built-in resolver admitted without walking it again', async kind => {
    const ownKeys = vi.fn(Reflect.ownKeys);
    const admitted = new Proxy<DIDDocument>(document(), { ownKeys });
    expect(admitParsedDidDocument(admitted).ok).toBe(true);
    ownKeys.mockClear();
    const options = { didResolvers: { web: { resolve: async () => admitted } } };
    const fetcher = kind === 'runtime' ? new RuntimeFetchProvider(options)
      : kind === 'subclass' ? new Delegating(options) : wrapping(new RuntimeFetchProvider(options));
    expect(await verifier(fetcher).fetchPublicKeyFromDID(did)).toMatchObject(jwk);
    expect(ownKeys).not.toHaveBeenCalled();
  });

  it('walks what a subclass returns even when it keeps resolveDID and changes a step behind it', async () => {
    class Rewired extends RuntimeFetchProvider {}
    const overLimit = { ...document(), padding: 'x'.repeat(MAX_DID_DOCUMENT_BYTES) };
    Object.defineProperty(Rewired.prototype, 'resolveWithin', { value: async () => overLimit });
    const rewired = new Rewired();
    expect(rewired.resolveDID).toBe(RuntimeFetchProvider.prototype.resolveDID);
    await expect(verifier(rewired).fetchPublicKeyFromDID(did)).rejects.toThrow();
  });

  it('refuses an empty DID with its own reason, and resolves nothing', async () => {
    const resolveDID = vi.fn(async () => document());
    await expect(verifier({ resolveDID } as unknown as FetchProvider).fetchPublicKeyFromDID('')).rejects.toThrow(/^DID is empty$/);
    expect(resolveDID).not.toHaveBeenCalled();
  });

  it('refuses a DID or key id over its limit with the limit error, and resolves neither', async () => {
    const resolveDID = vi.fn(async () => document());
    const fetcher = { resolveDID } as unknown as FetchProvider;
    const over: [string, string | undefined][] = [
      [`did:web:${'a'.repeat(MAX_DID_LENGTH)}`, undefined], [did, `${did}#${'k'.repeat(MAX_KEY_ID_LENGTH)}`],
    ];
    for (const [subject, kid] of over) {
      await expect(verifier(fetcher).fetchPublicKeyFromDID(subject, kid)).rejects.toThrow('DID or key identifier exceeds resource limit');
    }
    expect(await resolveProofDid(fetcher, did, '#'.repeat(MAX_KEY_ID_LENGTH + 1))).toBeNull();
    expect(resolveDID).not.toHaveBeenCalled();
    expect(await resolveProofDid(fetcher, did, '#'.repeat(MAX_KEY_ID_LENGTH))).toEqual(document());
  });

  it('validates an instance override and rejects custom documents missing id', async () => {
    const fetcher = new RuntimeFetchProvider();
    const { id: _id, ...withoutId } = document();
    fetcher.resolveDID = async () => withoutId as DIDDocument;
    await expect(verifier(fetcher).fetchPublicKeyFromDID(did)).rejects.toThrow();
  });

  it('does not treat a prototype replacement as the bounded implementation', async () => {
    const replacement = vi.spyOn(RuntimeFetchProvider.prototype, 'resolveDID')
      .mockResolvedValue({ ...document(), id: 'd'.repeat(MAX_DID_LENGTH + 1) });
    try { await expect(verifier(new RuntimeFetchProvider()).fetchPublicKeyFromDID(did)).rejects.toThrow(); }
    finally { replacement.mockRestore(); }
  });

  it('serves a built-in cache hit frozen, so the proof verifier gets the document that was measured', async () => {
    const fetcher = new RuntimeFetchProvider();
    const fetch = vi.spyOn(fetcher, 'fetch').mockImplementation(async () => new Response(JSON.stringify(document())));
    const doc = (await fetcher.resolveDID(did))!;
    expect(Object.isFrozen(doc) && Object.isFrozen(doc.verificationMethod![0]!.publicKeyJwk)).toBe(true);
    expect(() => { doc.id = 'd'.repeat(MAX_DID_LENGTH + 1); }).toThrow(TypeError);
    expect(await fetcher.resolveDID(did)).toBe(doc);
    expect(await verifier(fetcher).fetchPublicKeyFromDID(did)).toEqual({ ...jwk, kid: `${did}#key` });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('keeps the outer deadline across a configured resolver and its fallback', async () => {
    vi.useFakeTimers();
    const fetcher = new RuntimeFetchProvider({
      didResolvers: { web: { resolve: () => new Promise(resolve => setTimeout(() => resolve(null), 4000)) } },
    });
    const cancel = vi.fn();
    const fetch = vi.spyOn(fetcher, 'fetch').mockImplementation(async () => new Response(new ReadableStream({ cancel })));
    try {
      const failed = expect(verifier(fetcher).fetchPublicKeyFromDID(did)).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(4000);
      expect(fetch).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS - 4000);
      await failed;
      // The built-in fetch has its own cancellation deadline; the outer wait
      // must not silently turn into two sequential five-second waits.
      await vi.advanceTimersByTimeAsync(4000);
      expect(cancel).toHaveBeenCalled();
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });
});
