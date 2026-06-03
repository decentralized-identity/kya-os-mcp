import { describe, it, expect } from 'vitest';
import { NoopFetchProvider } from '../runtime-fetch.js';

describe('NoopFetchProvider (offline fallback)', () => {
  const provider = new NoopFetchProvider();

  it('resolveDID returns null — nothing is resolvable without network', async () => {
    expect(await provider.resolveDID('did:web:example.com')).toBeNull();
  });

  it('fetchStatusList returns null — revocation checks fail closed', async () => {
    expect(await provider.fetchStatusList('https://example.com/status/1')).toBeNull();
  });

  it('fetchDelegationChain returns an empty chain', async () => {
    expect(await provider.fetchDelegationChain('urn:delegation:1')).toEqual([]);
  });

  it('fetch throws rather than pretending to succeed', async () => {
    await expect(provider.fetch('https://example.com')).rejects.toThrow('fetch unavailable');
  });
});
