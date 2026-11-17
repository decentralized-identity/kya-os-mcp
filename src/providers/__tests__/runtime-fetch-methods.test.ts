/**
 * `RuntimeFetchProvider.resolveDID` asks a configured resolver only for a method its registry holds
 * as its own. A method an object's prototype holds, such as `constructor` or `__proto__`, names no
 * resolver, so a DID of one resolves to nothing, as a DID of any other method no resolver serves
 * does, and nothing put on `Object.prototype` is ever asked.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { RuntimeFetchProvider } from '../../index.js';
import { documentOf } from '../../__tests__/utils/did-documents.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('RuntimeFetchProvider.resolveDID by method', () => {
  it.each(['did:constructor:x', 'did:__proto__:x'])('resolves %s to nothing, and fetches nothing', async (did) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    const provider = new RuntimeFetchProvider({ didResolvers: { example: { resolve: async () => null } } });
    expect(await provider.resolveDID(did)).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('asks a resolver the registry holds as its own, even under a name the prototype holds too', async () => {
    const did = 'did:constructor:x';
    const document = documentOf({}, did);
    const provider = new RuntimeFetchProvider({ didResolvers: { constructor: { resolve: async () => document } } });
    expect((await provider.resolveDID(did))?.id).toBe(did);
  });

  it('never asks a resolver the prototype holds', async () => {
    const did = 'did:inherited:x';
    const document = documentOf({}, did);
    const resolve = vi.fn(async () => document);
    Object.defineProperty(Object.prototype, 'inherited', { value: { resolve }, configurable: true });
    try {
      expect(await new RuntimeFetchProvider().resolveDID(did)).toBeNull();
      expect(resolve).not.toHaveBeenCalled();
    } finally {
      delete (Object.prototype as Record<string, unknown>).inherited;
    }
  });
});
