/**
 * The requests the cheqd DID resolver makes, and what it logs when one fails. It resolves the
 * application's `headers` under the read's one deadline, so a headers function that never answers
 * costs a resolution at most 5,000 ms and wedges nothing: the next resolution starts afresh and
 * finds the document once the function answers again, called directly or through
 * `RuntimeFetchProvider`. A failed read is logged with the resolver URL's origin and path, never
 * the credentials before its host, its query or its fragment, where an operator may keep a key.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { DidCheqdResolver } from '../resolver.js';
import { RuntimeFetchProvider } from '../../../providers/runtime-fetch.js';
import { DID_RESOLUTION_TIMEOUT_MS } from '../../../delegation/did-resource-policy.js';
import { logger } from '../../../logging/index.js';
import type { FetchProvider } from '../../../providers/base.js';

const DID = 'did:cheqd:testnet:6c9b1bbe-1a2c-4c1e-9d3c-2e0f0f0b0a01';
const document = { id: DID, verificationMethod: [] };

/** A provider whose `fetch` answers `response` and counts its calls. */
const answering = (response: () => Response) => {
  const fetch = vi.fn(async () => response());
  return { fetch, provider: { fetch } as unknown as FetchProvider };
};

/** `promise`'s outcome so far: `pending`, or the value it resolved to. */
function watched<T>(promise: Promise<T>): { outcome: T | 'pending' } {
  const state: { outcome: T | 'pending' } = { outcome: 'pending' };
  void promise.then(value => { state.outcome = value; });
  return state;
}

/** Each way a verifier asks the resolver for a DID. */
const callers: [string, (resolver: DidCheqdResolver) => (did: string) => Promise<unknown>][] = [
  ['directly', resolver => did => resolver.resolve(did)],
  ['through RuntimeFetchProvider', resolver => {
    const runtime = new RuntimeFetchProvider({ didResolvers: { cheqd: resolver } });
    return did => runtime.resolveDID(did);
  }],
];

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('the cheqd resolver and a headers function that never answers', () => {
  it.each(callers)('%s: ends the resolution by the deadline, and finds the document on the next once the function answers', async (_how, caller) => {
    vi.useFakeTimers();
    const { fetch, provider } = answering(() => new Response(JSON.stringify(document)));
    // The first call never answers; every later one does.
    const headers = vi.fn(() => headers.mock.calls.length === 1
      ? new Promise<Record<string, string>>(() => {})
      : Promise.resolve({ Authorization: 'Bearer token' }));
    const resolve = caller(new DidCheqdResolver(provider, { resolverUrl: 'https://resolver.example', headers }));
    const first = watched(resolve(DID));
    await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS - 1);
    expect(first.outcome).toBe('pending');
    await vi.advanceTimersByTimeAsync(1);
    expect(first.outcome).toBeNull();
    const second = watched(resolve(DID));
    await vi.advanceTimersByTimeAsync(10);
    expect(second.outcome).toEqual(document);
    expect([headers.mock.calls.length, fetch.mock.calls.length]).toEqual([2, 1]);
  });
});

describe('the cheqd resolver logs a failed read', () => {
  it("with the resolver URL's origin and path, never its credentials, query or fragment", async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const short = 'did:cheqd:testnet:a';
    const { provider } = answering(() => new Response('{}', { status: 500 }));
    const resolverUrl = 'https://user:pass@r.example/{did}?key=secret#top';
    expect(await new DidCheqdResolver(provider, { resolverUrl }).resolve(short)).toBeNull();
    expect(warn.mock.calls).toEqual([
      [`[DidCheqdResolver] Error resolving ${short}: DID resolution failed: HTTP 500 for "https://r.example/${short}"`],
    ]);
  });
});
