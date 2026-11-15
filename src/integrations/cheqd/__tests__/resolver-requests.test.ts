/**
 * The requests the cheqd DID resolver makes, and what it logs when one fails. It resolves the
 * application's `headers` under the read's one deadline, so a headers function that never answers
 * costs a resolution at most 5,000 ms and wedges nothing: the next resolution starts afresh and
 * finds the document once the function answers again, called directly or through
 * `RuntimeFetchProvider`. A failed read is logged with the resolver URL's origin and path, never
 * the credentials before its host, its query or its fragment, where an operator may keep a key.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEADLINES, REFUSED_TIMEOUTS, settledAt, timeoutTypeError } from '../../../__tests__/utils/deadlines.js';
import { cheqdResolver, createDidCheqdResolver, DidCheqdResolver } from '../resolver.js';
import { RuntimeFetchProvider } from '../../../providers/runtime-fetch.js';
import { DID_RESOLUTION_TIMEOUT_MS } from '../../../delegation/did-resource-policy.js';
import { logger } from '../../../logging/index.js';
import type { FetchProvider } from '../../../providers/base.js';
import { documentOf } from '../../../__tests__/utils/did-documents.js';

const DID = 'did:cheqd:testnet:6c9b1bbe-1a2c-4c1e-9d3c-2e0f0f0b0a01';
const document = documentOf({ verificationMethod: [] }, DID);

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

describe.each(DEADLINES)('the cheqd resolver and a dependency that never answers, %s', (_label, option, ms) => {
  const options = { resolverUrl: 'https://resolver.example', ...option };

  it('resolves no document when its fetch has not answered by the deadline', async () => {
    expect(await settledAt(ms, (never) => new DidCheqdResolver({ fetch: never } as unknown as FetchProvider, options).resolve(DID))).toBeNull();
  });

  it('resolves no document when its headers function has not answered by the deadline', async () => {
    const { provider } = answering(() => new Response(JSON.stringify(document)));
    expect(await settledAt(ms, (never) => createDidCheqdResolver(provider, { ...options, headers: never }).resolve(DID))).toBeNull();
  });

  it('takes the deadline of the registry that builds it from a factory, unless its own options set one', async () => {
    const factory = cheqdResolver({ resolverUrl: 'https://resolver.example' });
    expect(await settledAt(ms, (never) => factory({ fetch: never } as unknown as FetchProvider, option).resolve(DID))).toBeNull();
    vi.useRealTimers();
    const own = cheqdResolver({ resolverUrl: 'https://resolver.example', dependencyTimeoutMs: 6_000 });
    expect(await settledAt(6_000, (never) => own({ fetch: never } as unknown as FetchProvider, option).resolve(DID))).toBeNull();
    vi.useRealTimers();
    const runtime = new RuntimeFetchProvider({ didResolvers: { cheqd: factory }, ...option });
    expect(await settledAt(ms, (never) => {
      vi.spyOn(runtime, 'fetch').mockImplementation(never);
      return runtime.resolveDID(DID);
    })).toBeNull();
  });

  it('shares one pending read among resolutions of a DID until the deadline, and starts another after it', async () => {
    vi.useFakeTimers();
    const fetch = vi.fn(() => new Promise<Response>(() => undefined));
    const resolver = cheqdResolver(options)({ fetch } as unknown as FetchProvider);
    void resolver.resolve(DID);
    await vi.advanceTimersByTimeAsync(ms - 1);
    void resolver.resolve(DID);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetch).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    void resolver.resolve(DID);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

describe('the cheqd resolver and a dependencyTimeoutMs it cannot wait', () => {
  it.each(REFUSED_TIMEOUTS)('throws a TypeError when built with %s', (_label, value, got) => {
    const { provider } = answering(() => new Response('{}'));
    const options = { resolverUrl: 'https://resolver.example', dependencyTimeoutMs: value as number };
    expect(() => new DidCheqdResolver(provider, options)).toThrow(timeoutTypeError(got));
    expect(() => createDidCheqdResolver(provider, options)).toThrow(timeoutTypeError(got));
  });
});
