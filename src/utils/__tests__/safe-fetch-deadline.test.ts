/**
 * One deadline covers a whole SafeFetch read: `timeoutMs` from its start, over the DNS lookup of
 * each hop, every redirect hop and the body. A caller's `AbortSignal` ends the read too, at any of
 * those steps, with the signal's reason, as `fetch` does.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSafeFetch, type DnsLookup, type RawResponse, type TransportInit } from '../safe-fetch.js';

const TIMEOUT_MS = 1_000;
const EXPIRED = new Error(`safe-fetch: request to example.com timed out after ${TIMEOUT_MS}ms`);
const lookup: DnsLookup = async () => [{ address: '93.184.216.34', family: 4 }];
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

/** A response of `status`, with a `location` header when one is given, and `text` as its body reader. */
const responding = (status: number, location?: string, text = () => Promise.resolve('{}')): RawResponse =>
  ({ status, headers: { get: (name) => (name === 'location' ? location ?? null : null) }, text });

/** `value` after `ms` of the fake clock. */
const after = <T>(ms: number, value: T): Promise<T> => new Promise((resolve) => setTimeout(() => resolve(value), ms));

/** A transport that answers only by rejecting with its signal's reason once that aborts. */
const stalled = (_url: string, init: TransportInit): Promise<RawResponse> =>
  new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason as Error)));

/** How `read` has settled after `ms` of the fake clock: `pending`, or what it rejected with. */
async function settledAfter(ms: number, read: Promise<unknown>): Promise<unknown> {
  let outcome: unknown = 'pending';
  void read.then(() => { outcome = 'resolved'; }, (error: unknown) => { outcome = error; });
  await vi.advanceTimersByTimeAsync(ms);
  return outcome;
}

afterEach(() => vi.useRealTimers());

describe("SafeFetch's one deadline", () => {
  it('covers a DNS lookup that never answers', async () => {
    vi.useFakeTimers();
    const read = createSafeFetch({ lookup: never, transport: stalled, timeoutMs: TIMEOUT_MS })('https://example.com/card');
    expect(await settledAfter(TIMEOUT_MS - 1, read)).toBe('pending');
    expect(await settledAfter(1, read)).toEqual(EXPIRED);
  });

  it('counts the lookup against the request that follows it', async () => {
    vi.useFakeTimers();
    const slowLookup: DnsLookup = () => after(TIMEOUT_MS - 1, [{ address: '93.184.216.34', family: 4 }]);
    const read = createSafeFetch({ lookup: slowLookup, transport: stalled, timeoutMs: TIMEOUT_MS })('https://example.com/card');
    expect(await settledAfter(TIMEOUT_MS, read)).toEqual(EXPIRED);
  });

  it('covers every redirect hop together, rather than each on its own', async () => {
    vi.useFakeTimers();
    const transport = (url: string, init: TransportInit) =>
      url.endsWith('/b') ? stalled(url, init) : after(TIMEOUT_MS - 1, responding(302, '/b'));
    const read = createSafeFetch({ lookup, transport, timeoutMs: TIMEOUT_MS })('https://example.com/a');
    expect(await settledAfter(TIMEOUT_MS, read)).toEqual(EXPIRED);
  });

  it('covers a body that is never read to its end', async () => {
    vi.useFakeTimers();
    const transport = async () => responding(200, undefined, never);
    const read = createSafeFetch({ lookup, transport, timeoutMs: TIMEOUT_MS })('https://example.com/card');
    expect(await settledAfter(TIMEOUT_MS - 1, read)).toBe('pending');
    expect(await settledAfter(1, read)).toEqual(EXPIRED);
  });

  it('is cleared once the read is done', async () => {
    vi.useFakeTimers();
    const response = await createSafeFetch({ lookup, transport: async () => responding(200), timeoutMs: TIMEOUT_MS })('https://example.com/card');
    expect(await response.json()).toEqual({});
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("a SafeFetch caller's AbortSignal", () => {
  const stopped = new Error('the caller stopped waiting');

  it('ends a read in its request, aborting the signal the transport was given', async () => {
    const controller = new AbortController();
    const transport = vi.fn(stalled);
    const read = createSafeFetch({ lookup, transport })('https://example.com/card', { signal: controller.signal });
    await vi.waitFor(() => expect(transport).toHaveBeenCalled());
    controller.abort(stopped);
    await expect(read).rejects.toBe(stopped);
    expect(transport.mock.calls[0]![1].signal.aborted).toBe(true);
  });

  it('ends a read in its DNS lookup, and in its body', async () => {
    const inLookup = new AbortController();
    const lookingUp = createSafeFetch({ lookup: never, transport: stalled })('https://example.com/card', { signal: inLookup.signal });
    inLookup.abort(stopped);
    await expect(lookingUp).rejects.toBe(stopped);

    const inBody = new AbortController();
    const reading = createSafeFetch({ lookup, transport: async () => responding(200, undefined, never) })('https://example.com/card', { signal: inBody.signal });
    await new Promise((resolve) => setTimeout(resolve, 0));
    inBody.abort(stopped);
    await expect(reading).rejects.toBe(stopped);
  });

  it('that has already aborted ends the read before any lookup', async () => {
    const lookupSpy = vi.fn(lookup);
    const read = createSafeFetch({ lookup: lookupSpy, transport: stalled })('https://example.com/card', { signal: AbortSignal.abort(stopped) });
    await expect(read).rejects.toBe(stopped);
    expect(lookupSpy).not.toHaveBeenCalled();
  });
});
