/**
 * SafeFetch's defaults for the options a caller leaves out (`../safe-fetch`): 5,000 ms for each
 * hop, and 1,048,576 bytes of response body. Each is tested one under, at and one over.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createSafeFetch, type DnsLookup, type RawResponse, type TransportInit } from '../safe-fetch.js';

const lookup: DnsLookup = async () => [{ address: '93.184.216.34', family: 4 }];

const HOP_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 1_048_576;

const respondingWith = (body: string): RawResponse =>
  ({ status: 200, headers: { get: () => null }, text: () => Promise.resolve(body) });

/** A JSON string value of exactly `bytes` bytes, quotes included. */
const jsonOfBytes = (bytes: number): string => `"${'a'.repeat(bytes - 2)}"`;

afterEach(() => vi.useRealTimers());

describe("SafeFetch's default size cap", () => {
  it('is 1,048,576 bytes, passed to the transport and applied to the body it returns', async () => {
    const at = vi.fn(async (_url: string, _init: TransportInit) => respondingWith(jsonOfBytes(MAX_RESPONSE_BYTES)));
    const response = await createSafeFetch({ lookup, transport: at })('https://example.com/card');
    expect(await response.json()).toHaveLength(MAX_RESPONSE_BYTES - 2);
    expect(at.mock.calls[0]![1].maxBytes).toBe(MAX_RESPONSE_BYTES);

    const over = async (): Promise<RawResponse> => respondingWith(jsonOfBytes(MAX_RESPONSE_BYTES + 1));
    await expect(createSafeFetch({ lookup, transport: over })('https://example.com/card')).rejects.toThrow(
      `safe-fetch: response body exceeds size cap ${MAX_RESPONSE_BYTES}`,
    );
  });
});

describe("SafeFetch's default timeout", () => {
  /** A transport that answers only by rejecting with its signal's reason once that aborts. */
  const stalled = (_url: string, init: TransportInit): Promise<RawResponse> =>
    new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason as Error)));

  it('is 5,000 ms for a hop: still waiting one millisecond before, refused at it', async () => {
    vi.useFakeTimers();
    let outcome: unknown = 'pending';
    const read = createSafeFetch({ lookup, transport: stalled })('https://example.com/card').catch((error: unknown) => {
      outcome = error;
    });
    await vi.advanceTimersByTimeAsync(HOP_TIMEOUT_MS - 1);
    expect(outcome).toBe('pending');
    await vi.advanceTimersByTimeAsync(1);
    await read;
    expect(outcome).toEqual(new Error(`safe-fetch: request to example.com timed out after ${HOP_TIMEOUT_MS}ms`));
  });

  it('bounds each hop on its own, so a redirect starts a new 5,000 ms', async () => {
    vi.useFakeTimers();
    const slowRedirect = (url: string, init: TransportInit): Promise<RawResponse> =>
      url.endsWith('/b')
        ? stalled(url, init)
        : new Promise(resolve => setTimeout(() => resolve({
            status: 302, headers: { get: name => (name === 'location' ? '/b' : null) }, text: () => Promise.resolve(''),
          }), HOP_TIMEOUT_MS - 1));
    let outcome: unknown = 'pending';
    const read = createSafeFetch({ lookup, transport: slowRedirect })('https://example.com/a').catch((error: unknown) => {
      outcome = error;
    });
    await vi.advanceTimersByTimeAsync(2 * HOP_TIMEOUT_MS - 2);
    expect(outcome).toBe('pending');
    await vi.advanceTimersByTimeAsync(1);
    await read;
    expect(outcome).toEqual(new Error(`safe-fetch: request to example.com timed out after ${HOP_TIMEOUT_MS}ms`));
  });
});
