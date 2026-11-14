/**
 * How the built-in resolvers read a response, and how long a verifier waits for a resolver: one
 * 5,000 ms deadline, kept even by a body whose reader ignores cancellation, with no timer left
 * behind; at most 64 empty chunks; and a buffer that never grows past the 1 MiB cap, nor for a
 * chunk that adds nothing.
 */

import { afterEach, describe, it, expect, vi } from 'vitest';
import { fetchDidJson } from '../read-did-json.js';
import { resolveBoundedDid, MAX_DID_DOCUMENT_BYTES as CAP } from '../did-resource-limits.js';
import type { DIDDocument } from '../vc-verifier.types.js';
import type { FetchProvider } from '../../providers/base.js';

const did = 'did:web:limits.example';
const url = 'https://limits.example/.well-known/did.json';
const provider = (fetch: () => Promise<Response>) => ({ fetch }) as unknown as FetchProvider;
const bytes = (text: string) => new TextEncoder().encode(text);

/** A response streaming `chunks` as given, empty ones included. */
const streaming = (chunks: Uint8Array[]) => new Response(new ReadableStream<Uint8Array>({
  start(controller) {
    for (const chunk of chunks) controller.enqueue(chunk);
    controller.close();
  },
}));

/** A response whose body never answers a read and ignores cancellation, as a custom transport's may. */
const ignoringCancellation = () => ({
  ok: true,
  status: 200,
  body: {
    getReader: () => ({ read: () => new Promise(() => {}), cancel: async () => {}, releaseLock: () => {} }),
    cancel: async () => {},
  },
}) as unknown as Response;

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('the resolution deadline', () => {
  const stalled: Record<string, () => Promise<unknown>> = {
    resolver: () => resolveBoundedDid({ resolve: () => new Promise(() => {}) }, did),
    fetch: () => fetchDidJson(provider(() => new Promise(() => {})), url),
    'body that ignores cancellation': () => fetchDidJson(provider(async () => ignoringCancellation()), url),
  };

  it.each(Object.keys(stalled))('waits 5,000 ms for a stalled %s, and no longer', async kind => {
    vi.useFakeTimers();
    let outcome: string | undefined;
    const settled = stalled[kind]!().then(() => 'resolved', (error: Error) => error.message).then(value => { outcome = value; });
    await vi.advanceTimersByTimeAsync(4_999);
    expect(outcome).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await settled;
    expect(outcome).toBe('DID resolution deadline exceeded');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('leaves no timer behind once a resolver or a response answers', async () => {
    vi.useFakeTimers();
    expect(await resolveBoundedDid({ resolve: async () => ({ id: did }) as DIDDocument }, did)).toEqual({ id: did });
    expect(await fetchDidJson(provider(async () => streaming([bytes(`{"id":"${did}"}`)])), url)).toEqual({ id: did });
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('the response body', () => {
  it.each([[63, true], [64, true], [65, false]] as const)('after %i empty chunks, reads the document: %s', async (empty, reads) => {
    const chunks = [...Array.from({ length: empty }, () => new Uint8Array()), bytes(`{"id":"${did}"}`)];
    const reading = fetchDidJson(provider(async () => streaming(chunks)), url);
    if (reads) expect(await reading).toEqual({ id: did });
    else await expect(reading).rejects.toThrow('empty-chunk limit');
  });

  /** The capacities of the buffers the reader allocates while reading `chunks`. */
  async function allocations(chunks: Uint8Array[]): Promise<number[]> {
    const response = streaming(chunks);
    const sizes: number[] = [];
    const Native = Uint8Array;
    vi.stubGlobal('Uint8Array', new Proxy(Native, {
      construct(target, args, newTarget) {
        if (typeof args[0] === 'number' && args[0] > 0) sizes.push(args[0]);
        return Reflect.construct(target, args, newTarget) as object;
      },
    }));
    try {
      await fetchDidJson(provider(async () => response), url);
    } finally {
      vi.unstubAllGlobals();
    }
    return sizes;
  }

  it('grows its buffer no further than the 1 MiB cap', async () => {
    const json = `{"id":"${did}"}`;
    const body = bytes(json + ' '.repeat(CAP - json.length));
    const chunks = Array.from({ length: Math.ceil(CAP / 3_000) }, (_, i) => body.subarray(i * 3_000, (i + 1) * 3_000));
    expect(Math.max(...await allocations(chunks))).toBe(CAP);
  });

  it('allocates nothing for an empty chunk after a full buffer', async () => {
    const body = bytes(`{"id":"${did}"}`);
    expect(await allocations([body, new Uint8Array(), new Uint8Array()])).toEqual([body.length]);
  });
});
