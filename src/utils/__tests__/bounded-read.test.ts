/**
 * `readCappedBody`, the one body reader the bounded fetch and SafeFetch share: it honours a signal
 * that was aborted before the read began, ends a read whose signal aborts, and cancels the body of
 * any read it does not finish. The bounded fetch reads only a 2xx response, names the URL of one it
 * refuses by its origin and path alone, and holds a request it is promised to the read's deadline.
 */

import { getEventListeners } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchBoundedJson, readCappedBody } from '../bounded-read.js';
import { DID_DOCUMENT_READ } from '../../delegation/did-resource-policy.js';
import { fetchTransport } from '../safe-fetch.js';

/** A body that sends nothing and never ends, with a spy on its cancellation. */
function stalled() {
  const cancel = vi.fn();
  return { cancel, body: new ReadableStream<Uint8Array>({ cancel }) };
}

const tooLarge = () => new Error('too large');

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('readCappedBody', () => {
  it('refuses at once, with the reason, a signal aborted before the read began, and cancels the body', async () => {
    const { cancel, body } = stalled();
    const reason = new Error('aborted before the read');
    await expect(readCappedBody(body, { maxBytes: 16, signal: AbortSignal.abort(reason), tooLarge })).rejects.toBe(reason);
    expect(cancel).toHaveBeenCalledOnce();
  }, 2_000);

  it('ends a pending read with the reason its signal aborts with, and cancels the body', async () => {
    const { cancel, body } = stalled();
    const controller = new AbortController();
    const reading = readCappedBody(body, { maxBytes: 16, signal: controller.signal, tooLarge });
    const reason = new Error('deadline');
    controller.abort(reason);
    await expect(reading).rejects.toBe(reason);
    expect(cancel).toHaveBeenCalledOnce();
  }, 2_000);

  it('leaves no abort listener on the signal once the read ends, read whole or refused', async () => {
    for (const [text, maxBytes] of [['{}', 16], ['{"too":"long"}', 4]] as const) {
      const controller = new AbortController();
      await readCappedBody(new Response(text).body!, { maxBytes, signal: controller.signal, tooLarge }).catch(() => undefined);
      expect(getEventListeners(controller.signal, 'abort')).toEqual([]);
    }
  });
});

describe('fetchBoundedJson', () => {
  it('refuses a 300 and a 304 that carry a JSON document, as any response that is not 2xx, and cancels the body', async () => {
    for (const status of [300, 304]) {
      const cancel = vi.fn();
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"id":"did:web:status.example"}'));
          controller.close();
        },
        cancel,
      });
      // A runtime builds no 304 with a body, but a provider can return one.
      const response = Object.defineProperties(new Response(body), { status: { value: status }, ok: { value: false } });
      const reading = fetchBoundedJson({ fetch: async () => response }, 'https://status.example/', {}, DID_DOCUMENT_READ);
      await expect(reading).rejects.toThrow(`DID resolution failed: HTTP ${status} for "https://status.example/"`);
      expect(cancel).toHaveBeenCalledOnce();
    }
  });

  it('names a URL it refuses by its origin and path, never the credentials before its host, its query or its fragment', async () => {
    const named: [string, string][] = [
      ['https://user:pass@r.example/1.0/identifiers/did:cheqd:testnet:a?key=secret#top', '"https://r.example/1.0/identifiers/did:cheqd:testnet:a"'],
      ['https://r.example/a?key=secret', '"https://r.example/a"'], ['https://r.example/a#key=secret', '"https://r.example/a"'],
      ['https://user@r.example:8443?key=secret', '"https://r.example:8443"'], ['https://user:p@ss@r.example/a', '"https://r.example/a"'],
      ['https://r.example/a@b/c', '"https://r.example/a@b/c"'],
      ['https://r.example\\a@b', '"https://r.example\\\\a@b"'], ['https://status.example/\uD800', '"https://status.example/\\ud800"'],
    ];
    for (const [url, quoted] of named) {
      const reading = fetchBoundedJson({ fetch: async () => new Response('{}', { status: 500 }) }, url, {}, DID_DOCUMENT_READ);
      await expect(reading).rejects.toMatchObject({ message: `DID resolution failed: HTTP 500 for ${quoted}` });
    }
  });

  it('holds a request it is promised to the deadline, and asks for nothing when the promise never settles', async () => {
    vi.useFakeTimers();
    try {
      const fetch = vi.fn(async () => new Response('{}'));
      let outcome: unknown = 'pending';
      const reading = fetchBoundedJson({ fetch }, 'https://r.example/', new Promise<RequestInit>(() => {}), DID_DOCUMENT_READ)
        .catch((error: Error) => { outcome = error.message; });
      await vi.advanceTimersByTimeAsync(DID_DOCUMENT_READ.timeoutMs - 1);
      expect(outcome).toBe('pending');
      await vi.advanceTimersByTimeAsync(1);
      await reading;
      expect(outcome).toBe('DID resolution deadline exceeded');
      expect(fetch).not.toHaveBeenCalled();
      const init = Promise.resolve({ headers: { Accept: 'application/json' } });
      expect(await fetchBoundedJson({ fetch }, 'https://r.example/', init, DID_DOCUMENT_READ)).toEqual({});
      expect(fetch).toHaveBeenCalledWith('https://r.example/', { headers: { Accept: 'application/json' }, signal: expect.any(AbortSignal) });
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });
});

describe("SafeFetch's fetch transport reads through it", () => {
  it('ends the read when its signal aborts, even for a body the runtime does not tie to the signal', async () => {
    const { cancel, body } = stalled();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body)));
    const controller = new AbortController();
    const reading = fetchTransport('https://example.com/', {
      signal: controller.signal, hostname: 'example.com', pinnedAddress: '', family: 4, maxBytes: 16,
    });
    const reason = new Error('safe-fetch: timed out');
    await vi.waitFor(() => expect(fetch).toHaveBeenCalled());
    controller.abort(reason);
    await expect(reading).rejects.toBe(reason);
    expect(cancel).toHaveBeenCalledOnce();
  }, 2_000);
});
