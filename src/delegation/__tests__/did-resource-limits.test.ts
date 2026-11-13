import { createServer } from 'node:http';
import { gzipSync } from 'node:zlib';
import { describe, it, expect, vi } from 'vitest';
import { RuntimeFetchProvider } from '../../providers/runtime-fetch.js';
import { fetchDidJson } from '../read-did-json.js';
import { checkJsonTokens } from '../../utils/json-preflight.js';
import { measureDidDocument, resolveBoundedDid, resolveWithinLimits, resolutionDeadline, DidDocumentCache, MAX_DID_DOCUMENT_BYTES as CAP,
  MAX_DID_LENGTH, MAX_KEY_ID_LENGTH, DID_RESOLUTION_TIMEOUT_MS, DID_DOCUMENT_JSON } from '../did-resource-limits.js';
import { DidWebResolver } from '../did-web-resolver.js';
import { DidCheqdResolver } from '../../integrations/cheqd/resolver.js';
import type { FetchProvider } from '../../providers/base.js';
import type { DIDDocument } from '../vc-verifier.types.js';

const did = 'did:web:limits.example';
const provider = (fetch: FetchProvider['fetch']) => ({ fetch }) as FetchProvider;
const encoded = (value: string) => new TextEncoder().encode(value);
const checkTokens = (text: string) => checkJsonTokens(text, DID_DOCUMENT_JSON);
const document = { id: did, verificationMethod: [{ id: '#key', type: 'JsonWebKey', controller: did }], assertionMethod: ['#key'] };

describe('DID resource boundaries', () => {
  it.each([1, 511, 8192])('allocates nothing while stalled and linear total storage for %i-byte chunks', async chunkSize => {
    const data = encoded(JSON.stringify({ id: did, padding: 'x'.repeat(8000) }));
    const chunks = Array.from({ length: Math.ceil(data.length / chunkSize) }, (_, i) => data.subarray(i * chunkSize, (i + 1) * chunkSize));
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    let started!: () => void;
    const reading = new Promise<void>(resolve => { started = resolve; });
    const response = new Response(new ReadableStream<Uint8Array>({
      start(value) { controller = value; }, pull() { started(); },
    }, { highWaterMark: 0 }));
    const allocations: number[] = [];
    const Native = Uint8Array;
    vi.stubGlobal('Uint8Array', new Proxy(Native, {
      construct(target, args, newTarget) {
        if (typeof args[0] === 'number') allocations.push(args[0]);
        return Reflect.construct(target, args, newTarget);
      },
    }));
    const originalSet = Native.prototype.set;
    let copied = 0;
    const set = vi.spyOn(Native.prototype, 'set').mockImplementation(function (this: Uint8Array, input, offset) {
      copied += input.length;
      originalSet.call(this, input, offset);
    });
    let closed = false;
    const result = fetchDidJson(provider(async () => response), 'https://limits.example');
    try {
      await reading;
      expect(allocations.reduce((a, b) => a + b, 0)).toBe(0);
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
      closed = true;
      expect(await result).toEqual(JSON.parse(new TextDecoder().decode(data)));
      // Geometric growth: all allocated capacities sum to < 4N; received
      // bytes plus copied prefixes cost < 3N. No timing threshold or JIT warmup.
      expect(allocations.reduce((a, b) => a + b, 0)).toBeLessThan(4 * data.length);
      expect(copied).toBeLessThan(3 * data.length);
      expect(Math.max(...allocations)).toBeLessThanOrEqual(2 * data.length);
    } finally {
      if (!closed) controller.close();
      await result.catch(() => {});
      set.mockRestore();
      vi.unstubAllGlobals();
    }
  });

  it('accepts exactly the byte cap and rejects cap + 1 before JSON.parse', async () => {
    const json = JSON.stringify({ id: did });
    const atCap = json + ' '.repeat(CAP - encoded(json).length);
    expect(await fetchDidJson(provider(async () => new Response(atCap)), 'https://limits.example')).toEqual({ id: did });
    const parse = vi.spyOn(JSON, 'parse');
    try {
      await expect(fetchDidJson(provider(async () => new Response(atCap + ' ')), 'https://limits.example')).rejects.toThrow('byte limit');
      expect(parse).not.toHaveBeenCalled();
    } finally { parse.mockRestore(); }
  });

  it('counts decoded response bytes despite a lying Content-Length and cancels the stream', async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(CAP + 1)); }, cancel,
    });
    await expect(fetchDidJson(provider(async () => new Response(stream, { headers: { 'Content-Length': '1', 'Content-Encoding': 'gzip' } })), 'https://limits.example')).rejects.toThrow('byte limit');
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('caps the decompressed body through the real runtime fetch provider', async () => {
    const compressed = gzipSync(JSON.stringify({ id: did }) + ' '.repeat(CAP));
    const server = createServer((_request, response) => {
      response.writeHead(200, { 'Content-Encoding': 'gzip', 'Content-Length': compressed.length });
      response.end(compressed);
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('missing test listener');
      // The server is on 127.0.0.1, a host the private-network rule refuses unless the provider opts out.
      const provider = new RuntimeFetchProvider({ allowPrivateNetworkHosts: true });
      await expect(fetchDidJson(provider, `http://127.0.0.1:${address.port}/did.json`)).rejects.toThrow('byte limit');
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it('bounds empty chunks even when a synchronous stream starves timers', async () => {
    const cancel = vi.fn();
    let reads = 0;
    // A reader that kept reading would starve the test's own timeout, so the stream ends it instead.
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (++reads > 10_000) controller.error(new Error('the reader took 10,000 empty chunks without refusing the body'));
        else controller.enqueue(new Uint8Array());
      },
      cancel,
    });
    await expect(fetchDidJson(provider(async () => new Response(stream)), 'https://limits.example')).rejects.toThrow('empty-chunk limit');
    expect(reads).toBeLessThanOrEqual(66); // one queued chunk may be prefetched
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('reads split UTF-8 correctly, rejects invalid UTF-8, and rejects escaped long keys before parsing', async () => {
    const bytes = encoded('{"id":"😀"}');
    const stream = new ReadableStream<Uint8Array>({ start(controller) {
      for (const byte of bytes) controller.enqueue(Uint8Array.of(byte)); controller.close();
    } });
    expect(await fetchDidJson(provider(async () => new Response(stream)), 'https://limits.example')).toEqual({ id: '😀' });
    // A lead byte whose continuation byte is missing, inside a JSON string that is otherwise valid.
    const invalid = Uint8Array.of(...encoded('{"id":"'), 0xc3, ...encoded('"}'));
    await expect(fetchDidJson(provider(async () => new Response(invalid)), 'https://limits.example'))
      .rejects.toThrow('DID resolution response is not valid UTF-8');
    const parse = vi.spyOn(JSON, 'parse');
    try {
      await expect(fetchDidJson(provider(async () => new Response('{"' + '\\u0061'.repeat(257) + '":0}')), 'https://limits.example')).rejects.toThrow('member limit');
      expect(parse).not.toHaveBeenCalled();
    } finally { parse.mockRestore(); }
    expect(() => checkTokens('{"' + '\\u0061'.repeat(256) + '":0}')).not.toThrow();
  });

  it('preflights depth and member count, including duplicate names, without interpreting strings as structure', () => {
    expect(() => checkTokens('['.repeat(64) + '0' + ']'.repeat(64))).not.toThrow();
    expect(() => checkTokens('['.repeat(65) + '0' + ']'.repeat(65))).toThrow('nesting');
    expect(() => checkTokens('{' + Array(8192).fill('"x":0').join(',') + '}')).not.toThrow();
    expect(() => checkTokens('{' + Array(8193).fill('"x":0').join(',') + '}')).toThrow('member');
    expect(() => checkTokens(JSON.stringify({ text: '[{"\\'.repeat(1000) }))).not.toThrow();
  });

  it.each(['fetch', 'body'] as const)('times out a stalled %s and cancels late/active bodies', async phase => {
    vi.useFakeTimers();
    const cancel = vi.fn();
    let deliver!: (response: Response) => void;
    const response = new Response(new ReadableStream<Uint8Array>({ cancel }));
    const fetch = vi.fn(async (_url: string, options?: unknown) => {
      expect((options as RequestInit).signal).toBeInstanceOf(AbortSignal);
      return phase === 'fetch' ? new Promise<Response>(resolve => { deliver = resolve; }) : response;
    });
    try {
      const result = fetchDidJson(provider(fetch), 'https://limits.example');
      const refused = expect(result).rejects.toThrow('deadline');
      await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS);
      await refused;
      // A response that arrives after the deadline has its body cancelled once it reaches the reader.
      if (phase === 'fetch') deliver(response);
      await vi.waitFor(() => expect(cancel).toHaveBeenCalled());
      expect((fetch.mock.calls[0]![1] as RequestInit).signal?.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });

  it('applies identifier limits before calling a custom resolver and validates its returned document', async () => {
    const resolve = vi.fn(async () => document);
    expect(await resolveBoundedDid({ resolve }, 'd'.repeat(MAX_DID_LENGTH + 1))).toBeNull();
    expect(await resolveBoundedDid({ resolve }, did, '#'.repeat(MAX_KEY_ID_LENGTH + 1))).toBeNull();
    expect(resolve).not.toHaveBeenCalled();
    expect(await resolveBoundedDid({ resolve }, did)).toEqual(document);
    expect(await resolveBoundedDid({ resolve: async () => ({ ...document, extra: 'x'.repeat(CAP) }) }, did)).toBeNull();
    expect(measureDidDocument({ ...document, assertionMethod: Array(8193).fill('#key') }).ok).toBe(false);
    expect(measureDidDocument({ ...document, assertionMethod: ['#'.repeat(MAX_KEY_ID_LENGTH + 1)] }).ok).toBe(false);
    expect(measureDidDocument({ id: `did:${'d'.repeat(MAX_DID_LENGTH - 4)}` }).ok).toBe(true);
  });

  it('says whether a resolution found a document within the limits, found none, or was refused', async () => {
    const answering = (answer: unknown) => ({ resolve: async () => answer as DIDDocument | null });
    expect(await resolveWithinLimits(answering(document), did)).toEqual({ status: 'found', document });
    for (const answer of [null, undefined]) expect(await resolveWithinLimits(answering(answer), did)).toEqual({ status: 'not found' });
    expect(await resolveWithinLimits(answering({ ...document, extra: 'x'.repeat(CAP) }), did)).toEqual({ status: 'refused' });
    expect(await resolveWithinLimits(answering(document), 'd'.repeat(MAX_DID_LENGTH + 1))).toEqual({ status: 'refused' });
  });

  it('bounds custom resolver waiting and never invokes getters or toJSON to measure data', async () => {
    const getter = vi.fn(() => 'x');
    const bad = Object.defineProperty({ ...document }, 'extra', { enumerable: true, get: getter });
    expect(measureDidDocument(bad).ok).toBe(false);
    expect(getter).not.toHaveBeenCalled();
    const toJSON = vi.fn(() => ({}));
    expect(measureDidDocument({ ...document, toJSON }).ok).toBe(false);
    expect(toJSON).not.toHaveBeenCalled();
    const cycle: Record<string, unknown> = { id: did }; cycle.child = cycle;
    expect(measureDidDocument(cycle)).toEqual({ ok: false, reason: 'document has a cycle' });
    const shared = { kept: [1] };
    const twice = { id: did, first: shared, second: shared };
    expect(measureDidDocument(twice)).toEqual({ ok: true, bytes: encoded(JSON.stringify(twice)).length });
    expect(measureDidDocument({ ...document, optional: undefined })).toEqual({ ok: true, bytes: encoded(JSON.stringify(document)).length });
    const unicode = { id: did, unicode: '\uD800😀\n' };
    expect(measureDidDocument(unicode)).toEqual({ ok: true, bytes: encoded(JSON.stringify(unicode)).length });
    vi.useFakeTimers();
    try {
      const refused = expect(resolveBoundedDid({ resolve: () => new Promise(() => {}) }, did)).rejects.toThrow('deadline');
      await vi.advanceTimersByTimeAsync(DID_RESOLUTION_TIMEOUT_MS); await refused;
      expect(vi.getTimerCount()).toBe(0);
    } finally { vi.useRealTimers(); }
  });

  it('leaves no rejection unhandled when its deadline passes with no step waiting, and refuses a later step at once', async () => {
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const deadline = resolutionDeadline();
      vi.advanceTimersByTime(DID_RESOLUTION_TIMEOUT_MS);
      await new Promise(resolve => setImmediate(resolve));
      expect(unhandled).not.toHaveBeenCalled();
      await expect(deadline.within(new Promise(() => {}))).rejects.toThrow('DID resolution deadline exceeded');
    } finally { vi.useRealTimers(); process.off('unhandledRejection', unhandled); }
  });

  it('bounds retained document count, aggregate bytes and TTL', () => {
    const cache = new DidDocumentCache();
    for (let i = 0; i < 129; i++) cache.set(String(i), document, 100, 10_000);
    expect(cache.get('0')).toBeUndefined(); expect(cache.get('128')).toEqual(document);
    cache.clear();
    for (let i = 0; i < 9; i++) cache.set(String(i), document, CAP, 10_000);
    expect(cache.get('0')).toBeUndefined(); expect(cache.get('8')).toEqual(document);
    cache.set('expired', document, 1, -1); expect(cache.get('expired')).toBeUndefined();
    cache.set('invalid-ttl', document, 1, NaN); expect(cache.get('invalid-ttl')).toBeUndefined();
  });

  it('uses the preparse boundary in both built-in network resolvers, including the cheqd envelope', async () => {
    const hostile = JSON.stringify({ ...document, ['k'.repeat(257)]: 0 });
    const fetch = vi.fn(async () => new Response(hostile));
    const parse = vi.spyOn(JSON, 'parse');
    try {
      expect(await new DidWebResolver(provider(fetch)).resolve(did)).toBeNull();
      expect(await new DidCheqdResolver(provider(fetch), { resolverUrl: 'https://resolver.example' }).resolve('did:cheqd:testnet:123')).toBeNull();
      expect(parse).not.toHaveBeenCalled();
    } finally { parse.mockRestore(); }
    const count = fetch.mock.calls.length;
    // A public host name, so that only the DID limit, not the private-network rule, keeps it from a fetch.
    const overLimit = `did:web:${'x'.repeat(MAX_DID_LENGTH - 'did:web:.example'.length + 1)}.example`;
    expect(overLimit).toHaveLength(MAX_DID_LENGTH + 1);
    expect(await new DidWebResolver(provider(fetch)).resolve(overLimit)).toBeNull();
    expect(fetch).toHaveBeenCalledTimes(count);
  });
});
