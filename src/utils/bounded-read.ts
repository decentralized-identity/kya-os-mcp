/**
 * The one bounded read of a response from a URL a counterparty named (SPEC §4.4.2): the body is
 * counted as it streams, after content decoding and never from Content-Length; one deadline covers
 * the request's options when they are promised, the response headers and the body together, and
 * always surfaces as that deadline's own reason; a non-2xx response is refused whatever its body says, quoting its
 * URL's origin and path as a refusal quotes any value its sender chose (`describeValue`), since an
 * operator may keep a key in its credentials, query or fragment; and the bytes must be valid UTF-8.
 *
 * Never `response.json()` or `response.text()`: both allocate the whole body before a caller can
 * check its size. A custom `FetchProvider` must therefore return a WHATWG `ReadableStream` body.
 */

import type { FetchProvider } from '../providers/base.js';
import { describeValue } from './describe-value.js';
import { checkJsonTokens, type JsonLimits } from './json-preflight.js';

/** What a bounded read allows, and the name its refusals carry. */
export interface BoundedReadPolicy {
  /** Names the read at the start of every refusal, e.g. "DID resolution". */
  readonly label: string;
  /** Bytes of body read before the read is refused. */
  readonly maxBytes: number;
  /** One deadline, in milliseconds, for the headers and the body together. */
  readonly timeoutMs: number;
}

/** A bounded read of JSON, and the shape its text may have before it is parsed. */
export interface BoundedJsonPolicy extends BoundedReadPolicy {
  readonly json: JsonLimits;
}

/** How {@link readCappedBody} reads one body. */
export interface CappedBodyOptions {
  /** Bytes of body read before the read is refused with `tooLarge()`. */
  readonly maxBytes: number;
  /** Ends the read with the signal's reason, through one listener removed when the read ends. */
  readonly signal?: AbortSignal;
  /** The error for a body longer than `maxBytes`. */
  readonly tooLarge: () => Error;
  /**
   * Empty chunks allowed before the read is refused with `tooManyEmptyChunks()`. They consume no
   * byte budget, and a stream that is always ready can keep a timer from ever firing.
   */
  readonly maxEmptyChunks?: number;
  readonly tooManyEmptyChunks?: () => Error;
}

type ChunkRead = Awaited<ReturnType<ReadableStreamDefaultReader<Uint8Array>['read']>>;

/** Empty chunks a bounded fetch allows before refusing the body. */
export const MAX_EMPTY_CHUNKS = 64;

/**
 * Read `body` to its end into one buffer, refusing more than `maxBytes`. The buffer grows
 * geometrically from nothing, so a stalled body holds no reservation and total copying stays
 * linear in the bytes received. Each read waits on a promise of its own that the one abort
 * listener can end, so nothing accumulates per chunk however small the chunks are.
 */
export async function readCappedBody(body: ReadableStream<Uint8Array>, options: CappedBodyOptions): Promise<Uint8Array> {
  const { maxBytes, signal } = options;
  const maxEmptyChunks = options.maxEmptyChunks ?? Infinity;
  const reader = body.getReader();
  let interrupt: ((reason: unknown) => void) | undefined;
  // Ends the pending read; the `finally` below then cancels the body, as for any unfinished read.
  const onAbort = (): void => interrupt?.(signal!.reason);
  signal?.addEventListener('abort', onAbort, { once: true });
  let complete = false;
  try {
    if (signal?.aborted) throw signal.reason;
    let buffer = new Uint8Array(0);
    let bytes = 0;
    let emptyChunks = 0;
    for (;;) {
      const chunk = await new Promise<ChunkRead>((resolve, reject) => {
        interrupt = reject;
        reader.read().then(resolve, reject);
      });
      if (chunk.done) break;
      const size = chunk.value.byteLength;
      if (size === 0) {
        if (++emptyChunks > maxEmptyChunks) throw (options.tooManyEmptyChunks ?? options.tooLarge)();
        continue;
      }
      bytes += size;
      if (bytes > maxBytes) throw options.tooLarge();
      if (bytes > buffer.length) {
        const grown = new Uint8Array(Math.min(maxBytes, Math.max(bytes, buffer.length * 2)));
        grown.set(buffer);
        buffer = grown;
      }
      buffer.set(chunk.value, bytes - size);
    }
    complete = true;
    return buffer.subarray(0, bytes);
  } finally {
    interrupt = undefined;
    signal?.removeEventListener('abort', onAbort);
    if (!complete) cancelQuietly(() => reader.cancel());
    reader.releaseLock();
  }
}

/**
 * GET `url` through `fetcher` under `policy` and return the body as text. `init` may be promised,
 * as when it carries headers an application resolves, and the deadline holds it too: a promise that
 * never settles ends the read at the deadline, before any request. A response that arrives after the
 * deadline, from a provider that ignores the abort signal, has its body cancelled too.
 */
export async function fetchBoundedText(
  fetcher: Pick<FetchProvider, 'fetch'>,
  url: string,
  init: RequestInit | Promise<RequestInit>,
  policy: BoundedReadPolicy,
): Promise<string> {
  const { label } = policy;
  const deadline = new Error(`${label} deadline exceeded`);
  const controller = new AbortController();
  let timedOut = false;
  let finished = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(deadline);
  }, policy.timeoutMs);
  try {
    const request = await untilAborted(Promise.resolve(init), controller.signal);
    const fetching = fetcher.fetch(url, { ...request, signal: controller.signal });
    void fetching.then(late => {
      if (finished && late?.body) cancelQuietly(() => late.body!.cancel());
    }, () => {});
    const response = await untilAborted(fetching, controller.signal);
    if (!response.ok) {
      cancelQuietly(() => response.body?.cancel());
      throw new Error(`${label} failed: HTTP ${response.status} for ${describeValue(originAndPath(url))}`);
    }
    if (!response.body) throw new Error(`${label} has no response body`);
    const bytes = await readCappedBody(response.body, {
      maxBytes: policy.maxBytes,
      signal: controller.signal,
      tooLarge: () => new Error(`${label} byte limit exceeded`),
      maxEmptyChunks: MAX_EMPTY_CHUNKS,
      tooManyEmptyChunks: () => new Error(`${label} empty-chunk limit exceeded`),
    });
    return decodeUtf8(bytes, label);
  } catch (error) {
    // Whatever the runtime rejected with once the timer fired, the read ended at the deadline.
    throw timedOut ? deadline : error;
  } finally {
    finished = true;
    clearTimeout(timer);
    controller.abort();
  }
}

/** GET `url` under `policy`, check the JSON text's shape, and only then parse it. */
export async function fetchBoundedJson(
  fetcher: Pick<FetchProvider, 'fetch'>,
  url: string,
  init: RequestInit | Promise<RequestInit>,
  policy: BoundedJsonPolicy,
): Promise<unknown> {
  const text = await fetchBoundedText(fetcher, url, init, policy);
  checkJsonTokens(text, policy.json);
  return JSON.parse(text) as unknown;
}

/**
 * `url` without its query, its fragment and any credentials before its host, as written otherwise.
 * The authority ends at the first `/` or `\`, as the URL parser ends it for http and https, and
 * its credentials at its last `@`.
 */
function originAndPath(url: string): string {
  const end = url.search(/[?#]/);
  return (end === -1 ? url : url.slice(0, end)).replace(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/\\]*@/, '$1');
}

/** `bytes` as UTF-8 text, refusing any byte sequence that is not UTF-8. */
function decodeUtf8(bytes: Uint8Array, label: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} response is not valid UTF-8`);
  }
}

/** `work`, or the signal's reason once it aborts, through one listener removed when `work` settles. */
function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason as Error);
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason as Error);
    signal.addEventListener('abort', onAbort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

/**
 * Cancel a body whose read has already ended, synchronously so it happens before the reader's lock
 * is released. Its read is over, so a cancel that throws or rejects has nothing left to report to.
 */
export function cancelQuietly(cancel: () => Promise<unknown> | undefined): void {
  try {
    void Promise.resolve(cancel()).catch(() => undefined);
  } catch {
    // A custom reader's cancel threw synchronously: nothing is left to cancel or report.
  }
}
