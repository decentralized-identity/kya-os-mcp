/**
 * The one bounded read of a response from a URL a counterparty named (SPEC §4.4.2): the body is
 * counted as it streams, after content decoding and never from Content-Length; one deadline covers
 * the request's options when they are promised, the response headers and the body together, and
 * always surfaces as that deadline's own reason; a non-2xx response is refused whatever its body says, quoting its
 * URL's origin and path as a refusal quotes any value its sender chose (`describeValue`), since an
 * operator may keep a key in its credentials, query or fragment; and the bytes must be valid UTF-8.
 * Each refusal in the read's own words is a {@link ReadFailureError}: the deadline is
 * `deadline_exceeded`, and every other is `unavailable`.
 *
 * A WHATWG `ReadableStream` body is read as it streams, never through `response.json()` or
 * `response.text()`, which allocate the whole body before a caller can check its size. A response
 * with no such body, as SafeFetch answers and as 1.22.0 read every response, is read through its
 * `text()`, or else its `json()`, under the same deadline, and held to the same byte cap, counted in
 * UTF-8, once it has answered ({@link readWithoutStream}).
 */

import { describeValue } from './describe-value.js';
import type { FetchPort } from './fetch-port.js';
import { checkJsonTokens, type JsonLimits } from './json-preflight.js';
import { ReadFailureError } from './read-failure.js';

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
  fetcher: FetchPort,
  url: string,
  init: RequestInit | Promise<RequestInit>,
  policy: BoundedReadPolicy,
): Promise<string> {
  const { label } = policy;
  const deadline = new ReadFailureError('deadline_exceeded', `${label} deadline exceeded`);
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
      throw new ReadFailureError('unavailable', `${label} failed: HTTP ${response.status} for ${describeValue(originAndPath(url))}`);
    }
    if (!isReadableStream(response.body)) return await readWithoutStream(response, policy, controller.signal);
    const bytes = await readCappedBody(response.body, {
      maxBytes: policy.maxBytes,
      signal: controller.signal,
      tooLarge: () => new ReadFailureError('unavailable', `${label} byte limit exceeded`),
      maxEmptyChunks: MAX_EMPTY_CHUNKS,
      tooManyEmptyChunks: () => new ReadFailureError('unavailable', `${label} empty-chunk limit exceeded`),
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

/** Whether `body` is a WHATWG `ReadableStream`, which the read can count as it streams. */
function isReadableStream(body: unknown): body is ReadableStream<Uint8Array> {
  return typeof body === 'object' && body !== null && typeof (body as { getReader?: unknown }).getReader === 'function';
}

/**
 * Read a response that has no WHATWG `ReadableStream` body, as 1.22.0 read every response: through
 * its `text()` when it has one, so the text measured and parsed is exactly what was sent, or else
 * through its `json()`, whose value is measured, and later parsed, as the JSON text `JSON.stringify`
 * writes for it, so it meets the JSON shape limits as any text does. The answer is awaited under
 * `signal`, the read's one deadline, and then held to the byte cap, counted as the UTF-8 bytes of the
 * text. Either method allocates the whole body before it answers, so only the provider bounds that.
 */
async function readWithoutStream(response: Response, policy: BoundedReadPolicy, signal: AbortSignal): Promise<string> {
  const { label } = policy;
  const { text, json } = response as { text?: unknown; json?: unknown };
  let read: string;
  if (typeof text === 'function') {
    const answer: unknown = await untilAborted(Promise.resolve((text as () => unknown).call(response)), signal);
    if (typeof answer !== 'string') throw new ReadFailureError('unavailable', `${label} response text() did not answer a string`);
    read = answer;
  } else if (typeof json === 'function') {
    read = jsonText(await untilAborted(Promise.resolve((json as () => unknown).call(response)), signal), label);
  } else {
    throw new ReadFailureError(
      'unavailable',
      `${label} response has no body to read: a FetchProvider must return a Response whose body is a ReadableStream, ` +
        'or a response with a text() or json() method',
    );
  }
  if (exceedsUtf8Bytes(read, policy.maxBytes)) throw new ReadFailureError('unavailable', `${label} byte limit exceeded`);
  return read;
}

/** The JSON text of a value `json()` answered, refusing one that has none, such as `undefined` or a bigint. */
function jsonText(value: unknown, label: string): string {
  let text: unknown;
  try {
    text = JSON.stringify(value);
  } catch {
    text = undefined;
  }
  if (typeof text !== 'string') throw new ReadFailureError('unavailable', `${label} response json() answered a value with no JSON text`);
  return text;
}

/**
 * Whether `text` takes more than `maxBytes` bytes as UTF-8, counted without encoding it and only as
 * far as the limit. A code unit takes one to three bytes and a surrogate pair four, and a lone
 * surrogate is counted as the three bytes of the U+FFFD an encoder writes for it.
 */
function exceedsUtf8Bytes(text: string, maxBytes: number): boolean {
  if (text.length > maxBytes) return true;
  if (text.length * 3 <= maxBytes) return false;
  let bytes = 0;
  for (let i = 0; i < text.length && bytes <= maxBytes; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && isLowSurrogate(text.charCodeAt(i + 1))) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes > maxBytes;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

/**
 * GET `url` under `policy`, check the JSON text's shape, and only then parse it, refusing text that is
 * not JSON in the read's own words.
 */
export async function fetchBoundedJson(
  fetcher: FetchPort,
  url: string,
  init: RequestInit | Promise<RequestInit>,
  policy: BoundedJsonPolicy,
): Promise<unknown> {
  const text = await fetchBoundedText(fetcher, url, init, policy);
  try {
    checkJsonTokens(text, policy.json);
  } catch (error) {
    // The shape check throws only errors of its own, which name the limit and quote nothing.
    throw new ReadFailureError('unavailable', (error as Error).message);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // The engine's own message quotes the text, which the server chose.
    throw new ReadFailureError('unavailable', `${policy.label} response is not JSON`);
  }
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
    throw new ReadFailureError('unavailable', `${label} response is not valid UTF-8`);
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
