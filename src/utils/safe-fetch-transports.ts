/**
 * SSRF-hardened fetch — the Node I/O adapters (the `SafeFetchTransport` + `DnsLookup` defaults).
 *
 * Two transports ship. The DEFAULT `nodeHttpsTransport` PINS the connection to the pre-validated
 * IP (closing the DNS-rebinding TOCTOU window) via a custom `node:https` `lookup`, over a connection
 * of its own that no other request shares (`pinnedRequester`). That pinned path
 * misbehaves in some serverless runtimes — it failed 100% of fetches in the Vercel Node serverless
 * runtime on 2026-07-02, a failure the mocked-transport unit suite cannot catch. For those runtimes,
 * select `fetchTransport`: it connects by HOSTNAME through global `fetch` (the SSRF screen has
 * already run in the policy layer via `resolveAndPin`). The pinned transport asks and reads as that
 * `fetch` does: it sends its `Accept` and `User-Agent`, asks for gzip, and decodes a gzip body through
 * the package's capped decompressor, so the cap holds the decoded body. All addressing policy lives in
 * `./ip-classifier`; the seam vocabulary lives in `./safe-fetch-types`. No crypto here.
 */

import type { Agent, ClientRequest, IncomingMessage } from 'node:http';
import type { RequestOptions } from 'node:https';
import type { LookupFunction, TcpNetConnectOpts } from 'node:net';
import type { DnsAddress, DnsLookup, RawResponse, SafeFetchTransport, TransportInit } from './safe-fetch-types.js';
import { logger } from '../logging/index.js';
import { readCappedBody } from './bounded-read.js';
import { describeValue } from './describe-value.js';
import { ReadFailureError } from './read-failure.js';
import { statusListGzipCodec } from './statuslist-gzip.js';

/** The refusal of a body larger than `maxBytes`, as SafeFetch refuses a declared length over its cap: a read that came back too large. */
const overCap = (maxBytes: number): ReadFailureError =>
  new ReadFailureError('too_large', `safe-fetch: response body exceeds size cap ${maxBytes}`);

/*
 * Node built-ins are loaded LAZILY (never at the module top level), so this
 * module — and everything that builds a `SafeFetch`, incl. the Entity Card /
 * VC-JWT verification path — bundles cleanly for workerd / browser, where
 * `node:dns` and `node:https` don't exist. A static `import 'node:dns/promises'`
 * here broke Cloudflare Worker builds at bundle time (@kya-os/mcp 1.10.0). The
 * built-ins now load only when a node code path actually runs; a Worker that
 * injects its own `lookup` / `transport` (or uses `fetchTransport` + trusted
 * origins) never triggers them. Type-only imports above are erased at compile
 * time, so they never reach the bundle.
 */

type NodeDnsLookup = (typeof import('node:dns/promises'))['lookup'];
let dnsLookupPromise: Promise<NodeDnsLookup> | undefined;
/**
 * Lazily load (and cache) `node:dns/promises`' `lookup`. Where `node:dns` is absent (workerd),
 * fail with a guiding error rather than a cryptic module-resolution reject: a Worker should inject
 * its own `lookup` seam (e.g. DNS-over-HTTPS) or use trusted origins + `fetchTransport`.
 */
function loadNodeDnsLookup(): Promise<NodeDnsLookup> {
  return (dnsLookupPromise ??= import('node:dns/promises').then(
    (m) => m.lookup,
    (cause) => {
      throw new Error(
        'safe-fetch: node:dns is unavailable in this runtime — inject a `lookup` seam (e.g. DNS-over-HTTPS) or use trusted origins with fetchTransport',
        { cause },
      );
    },
  ));
}

type NodeHttps = typeof import('node:https');
let nodeHttpsPromise: Promise<NodeHttps | null> | undefined;
/** Lazily load (and cache) `node:https`; resolves to `null` where it's absent (workerd). */
function loadNodeHttps(): Promise<NodeHttps | null> {
  return (nodeHttpsPromise ??= import('node:https').then(
    (m) => m,
    () => null,
  ));
}

type NodeHttp = typeof import('node:http');
let nodeHttpPromise: Promise<NodeHttp | null> | undefined;
/** Lazily load (and cache) `node:http`, for an http URL a caller named; resolves to `null` where it's absent. */
function loadNodeHttp(): Promise<NodeHttp | null> {
  return (nodeHttpPromise ??= import('node:http').then(
    (m) => m,
    () => null,
  ));
}

type NodeUrl = typeof import('node:url');
let nodeUrlPromise: Promise<NodeUrl | null> | undefined;
/** Lazily load (and cache) `node:url`, for the request options a URL makes; resolves to `null` where it's absent. */
function loadNodeUrl(): Promise<NodeUrl | null> {
  return (nodeUrlPromise ??= import('node:url').then(
    (m) => m,
    () => null,
  ));
}

/** One pinned request: the URL, its options and what to do with its response. */
type PinnedRequester = (url: string, options: PinnedRequestOptions, onResponse: (res: IncomingMessage) => void) => ClientRequest;

/**
 * How a pinned request is made: as a `node:http` `ClientRequest` through an agent of its own
 * ({@link ownAgent}), over `node:http` for an http URL, which SafeFetch hands a transport only where
 * the caller's `operatorNamed` named it, and over `node:https` for any other. Never through the
 * `request` or `get` of either module, nor its `globalAgent`, which an application, or a package
 * such as global-agent, may replace to send every request through a proxy that resolves the host
 * again, and whose pool hands a request a socket another opened, to whatever address it reached.
 */
async function pinnedRequester(http: boolean): Promise<PinnedRequester> {
  const [nodeHttp, nodeHttps, nodeUrl] = await Promise.all([loadNodeHttp(), http ? null : loadNodeHttps(), loadNodeUrl()]);
  const tls = http ? undefined : nodeHttps;
  if (!nodeHttp || !nodeUrl || tls === null) {
    throw new Error(`safe-fetch: node:${http ? 'http' : 'https'} is unavailable in this runtime; pass transport: fetchTransport`);
  }
  return (url, options, onResponse) => {
    const agent = tls === undefined ? new nodeHttp.Agent({ keepAlive: false }) : ownAgent(tls);
    return new nodeHttp.ClientRequest({ ...nodeUrl.urlToHttpOptions(new URL(url)), ...options, agent }, onResponse);
  };
}

/**
 * The TLS settings of `https.globalAgent` a pinned request keeps, as it kept them when it went
 * through that agent: those that decide which servers it trusts and how it proves itself, such as a
 * `ca` an application adds. Nothing that pools, routes or resolves, so no `lookup`, proxy or
 * keep-alive setting there reaches it.
 */
const TLS_SETTINGS = ['ca', 'cert', 'key', 'pfx', 'passphrase', 'crl', 'ciphers', 'minVersion', 'maxVersion', 'rejectUnauthorized', 'checkServerIdentity'] as const;

/**
 * An `https.Agent` for one pinned request, never pooled with another: it keeps no socket alive, so
 * the request connects to the address it was pinned to and closes after its response. It takes
 * {@link TLS_SETTINGS} from `https.globalAgent` as the application has set it now, a replaced one
 * included, and nothing else from it.
 */
function ownAgent(nodeHttps: NodeHttps): Agent {
  const live = (nodeHttps as NodeHttps & { default?: Pick<NodeHttps, 'globalAgent'> }).default ?? nodeHttps;
  let options: unknown;
  try {
    options = (live.globalAgent as { options?: unknown } | undefined)?.options;
  } catch {
    options = undefined;
  }
  const settings = typeof options === 'object' && options !== null ? (options as Record<string, unknown>) : {};
  const kept = Object.fromEntries(TLS_SETTINGS.flatMap((name) => (settings[name] === undefined ? [] : [[name, settings[name]]])));
  return new nodeHttps.Agent({ ...kept, keepAlive: false });
}

/** Default DNS seam — resolve every address (`all: true`) for full SSRF screening. */
export const defaultLookup: DnsLookup = async (hostname) => {
  const nodeDnsLookup = await loadNodeDnsLookup();
  const resolved = await nodeDnsLookup(hostname, { all: true, verbatim: true });
  return resolved.map((entry) => ({ address: entry.address, family: entry.family }));
};

let resolvesNames: boolean | undefined;
/**
 * Whether this runtime resolves host names through {@link defaultLookup}, asked of `localhost`,
 * which every resolver answers from local configuration without a query. Node does. Only a runtime
 * that has no resolver answers `false`: one where `node:dns` does not load, as in a browser, or whose
 * `lookup` says it is not implemented, as a Cloudflare Worker's does. That answer, and a lookup that
 * answers, are kept for the life of the process. Any other failure, such as a resolver that is busy
 * for a moment (`EAI_AGAIN`), answers `true` and is not kept: the read then resolves its own host,
 * and fails if that fails too, rather than going on unchecked. The question is a fixed name, never a
 * host a counterparty chose, so no host can make a runtime that resolves names look like one that
 * does not.
 */
export async function runtimeResolvesNames(): Promise<boolean> {
  if (resolvesNames !== undefined) return resolvesNames;
  let nodeDnsLookup: NodeDnsLookup;
  try {
    nodeDnsLookup = await loadNodeDnsLookup();
  } catch {
    return (resolvesNames = false);
  }
  try {
    await nodeDnsLookup('localhost', { all: true, verbatim: true });
    return (resolvesNames = true);
  } catch (error) {
    if (isNotImplemented(error)) return (resolvesNames = false);
    return true;
  }
}

/** Whether `error` says the runtime does not implement the call, as workerd's and unenv's `node:dns` do. */
function isNotImplemented(error: unknown): boolean {
  const { code, message } = (typeof error === 'object' && error !== null ? error : {}) as { code?: unknown; message?: unknown };
  if (code === 'ERR_METHOD_NOT_IMPLEMENTED' || code === 'ERR_NOT_IMPLEMENTED') return true;
  return typeof message === 'string' && /\bnot implemented\b/i.test(message);
}

/**
 * Fetch-based transport — for runtimes where the `node:https` pinned-connect path misbehaves
 * (the Vercel Node serverless runtime failed 100% of fetches on 2026-07-02). Select it explicitly
 * with `transport: fetchTransport`, or rely on the auto-select when `node:https` is unavailable.
 *
 * The SSRF screen is UNCHANGED: for non-first-party origins `resolveAndPin` has already run EVERY
 * resolved address through the `lookup` seam + `isBlockedAddress` policy before this transport is
 * called. This variant then connects by HOSTNAME via global `fetch` (`redirect: 'manual'`, so a
 * 3xx flows back to the caller's redirect loop) — it does NOT pin `init.pinnedAddress`.
 *
 * TOCTOU: `nodeHttpsTransport` PINS the validated IP, closing the DNS-rebinding window. This
 * variant validates-then-reconnects-by-name, so a hostile resolver could hand `lookup` a public
 * IP and `fetch`'s own resolution a private one — a narrow validated-then-reconnected-by-name
 * window it knowingly accepts for serverless compatibility. Prefer the pinned transport where
 * `node:https` works; the first-party escape hatch avoids the window for a caller's own origin.
 */
export const fetchTransport: SafeFetchTransport = async (url, init) => {
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    signal: init.signal,
    ...(init.headers === undefined ? {} : { headers: { ...init.headers } }),
  });
  return readCapped(response, init.maxBytes, init.signal);
};

/**
 * Read a fetch Response body into a RawResponse through the one bounded body reader, enforcing the
 * byte cap mid-stream, a larger body refused as `too_large`, and ending the read when `signal` aborts.
 */
async function readCapped(response: Response, maxBytes: number, signal: AbortSignal): Promise<RawResponse> {
  const bytes = response.body
    ? await readCappedBody(response.body, {
        maxBytes,
        signal,
        tooLarge: () => overCap(maxBytes),
      })
    : new Uint8Array(0);
  return rawResponse(response.status, { get: (name) => response.headers.get(name) }, bytes);
}

/** A RawResponse of `status` and `headers` whose body is `bytes`, answered as they are and as UTF-8 text. */
function rawResponse(status: number, headers: RawResponse['headers'], bytes: Uint8Array): RawResponse {
  const body = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('utf8');
  return {
    status,
    headers,
    text: () => Promise.resolve(body),
    bytes: () => Promise.resolve(bytes),
  };
}

/**
 * Build the custom `node:https` lookup that pins the connection to the pre-validated IPs for BOTH
 * call-shapes (closing the DNS-rebinding TOCTOU window). With `autoSelectFamily`, which the pinned
 * transport sets and Node ≥20 defaults to, Node invokes a custom lookup with `{ all: true }` and
 * expects an ARRAY of `{ address, family }`, every one of which it tries in turn until one connects;
 * a scalar 3-arg callback yields "Invalid IP address: undefined" and breaks every real request. So
 * the array form answers `pinnedAddress` and then each of `fallbacks`, every one checked, and the
 * scalar form `pinnedAddress` alone. Exported for direct unit testing; the request wiring around it
 * is tested against a stand-in for `node:https`, since the unit suite makes no TLS connection. Not
 * re-exported from the package barrels; the public surface is unchanged.
 */
export function buildPinnedLookup(pinnedAddress: string, family: 4 | 6, fallbacks: readonly DnsAddress[] = []): LookupFunction {
  return (_hostname, options, cb) => {
    if (typeof options === 'object' && options?.all) {
      (cb as unknown as (e: null, a: Array<{ address: string; family: number }>) => void)(null, [
        { address: pinnedAddress, family },
        ...fallbacks.map(({ address, family: other }) => ({ address, family: other })),
      ]);
    } else {
      cb(null, pinnedAddress, family);
    }
  };
}

/** A pinned request's options: `node:https`'s, and the socket's `autoSelectFamily`, which its types leave out but it passes on. */
type PinnedRequestOptions = RequestOptions & Pick<TcpNetConnectOpts, 'autoSelectFamily'>;

/**
 * The request headers the pinned transport sends where the reader sets none: the `Accept` and
 * `User-Agent` the runtime's `fetch` sends, so a host that served that `fetch` serves this.
 */
const FETCH_HEADERS: Readonly<Record<string, string>> = { accept: '*/*', 'user-agent': 'node' };

/** The one content coding the pinned transport decodes, and so the only one its `Accept-Encoding` names. */
const DECODED_CODING = 'gzip';

/** The names a response may give {@link DECODED_CODING} by: `x-gzip` is its alias (RFC 9110 §8.4.1.3). */
const GZIP_NAMES: ReadonlySet<string> = new Set(['gzip', 'x-gzip']);

/**
 * The headers of a request through the pinned transport: {@link FETCH_HEADERS}, then the reader's
 * own `headers`, by any case of their names, then `Accept-Encoding` naming the one coding it decodes,
 * whatever the reader asked.
 */
function requestHeaders(headers: TransportInit['headers']): Record<string, string> {
  const own = Object.entries(headers ?? {}).map(([name, value]) => [name.toLowerCase(), value] as const);
  return { ...FETCH_HEADERS, ...Object.fromEntries(own), 'accept-encoding': DECODED_CODING };
}

/**
 * Default transport: node:https pinned to the validated IP, TLS SNI preserved, body-capped, gzip
 * decoded, over a connection of its own ({@link pinnedRequester}). An http URL, which SafeFetch
 * hands it only where the caller's `operatorNamed` named it, is read over node:http, pinned the same
 * way.
 */
export const nodeHttpsTransport: SafeFetchTransport = async (url, init) => {
  const http = new URL(url).protocol === 'http:';
  const request = await pinnedRequester(http);
  return new Promise<RawResponse>((resolve, reject) => {
    const family = init.family === 6 ? 6 : 4;
    const pinnedLookup = buildPinnedLookup(init.pinnedAddress, family, init.fallbackAddresses);
    const options: PinnedRequestOptions = {
      method: 'GET',
      // The name TLS presents (SNI); a connection over http has none.
      ...(http ? {} : { servername: init.hostname }),
      signal: init.signal,
      lookup: pinnedLookup,
      // Every address the lookup answers is tried in turn, and never another.
      autoSelectFamily: true,
      headers: requestHeaders(init.headers),
    };
    const req = request(
      url,
      options,
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > init.maxBytes) {
            req.destroy();
            reject(overCap(init.maxBytes));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => decodedResponse(res, chunks, init).then(resolve, reject));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end();
  });
};

/**
 * Project a node:http IncomingMessage and its buffered chunks into the RawResponse shape, its body
 * decoded as the runtime's `fetch` decodes one. A gzip body is inflated through the package's one
 * capped decompressor, so `init.maxBytes` holds the decoded body, and its response then says no
 * `Content-Encoding` or `Content-Length`, which named the bytes sent. A redirect, whose body is not
 * read, and an empty body are handed back as sent, whatever coding they name, as `fetch` follows
 * the one and reads the other. A body in any other coding is refused, and so is one in more than
 * one, `gzip, gzip` included, which no host a reader names is known to send: the log says which
 * codings the host named.
 */
async function decodedResponse(res: IncomingMessage, chunks: Buffer[], init: TransportInit): Promise<RawResponse> {
  const headerOf = (name: string): string | null => {
    const value = res.headers[name.toLowerCase()];
    return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
  };
  const sent = new Uint8Array(Buffer.concat(chunks));
  const status = res.statusCode ?? 0;
  const coding = headerOf('content-encoding');
  const named = coding?.trim().toLowerCase() ?? '';
  const undecoded = named === '' || named === 'identity' || isRedirect(status) || sent.byteLength === 0;
  if (undecoded) return rawResponse(status, { get: headerOf }, sent);
  if (!GZIP_NAMES.has(named)) {
    logger.warn(`[kya-os] safe-fetch: ${init.hostname} answered with Content-Encoding ${describeValue(coding)}, which is not decoded, so the response is refused`);
    throw new ReadFailureError('unavailable', 'safe-fetch: the response is in a content coding that is not decoded');
  }
  const decoded = await inflated(sent, init.maxBytes);
  const asDecoded = (name: string): string | null => (/^content-(encoding|length)$/i.test(name) ? null : headerOf(name));
  return rawResponse(status, { get: asDecoded }, decoded);
}

/** Whether `status` is a redirect's, whose body the reader does not read. */
function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

/** `body`, gzip, inflated through the package's capped decompressor: refused as too large past `maxBytes`, or as unreadable when it is not gzip. */
async function inflated(body: Uint8Array, maxBytes: number): Promise<Uint8Array> {
  try {
    return await statusListGzipCodec.decompress(body, { maxBytes });
  } catch (error) {
    if ((error as { code?: unknown } | null)?.code === 'ERR_BUFFER_TOO_LARGE') throw overCap(maxBytes);
    throw new ReadFailureError('unavailable', 'safe-fetch: the response says it is gzip, and is not');
  }
}

/**
 * Pick the default transport: the `node:https` pinned transport when it is available, else the
 * fetch-based transport. The `node:https` check is deferred to request time (it lazy-loads), so a
 * runtime without `node:https` (workerd) transparently gets `fetchTransport`. This only covers
 * ABSENCE of `node:https`; a runtime where the pinned path is present-but-broken (e.g. the Vercel
 * Node serverless runtime) must still pass `transport: fetchTransport` explicitly.
 */
export function selectDefaultTransport(): SafeFetchTransport {
  return async (url, init) => {
    const https = await loadNodeHttps();
    return https ? nodeHttpsTransport(url, init) : fetchTransport(url, init);
  };
}
