/**
 * SSRF-hardened fetch — the Node I/O adapters (the `SafeFetchTransport` + `DnsLookup` defaults).
 *
 * Two transports ship. The DEFAULT `nodeHttpsTransport` PINS the connection to the pre-validated
 * IP (closing the DNS-rebinding TOCTOU window) via a custom `node:https` `lookup`. That pinned path
 * misbehaves in some serverless runtimes — it failed 100% of fetches in the Vercel Node serverless
 * runtime on 2026-07-02, a failure the mocked-transport unit suite cannot catch. For those runtimes,
 * select `fetchTransport`: it connects by HOSTNAME through global `fetch` (the SSRF screen has
 * already run in the policy layer via `resolveAndPin`). All addressing policy lives in
 * `./ip-classifier`; the seam vocabulary lives in `./safe-fetch-types`. No crypto here.
 */

import type { IncomingMessage } from 'node:http';
import type { LookupFunction } from 'node:net';
import type { DnsLookup, RawResponse, SafeFetchTransport } from './safe-fetch-types.js';

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

/** Default DNS seam — resolve every address (`all: true`) for full SSRF screening. */
export const defaultLookup: DnsLookup = async (hostname) => {
  const nodeDnsLookup = await loadNodeDnsLookup();
  const resolved = await nodeDnsLookup(hostname, { all: true, verbatim: true });
  return resolved.map((entry) => ({ address: entry.address, family: entry.family }));
};

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
  const response = await fetch(url, { method: 'GET', redirect: 'manual', signal: init.signal });
  return readCapped(response, init.maxBytes);
};

/** Stream a fetch Response body into a RawResponse, enforcing the byte cap mid-stream. */
async function readCapped(response: Response, maxBytes: number): Promise<RawResponse> {
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error(`safe-fetch: response body exceeds size cap ${maxBytes}`);
      }
      chunks.push(value);
    }
  }
  const body = Buffer.concat(chunks).toString('utf8');
  return {
    status: response.status,
    headers: { get: (name) => response.headers.get(name) },
    text: () => Promise.resolve(body),
  };
}

/**
 * Build the custom `node:https` lookup that pins the connection to the pre-validated IP for BOTH
 * call-shapes (closing the DNS-rebinding TOCTOU window). Node ≥20 defaults to
 * `autoSelectFamily=true`, which invokes a custom lookup with `{ all: true }` and expects an ARRAY
 * of `{ address, family }`; a scalar 3-arg callback yields "Invalid IP address: undefined" and
 * breaks every real request. Honour the array form when `all` is asked, the scalar form otherwise.
 * Exported for direct unit testing (the request wiring around it is integration-only — no TLS in
 * the unit suite). Not re-exported from the package barrels; the public surface is unchanged.
 */
export function buildPinnedLookup(pinnedAddress: string, family: 4 | 6): LookupFunction {
  return (_hostname, options, cb) => {
    if (typeof options === 'object' && options?.all) {
      (cb as unknown as (e: null, a: Array<{ address: string; family: number }>) => void)(null, [
        { address: pinnedAddress, family },
      ]);
    } else {
      cb(null, pinnedAddress, family);
    }
  };
}

/** Default transport — node:https pinned to the validated IP, TLS SNI preserved, body-capped. */
export const nodeHttpsTransport: SafeFetchTransport = async (url, init) => {
  const https = await loadNodeHttps();
  if (!https) {
    throw new Error('safe-fetch: node:https is unavailable in this runtime; pass transport: fetchTransport');
  }
  const httpsRequest = https.request;
  return new Promise<RawResponse>((resolve, reject) => {
    const family = init.family === 6 ? 6 : 4;
    const pinnedLookup = buildPinnedLookup(init.pinnedAddress, family);
    const req = httpsRequest(
      url,
      { method: 'GET', servername: init.hostname, signal: init.signal, lookup: pinnedLookup },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > init.maxBytes) {
            req.destroy();
            reject(new Error(`safe-fetch: response body exceeds size cap ${init.maxBytes}`));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => resolve(toRawResponse(res, chunks)));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end();
  });
};

/** Project a node:http IncomingMessage + buffered chunks into the RawResponse shape. */
function toRawResponse(res: IncomingMessage, chunks: Buffer[]): RawResponse {
  return {
    status: res.statusCode ?? 0,
    headers: {
      get: (name) => {
        const value = res.headers[name.toLowerCase()];
        return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
      },
    },
    text: () => Promise.resolve(Buffer.concat(chunks).toString('utf8')),
  };
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
