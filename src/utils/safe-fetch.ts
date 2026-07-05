/**
 * SSRF-hardened outbound fetch (safe-fetch) — the policy orchestrator.
 *
 * `resolveCard` — and, later, JWKS + status-list resolution — follows URLs an attacker can
 * influence across four discovery surfaces, so every outbound request goes through this
 * guard. `createSafeFetch` returns a fetcher structurally compatible with the card's
 * `FetchLike` ({ ok, status, json }) that enforces, fail-closed:
 *
 *   - https-only (no http:, file:, data:, …);
 *   - the connection IP is a PUBLIC UNICAST address (RFC1918, loopback, link-local incl. the
 *     169.254.169.254 cloud-metadata endpoint, IPv6 ULA/link-local, NAT64/6to4/Teredo transition
 *     ranges are denied — see `./ip-classifier`). Each HOP is resolved ONCE and its connection is
 *     PINNED to that validated address, closing the DNS-rebinding (TOCTOU) window within the hop; a
 *     same-origin redirect to a different host triggers a fresh resolve-and-pin cycle for that hop;
 *   - cross-origin redirects are blocked (manual handling; a 3xx to a different origin is
 *     rejected, same-origin redirects are followed up to a small cap);
 *   - a response size cap and an AbortSignal-backed timeout bound resource use.
 *
 * The two Node transports live in `./safe-fetch-transports`; the seam vocabulary in
 * `./safe-fetch-types`; the address policy in `./ip-classifier`. This module owns only the
 * hop-by-hop POLICY (scheme, resolve-and-pin, redirect, size cap, timeout, first-party escape
 * hatch) and re-exports the transports + classifier + types so the public surface is one import.
 *
 * First-party escape hatch: `allowOrigins` / `firstPartyOrigin` list origins a caller owns. A
 * request whose origin equals a configured one is fetched plain (origin-equality is not
 * attacker-routable); every other origin still takes the guarded path, fail-closed.
 *
 * All I/O is injected via pluggable seams (`lookup`, `transport`) so the policy is unit tested
 * with mocked DNS + transport. No crypto here — no mcp-i-core dependency leaks in.
 */

import { isBlockedAddress } from './ip-classifier.js';
import {
  defaultLookup,
  fetchTransport,
  selectDefaultTransport,
} from './safe-fetch-transports.js';
import type {
  DnsAddress,
  DnsLookup,
  RawResponse,
  SafeFetch,
  SafeFetchOptions,
  SafeFetchResponse,
  SafeFetchTransport,
} from './safe-fetch-types.js';

// Re-export the full public surface so a consumer needs only `./safe-fetch` (barrels unchanged).
export * from './safe-fetch-types.js';
export { isBlockedAddress } from './ip-classifier.js';
export {
  defaultLookup,
  fetchTransport,
  nodeHttpsTransport,
  selectDefaultTransport,
} from './safe-fetch-transports.js';

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 1_048_576;
const DEFAULT_MAX_REDIRECTS = 3;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Parse + require https; returns the normalized href. */
function assertHttpsUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`safe-fetch: invalid URL "${raw}"`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`safe-fetch: only https is allowed (got "${url.protocol}")`);
  }
  return url.href;
}

/** Resolve the host ONCE, reject if ANY resolved address is non-public, and pin the first. */
async function resolveAndPin(hostname: string, lookup: DnsLookup): Promise<DnsAddress> {
  const addresses = await lookup(hostname);
  const [first] = addresses;
  if (!first) {
    throw new Error(`safe-fetch: DNS lookup for "${hostname}" returned no addresses`);
  }
  for (const candidate of addresses) {
    if (isBlockedAddress(candidate.address)) {
      throw new Error(`safe-fetch: refusing non-public address ${candidate.address} for host "${hostname}"`);
    }
  }
  return first;
}

/** Resolve a 3xx into the next URL, rejecting cross-origin / non-https / missing-Location. */
function nextRedirectUrl(currentUrl: string, raw: RawResponse): string {
  const location = raw.headers.get('location');
  if (!location) {
    throw new Error(`safe-fetch: ${raw.status} redirect without a Location header`);
  }
  let target: URL;
  try {
    target = new URL(location, currentUrl);
  } catch {
    // Keep the module's fail-closed convention: a malformed Location surfaces a `safe-fetch:`-
    // prefixed error rather than a raw TypeError leaking out of the URL constructor.
    throw new Error(`safe-fetch: redirect location is not a valid URL "${location}"`);
  }
  if (target.protocol !== 'https:') {
    throw new Error(`safe-fetch: redirect to non-https target "${target.protocol}" blocked`);
  }
  const origin = new URL(currentUrl).origin;
  if (target.origin !== origin) {
    throw new Error(`safe-fetch: cross-origin redirect blocked (${origin} → ${target.origin})`);
  }
  return target.href;
}

/** Enforce the size cap and project a RawResponse into the FetchLike-compatible shape. */
async function finalize(raw: RawResponse, maxBytes: number): Promise<SafeFetchResponse> {
  const declared = Number(raw.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new Error(`safe-fetch: declared content-length ${declared} exceeds cap ${maxBytes}`);
  }
  const body = await raw.text();
  if (Buffer.byteLength(body, 'utf8') > maxBytes) {
    throw new Error(`safe-fetch: response body exceeds size cap ${maxBytes}`);
  }
  return {
    ok: raw.status >= 200 && raw.status < 300,
    status: raw.status,
    json: () => Promise.resolve(JSON.parse(body) as unknown),
  };
}

/**
 * Build an SSRF-hardened fetcher. The returned function is structurally compatible with the
 * card's `FetchLike`: `(url) => Promise<{ ok, status, json }>`.
 */
export function createSafeFetch(options: SafeFetchOptions = {}): SafeFetch {
  const cfg: HopConfig = {
    lookup: options.lookup ?? defaultLookup,
    transport: options.transport ?? selectDefaultTransport(),
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxBytes: options.maxBytes ?? DEFAULT_MAX_BYTES,
    trustedOrigins: normalizeTrustedOrigins(options),
  };
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  return async function safeFetch(initialUrl: string): Promise<SafeFetchResponse> {
    let url = assertHttpsUrl(initialUrl);
    for (let hop = 0; ; hop++) {
      const raw = await requestOnce(url, cfg);
      if (!REDIRECT_STATUSES.has(raw.status)) {
        return finalize(raw, cfg.maxBytes);
      }
      if (hop >= maxRedirects) {
        throw new Error(`safe-fetch: too many redirects (> ${maxRedirects})`);
      }
      url = nextRedirectUrl(url, raw);
    }
  };
}

/** Resolved per-request policy shared across hops. */
interface HopConfig {
  lookup: DnsLookup;
  transport: SafeFetchTransport;
  timeoutMs: number;
  maxBytes: number;
  trustedOrigins: ReadonlySet<string>;
}

/**
 * Perform ONE hop. First-party origins skip the resolve-and-pin SSRF screen (origin-equality is
 * not attacker-routable) and are fetched plain by name; every other origin is resolved, screened,
 * and pinned before the configured transport runs. Both branches are timeout-bounded.
 */
async function requestOnce(url: string, cfg: HopConfig): Promise<RawResponse> {
  const { hostname, origin } = new URL(url);
  if (cfg.trustedOrigins.has(origin)) {
    return withTimeout(hostname, cfg.timeoutMs, (signal) =>
      fetchTransport(url, { signal, hostname, pinnedAddress: '', family: 4, maxBytes: cfg.maxBytes }),
    );
  }
  const pinned = await resolveAndPin(hostname, cfg.lookup);
  return withTimeout(hostname, cfg.timeoutMs, (signal) =>
    cfg.transport(url, {
      signal,
      hostname,
      pinnedAddress: pinned.address,
      family: pinned.family,
      maxBytes: cfg.maxBytes,
    }),
  );
}

/** Run a transport call under an AbortSignal that fires after `timeoutMs`. */
async function withTimeout(
  hostname: string,
  timeoutMs: number,
  run: (signal: AbortSignal) => Promise<RawResponse>,
): Promise<RawResponse> {
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error(`safe-fetch: request to ${hostname} timed out after ${timeoutMs}ms`)),
    timeoutMs,
  );
  try {
    return await run(controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Build the set of first-party origins that bypass the SSRF screen. Each `allowOrigins` /
 * `firstPartyOrigin` entry MUST parse as an https origin — fail-closed (throw) otherwise.
 */
function normalizeTrustedOrigins(options: SafeFetchOptions): ReadonlySet<string> {
  const raw = [...(options.allowOrigins ?? []), ...(options.firstPartyOrigin ? [options.firstPartyOrigin] : [])];
  const origins = new Set<string>();
  for (const entry of raw) {
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw new Error(`safe-fetch: invalid first-party origin "${entry}"`);
    }
    if (url.protocol !== 'https:') {
      throw new Error(`safe-fetch: first-party origin must be https (got "${entry}")`);
    }
    origins.add(url.origin);
  }
  return origins;
}
