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
 *   - a response size cap, and one deadline over the whole read (its DNS lookups, every redirect hop
 *     and its body), bound resource use; a caller's AbortSignal ends the read too.
 *
 * The two Node transports live in `./safe-fetch-transports`; the seam vocabulary in
 * `./safe-fetch-types`; the address policy in `./ip-classifier`. This module owns only the
 * hop-by-hop POLICY (scheme, resolve-and-pin, redirect, size cap, timeout, first-party escape
 * hatch) and re-exports the transports + classifier + types so the public surface is one import.
 *
 * First-party escape hatch: `allowOrigins` / `firstPartyOrigin` list origins a caller owns. A
 * request whose origin equals a configured one is fetched plain (origin-equality is not
 * attacker-routable); every other origin still takes the guarded path, fail-closed.
 * `development: true` admits private and local addresses on that path, for a local demo only.
 *
 * All I/O is injected via pluggable seams (`lookup`, `transport`) so the policy is unit tested
 * with mocked DNS + transport. No crypto here — no mcp-i-core dependency leaks in.
 */

import { logger } from '../logging/index.js';
import { developmentMode } from './development-mode.js';
import { isNonPublicByForm } from './host-form.js';
import { isBlockedAddress } from './ip-classifier.js';
import { ReadFailureError } from './read-failure.js';
import { followRedirects, MAX_REDIRECTS, type RedirectRefusals, type RedirectTarget } from './redirect-follower.js';
import {
  defaultLookup,
  fetchTransport,
  selectDefaultTransport,
} from './safe-fetch-transports.js';
import { OUTBOUND_READ_MAX_BYTES, OUTBOUND_READ_TIMEOUT_MS } from './outbound-read-limits.js';
import type {
  DnsAddress,
  DnsLookup,
  RawResponse,
  SafeFetch,
  SafeFetchInit,
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

/*
 * SafeFetch's defaults for the `timeoutMs` and `maxBytes` options, the package's limits for one
 * outbound read (`./outbound-read-limits.ts`). Here a caller may override them.
 */
/** Milliseconds one read may take: its DNS lookups, every redirect hop and its body. */
const DEFAULT_TIMEOUT_MS = OUTBOUND_READ_TIMEOUT_MS;
/** Bytes of response body read before the response is refused. */
const DEFAULT_MAX_RESPONSE_BYTES = OUTBOUND_READ_MAX_BYTES;

/** Parse + require https; returns the normalized href. */
function assertHttpsUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`safe-fetch: invalid URL "${raw}"`);
  }
  if (url.protocol !== 'https:') {
    throw new ReadFailureError('host_refused', `safe-fetch: only https is allowed (got "${url.protocol}")`, { beforeRequest: true });
  }
  return url.href;
}

/** The production opt-in SafeFetch's refusals and its production guard name beside `development: true`. */
const OWNED_ORIGINS = "list each origin you own in SafeFetch's allowOrigins";

/** The two settings that admit a host SafeFetch refuses as private or local. */
const PRIVATE_HOST_SETTINGS = `in local development, set development: true; to read a host you own in production, ${OWNED_ORIGINS}`;

/**
 * Resolve the host ONCE, reject if ANY resolved address is non-public, unless `admitPrivate`, and
 * pin the first. A host that is non-public whatever any resolver answers (a non-public IP literal,
 * or `localhost` or a name under it, `./host-form`) is refused by the URL alone, before any lookup,
 * and the refusal says so. The refusal of a name that resolves to a non-public address names the
 * host and what admits it, never the address, since whoever named the host may not know what it
 * resolves to; the address goes to the log.
 */
async function resolveAndPin(hostname: string, lookup: DnsLookup, admitPrivate: boolean): Promise<DnsAddress> {
  if (!admitPrivate && isNonPublicByForm(hostname)) {
    throw new ReadFailureError('host_refused', `safe-fetch: refusing host "${hostname}", a private or local host: ${PRIVATE_HOST_SETTINGS}`, {
      beforeRequest: true,
    });
  }
  const addresses = await lookup(hostname);
  const [first] = addresses;
  if (!first) {
    throw new Error(`safe-fetch: DNS lookup for "${hostname}" returned no addresses`);
  }
  for (const candidate of admitPrivate ? [] : addresses) {
    if (isBlockedAddress(candidate.address)) {
      logger.warn(`[kya-os] safe-fetch: host "${hostname}" resolves to the non-public address ${candidate.address}, so it is refused`);
      throw new ReadFailureError(
        'host_refused',
        `safe-fetch: refusing host "${hostname}", which resolves to a non-public address: ${PRIVATE_HOST_SETTINGS}`,
      );
    }
  }
  return first;
}

const nonHttpsTarget = (target: URL): Error =>
  new ReadFailureError('host_refused', `safe-fetch: redirect to non-https target "${target.protocol}" blocked`);

const REDIRECT_REFUSALS: RedirectRefusals = {
  limitExceeded: (maxRedirects) => new Error(`safe-fetch: too many redirects (> ${maxRedirects})`),
  missingLocation: (status) => new Error(`safe-fetch: ${status} redirect without a Location header`),
  // Keep the module's fail-closed convention: a malformed Location surfaces a `safe-fetch:`-
  // prefixed error rather than a raw TypeError leaking out of the URL constructor.
  invalidLocation: (location) => new Error(`safe-fetch: redirect location is not a valid URL "${location}"`),
  httpsToHttp: nonHttpsTarget,
};

/**
 * Refuse a redirect target the shared rule admits: any scheme but https, and any other origin. A
 * refusal names the origin redirected from, never the one the server chose to redirect to, which
 * goes to the log.
 */
function vetRedirectTarget({ target, from, crossOrigin }: RedirectTarget): void {
  if (target.protocol !== 'https:') throw nonHttpsTarget(target);
  if (crossOrigin) {
    logger.warn(`[kya-os] safe-fetch: redirect from ${from.origin} to ${target.origin} blocked, as cross-origin`);
    throw new ReadFailureError('host_refused', `safe-fetch: cross-origin redirect from ${from.origin} blocked`);
  }
}

/**
 * Enforce the size cap, refusing a larger body as `too_large`, and project a RawResponse into the
 * FetchLike-compatible shape. The body is read within the read's deadline.
 */
async function finalize(raw: RawResponse, maxBytes: number, deadline: ReadDeadline): Promise<SafeFetchResponse> {
  const declared = Number(raw.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ReadFailureError('too_large', `safe-fetch: declared content-length ${declared} exceeds cap ${maxBytes}`);
  }
  const body = await deadline.within(() => raw.text());
  if (Buffer.byteLength(body, 'utf8') > maxBytes) {
    throw new ReadFailureError('too_large', `safe-fetch: response body exceeds size cap ${maxBytes}`);
  }
  return {
    ok: raw.status >= 200 && raw.status < 300,
    status: raw.status,
    json: () => Promise.resolve(JSON.parse(body) as unknown),
    text: () => Promise.resolve(body),
  };
}

/**
 * Build an SSRF-hardened fetcher. The returned function is structurally compatible with the
 * card's `FetchLike`: `(url) => Promise<{ ok, status, json }>`. A URL or redirect its own rules
 * refuse (a scheme other than https, a non-public address, a cross-origin redirect) rejects with
 * an error that carries the `host_refused` read-failure kind, and a hop that runs out of time with
 * one of `deadline_exceeded`, so a verifier codes the refusal without reading its message. A
 * refusal decided from the URL alone, before any DNS lookup or request (its scheme, a non-public IP
 * literal, a localhost name), also says so, so a verifier may tell whoever named the URL why.
 *
 * One deadline, `timeoutMs` from the call, covers the whole read: the DNS lookup of each hop, every
 * redirect hop and the body. A `signal` the caller passes ends the read when it aborts, at whatever
 * step it has reached, with the signal's reason, as `fetch` does.
 */
export function createSafeFetch(options: SafeFetchOptions = {}): SafeFetch {
  const cfg: HopConfig = {
    lookup: options.lookup ?? defaultLookup,
    transport: options.transport ?? selectDefaultTransport(),
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxBytes: options.maxBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    trustedOrigins: normalizeTrustedOrigins(options),
    admitPrivate: developmentMode(options.development, 'SafeFetchOptions.development', OWNED_ORIGINS),
  };
  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;

  return async function safeFetch(initialUrl: string, init?: SafeFetchInit): Promise<SafeFetchResponse> {
    const url = assertHttpsUrl(initialUrl);
    const deadline = startReadDeadline(new URL(url).hostname, cfg.timeoutMs, init?.signal ?? undefined);
    try {
      const raw = await followRedirects<RawResponse>(url, {
        request: (hop) => requestOnce(hop.url, cfg, deadline),
        vetTarget: vetRedirectTarget,
        maxRedirects,
        // A Location with no value names no target, so it is refused as a missing header is.
        emptyLocationIsMissing: true,
        refusals: REDIRECT_REFUSALS,
      });
      return await finalize(raw, cfg.maxBytes, deadline);
    } finally {
      deadline.clear();
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
  /** Whether `development: true` admits private and local addresses. */
  admitPrivate: boolean;
}

/**
 * Perform ONE hop. First-party origins skip the resolve-and-pin SSRF screen (origin-equality is
 * not attacker-routable) and are fetched plain by name; every other origin is resolved, screened,
 * and pinned before the configured transport runs. Every step is bounded by the read's deadline.
 */
async function requestOnce(url: string, cfg: HopConfig, deadline: ReadDeadline): Promise<RawResponse> {
  const { hostname, origin } = new URL(url);
  const { signal } = deadline;
  if (cfg.trustedOrigins.has(origin)) {
    return deadline.within(() => fetchTransport(url, { signal, hostname, pinnedAddress: '', family: 4, maxBytes: cfg.maxBytes }));
  }
  const pinned = await deadline.within(() => resolveAndPin(hostname, cfg.lookup, cfg.admitPrivate));
  return deadline.within(() =>
    cfg.transport(url, { signal, hostname, pinnedAddress: pinned.address, family: pinned.family, maxBytes: cfg.maxBytes }),
  );
}

/**
 * The one deadline of a read. Its `signal` aborts once `timeoutMs` has passed, with a
 * `deadline_exceeded` read failure, or once the caller's `outside` signal aborts, with that signal's
 * reason; each transport call is given it. `within` runs a step unless the signal has aborted, and
 * stops waiting on it once it does, so a lookup or a body reader that ignores the signal still
 * cannot hold the read open.
 */
interface ReadDeadline {
  readonly signal: AbortSignal;
  within<T>(step: () => Promise<T>): Promise<T>;
  clear(): void;
}

function startReadDeadline(hostname: string, timeoutMs: number, outside: AbortSignal | undefined): ReadDeadline {
  const controller = new AbortController();
  const { signal } = controller;
  const timer = setTimeout(
    () => controller.abort(new ReadFailureError('deadline_exceeded', `safe-fetch: request to ${hostname} timed out after ${timeoutMs}ms`)),
    timeoutMs,
  );
  const forward = (): void => controller.abort(outside?.reason);
  if (outside?.aborted) forward();
  else outside?.addEventListener('abort', forward, { once: true });
  const aborted = new Promise<never>((_resolve, reject) => {
    if (signal.aborted) reject(signal.reason);
    else signal.addEventListener('abort', () => reject(signal.reason), { once: true });
  });
  // A step that is not waiting when the read ends leaves no rejection unhandled.
  aborted.catch(() => undefined);
  return {
    signal,
    within: (step) => (signal.aborted ? aborted : Promise.race([step(), aborted])),
    clear: () => {
      clearTimeout(timer);
      outside?.removeEventListener('abort', forward);
    },
  };
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
