/**
 * SSRF-hardened fetch — the shared seam types.
 *
 * Kept in their own module so the pure address classifier (`./ip-classifier`), the Node I/O
 * adapters (`./safe-fetch-transports`), and the policy orchestrator (`./safe-fetch`) can all
 * depend on the vocabulary without any import cycle. `./safe-fetch` re-exports every name here,
 * so the public surface (`@kya-os/mcp` barrels) is unchanged.
 */

/** A resolved address + its IP family (4 or 6). */
export interface DnsAddress {
  address: string;
  family: number;
}

/** DNS resolution seam — returns every address the host resolves to. */
export type DnsLookup = (hostname: string) => Promise<DnsAddress[]>;

/** The minimal response a transport yields; safe-fetch interprets status/headers/body. */
export interface RawResponse {
  status: number;
  headers: { get(name: string): string | null };
  text: () => Promise<string>;
  /**
   * The body as the bytes that were sent. The library's transports answer it, so a reader that
   * refuses a body that is not UTF-8, as a did:web or status-list read does, reads these rather
   * than the text, which a transport decodes as it can. Optional: a transport without it is read
   * through `text()`.
   */
  bytes?: () => Promise<Uint8Array>;
}

/** Per-request context handed to the transport (connection already validated + pinned). */
export interface TransportInit {
  signal: AbortSignal;
  hostname: string;
  pinnedAddress: string;
  family: number;
  /**
   * The other addresses the host name resolved to, each checked as `pinnedAddress` was, in the order
   * the lookup answered. A transport that pins its connection tries them in turn when it cannot
   * reach `pinnedAddress`, as `nodeHttpsTransport` does, and never an address not given here. A
   * transport that connects by name ignores them. Absent when the name resolved to one address.
   */
  fallbackAddresses?: readonly DnsAddress[];
  maxBytes: number;
  /**
   * The request headers the reader sends, such as `Accept`. SafeFetch sends none; a did:web or
   * status-list read under the private-network rule sends the ones its reader sets. The library's
   * transports send them: `fetchTransport` beside the runtime `fetch`'s own, and
   * `nodeHttpsTransport` over the `Accept` and `User-Agent` that `fetch` sends, with
   * `Accept-Encoding: gzip`, the one coding it decodes. A transport that leaves them out sends a bare
   * GET.
   */
  headers?: Readonly<Record<string, string>>;
}

/**
 * Transport seam: performs ONE request (no redirect following) to the pinned address. Its URL is
 * https, or http at a URL the caller's `operatorNamed` named as the read's first request.
 */
export type SafeFetchTransport = (url: string, init: TransportInit) => Promise<RawResponse>;

/** The fetcher safe-fetch returns — structurally compatible with the card's `FetchLike`. */
export interface SafeFetchResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  /**
   * The body as the text that was sent. `createSafeFetch` answers it, so a did:web or status-list
   * read through a `FetchProvider` whose `fetch` returns this response measures and parses that exact
   * text. Optional, so a `SafeFetch` written without it still type-checks: such a read takes `json()`.
   */
  text?: () => Promise<string>;
}

/** What a caller may pass a SafeFetch beside the URL: a `RequestInit` fits, and only its `signal` is read. */
export interface SafeFetchInit {
  /**
   * Ends the read when it aborts, at whatever step the read has reached, with the signal's reason,
   * as `fetch` does. The read's own `timeoutMs` holds as well.
   */
  signal?: AbortSignal | null;
  /**
   * Which URLs of this read the verifier's operator named, asked of each hop, the first and each
   * redirect, as `allowOrigins` is: the status lists its `statusListIssuers` binds, and the one a
   * pinned root's own credential names once that credential's proof has verified. A hop it answers
   * `true` for is read wherever its host resolves, a private or local address included, as
   * `development: true` reads one; the connection is still pinned to the address looked up, and the
   * redirect, size and deadline rules all hold. The first request may be http when it answers `true`
   * for that URL, as an operator binds a list's exact http URL; a redirect is https alone. Every
   * other hop is held to the rule. The status-list checker passes it for those lists alone, and for
   * a pinned root's own list only over https; never answer `true` for a URL whoever presented a
   * credential could have chosen.
   */
  operatorNamed?: (url: string) => boolean;
}

/**
 * The fetcher `createSafeFetch` returns. A function that takes only the URL is one too, and a
 * caller that passes no `init` reads as before.
 */
export type SafeFetch = (url: string, init?: SafeFetchInit) => Promise<SafeFetchResponse>;

export interface SafeFetchOptions {
  /** DNS seam (default: `node:dns` resolving every address). */
  lookup?: DnsLookup;
  /**
   * Transport seam. Default auto-selects `nodeHttpsTransport` when `node:https` is available,
   * else `fetchTransport`. Serverless runtimes where the pinned path is broken (not absent)
   * should pass `fetchTransport` explicitly.
   */
  transport?: SafeFetchTransport;
  /**
   * First-party origins the caller OWNS (e.g. `["https://api.example.com"]`). A request whose
   * origin equals one of these skips the SSRF resolve-and-pin screen and is fetched plain by
   * name — origin-equality is not attacker-routable. Each entry MUST be a valid https origin
   * (fail-closed otherwise); every non-listed origin still takes the guarded path.
   */
  allowOrigins?: string[];
  /** Convenience singular form of {@link SafeFetchOptions.allowOrigins}. */
  firstPartyOrigin?: string;
  /**
   * How long one read may take, in ms, from the call to its body: the DNS lookup of each hop, every
   * redirect hop and the body together (default 5000).
   */
  timeoutMs?: number;
  /** Maximum response body size, in bytes (default 1 MiB). */
  maxBytes?: number;
  /** Maximum same-origin redirects to follow (default 3). */
  maxRedirects?: number;
  /**
   * Read hosts whose addresses are private or local, such as a `*.localhost` name in a local demo:
   * the host is still resolved once and pinned, but its address is not screened. Nothing else
   * changes: https alone, the origin rule for redirects, the size cap and the timeout all hold. For
   * development only: while `NODE_ENV` is `production` it throws when the fetcher is built, and it
   * warns once per process. A production deployment lists the origins it owns in `allowOrigins`
   * instead. Any value but a boolean throws a `TypeError`. A runtime with no `process`, such as
   * Workers, has no `NODE_ENV` to read unless its bundler defines `process.env.NODE_ENV`, so there it
   * does not throw: keep it out of production configuration.
   */
  development?: boolean;
}
