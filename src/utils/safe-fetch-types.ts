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
}

/** Per-request context handed to the transport (connection already validated + pinned). */
export interface TransportInit {
  signal: AbortSignal;
  hostname: string;
  pinnedAddress: string;
  family: number;
  maxBytes: number;
}

/** Transport seam — performs ONE request (no redirect following) to the pinned address. */
export type SafeFetchTransport = (url: string, init: TransportInit) => Promise<RawResponse>;

/** The fetcher safe-fetch returns — structurally compatible with the card's `FetchLike`. */
export interface SafeFetchResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

export type SafeFetch = (url: string) => Promise<SafeFetchResponse>;

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
  /** Request timeout per hop, in ms (default 5000). */
  timeoutMs?: number;
  /** Maximum response body size, in bytes (default 1 MiB). */
  maxBytes?: number;
  /** Maximum same-origin redirects to follow (default 3). */
  maxRedirects?: number;
}
