/**
 * Runtime FetchProvider
 *
 * Network-capable `FetchProvider` for any runtime that exposes a global
 * `fetch` (Node 18+, Deno, Bun, Cloudflare Workers, browsers). It resolves
 * DIDs (did:key locally, did:web over HTTPS), fetches StatusList2021 credentials,
 * and exposes the raw `fetch` escape hatch the delegation resolvers build on.
 *
 * Security (SSRF): `resolveDID` (did:web) and `fetchStatusList` issue outbound
 * HTTPS GETs to hosts named by counterparty-controlled data — the DID or
 * status-list URL embedded in a proof or credential. To blunt SSRF, requests to
 * private / loopback / link-local IP-literal hosts (e.g. did:web:169.254.169.254,
 * the cloud-metadata endpoint) are refused by default. This is best-effort
 * defense-in-depth for IP literals only: it does NOT stop a public domain that
 * resolves to an internal address (DNS rebinding). Run verifiers behind an egress
 * allowlist. Pass `{ allowPrivateNetworkHosts: true }` for trusted internal use.
 * The raw `fetch()` escape hatch is intentionally unguarded — it is the caller's
 * responsibility.
 *
 * @example
 * ```typescript
 * import { ProofVerifier, RuntimeFetchProvider, SystemClockProvider, NodeCryptoProvider, MemoryNonceCacheProvider } from '@kya-os/mcp';
 *
 * const verifier = new ProofVerifier({
 *   cryptoProvider: new NodeCryptoProvider(),
 *   clockProvider: new SystemClockProvider(),
 *   nonceCacheProvider: new MemoryNonceCacheProvider(),
 *   fetchProvider: new RuntimeFetchProvider(), // resolves the signer's did:key / did:web
 * });
 * ```
 */

import { FetchProvider } from "./base.js";
import { createDidKeyResolver } from "../delegation/did-key-resolver.js";
import {
  createDidWebResolver,
  isDidWeb,
  didWebToUrl,
} from "../delegation/did-web-resolver.js";
import type { DIDDocument } from "../delegation/vc-verifier.js";
import type {
  StatusList2021Credential,
  DelegationRecord,
} from "../types/protocol.js";

export interface RuntimeFetchProviderOptions {
  /**
   * Allow outbound requests to private / loopback / link-local IP-literal hosts.
   * Default `false` (such hosts are refused to blunt SSRF). Enable only for
   * trusted internal deployments.
   */
  allowPrivateNetworkHosts?: boolean;
}

export class RuntimeFetchProvider extends FetchProvider {
  private readonly didKeyResolver = createDidKeyResolver();
  private didWebResolver: ReturnType<typeof createDidWebResolver> | undefined;
  private readonly allowPrivateNetworkHosts: boolean;

  constructor(options?: RuntimeFetchProviderOptions) {
    super();
    this.allowPrivateNetworkHosts =
      options?.allowPrivateNetworkHosts ?? false;
  }

  /**
   * Resolve a DID to its DID Document. did:key is decoded locally (no network);
   * did:web is fetched from its HTTPS `/.well-known/did.json`. Returns null for
   * unsupported methods, a blocked (private-network) did:web host, or any
   * resolution failure (never throws).
   */
  async resolveDID(did: string): Promise<DIDDocument | null> {
    if (did.startsWith("did:key:")) {
      return this.didKeyResolver.resolve(did);
    }
    if (isDidWeb(did)) {
      if (this.isBlockedTarget(didWebToUrl(did))) {
        return null;
      }
      // createDidWebResolver(this) only calls this.fetch() — never resolveDID —
      // so passing `this` does not recurse. Cache it to reuse its doc cache.
      if (!this.didWebResolver) {
        this.didWebResolver = createDidWebResolver(this);
      }
      return this.didWebResolver.resolve(did);
    }
    return null;
  }

  /**
   * Fetch and validate a StatusList2021 credential by URL. Returns null on a
   * blocked (private-network) host, non-ok response, malformed payload, or
   * transport error (never throws). Bit decoding is the verifier's job — this
   * only retrieves the credential.
   */
  async fetchStatusList(url: string): Promise<StatusList2021Credential | null> {
    if (this.isBlockedTarget(url)) {
      return null;
    }
    try {
      const res = await this.fetch(url);
      if (!res.ok) {
        return null;
      }
      const json: unknown = await res.json();
      return isStatusList2021Credential(json) ? json : null;
    } catch {
      return null;
    }
  }

  /**
   * No remote delegation-chain wire format is defined: chains are assembled from
   * a populated delegation graph, not fetched by id. Returns [] so consumers
   * treat the chain as locally supplied.
   */
  async fetchDelegationChain(_id: string): Promise<DelegationRecord[]> {
    return [];
  }

  /** Raw HTTP escape hatch — delegates to the runtime's global `fetch`. */
  async fetch(url: string, options?: unknown): Promise<Response> {
    if (typeof globalThis.fetch !== "function") {
      throw new Error("Global fetch is not available in this runtime");
    }
    return globalThis.fetch(url, options as RequestInit);
  }

  /** True when SSRF protection should refuse `url` (a private IP-literal host). */
  private isBlockedTarget(url: string | null): boolean {
    if (this.allowPrivateNetworkHosts || url === null) {
      return false;
    }
    let hostname: string;
    try {
      hostname = new URL(url).hostname;
    } catch {
      return false;
    }
    return isPrivateOrLoopbackHost(hostname);
  }
}

/** Structural guard: a JSON payload is a StatusList2021 credential. */
function isStatusList2021Credential(
  value: unknown,
): value is StatusList2021Credential {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const cred = value as Record<string, unknown>;
  if (
    !Array.isArray(cred["type"]) ||
    !cred["type"].includes("StatusList2021Credential")
  ) {
    return false;
  }
  const subject = cred["credentialSubject"];
  if (typeof subject !== "object" || subject === null) {
    return false;
  }
  const s = subject as Record<string, unknown>;
  return s["type"] === "StatusList2021" && typeof s["encodedList"] === "string";
}

/**
 * True if `hostname` is a private / loopback / link-local IP LITERAL. Domain
 * names return false (DNS-resolution-based SSRF is out of scope here — use an
 * egress allowlist). Covers the common IPv4 ranges plus IPv6 loopback /
 * link-local / unique-local literals.
 */
function isPrivateOrLoopbackHost(hostname: string): boolean {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) {
    h = h.slice(1, -1); // URL.hostname brackets IPv6 literals
  }
  if (h.includes(":")) {
    // IPv6 literal
    return (
      h === "::1" || // loopback
      h === "::" || // unspecified
      h.startsWith("fe80:") || // link-local
      h.startsWith("fc") || // unique-local fc00::/7
      h.startsWith("fd")
    );
  }
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) {
    return false; // domain name, not an IP literal
  }
  const a = Number(m[1]);
  const b = Number(m[2]);
  return (
    a === 127 || // loopback 127.0.0.0/8
    a === 10 || // private 10.0.0.0/8
    a === 0 || // 0.0.0.0/8 (unspecified / this-host)
    (a === 169 && b === 254) || // link-local 169.254.0.0/16 (cloud metadata)
    (a === 192 && b === 168) || // private 192.168.0.0/16
    (a === 172 && b >= 16 && b <= 31) // private 172.16.0.0/12
  );
}
