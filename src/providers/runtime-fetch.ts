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
 * status-list URL embedded in a proof or credential. Both read through the
 * package's private-network rule (`utils/private-network-rule.ts`), as every
 * did:web and status-list read does whatever provider it goes through: a
 * private, loopback, link-local or otherwise non-public IP-literal host (e.g.
 * did:web:169.254.169.254, the cloud-metadata endpoint), a local name (a single
 * label, or `localhost`, `localdomain`, `local`, `internal` or `home.arpa` or a
 * name under one), and a scheme other than http and https are refused, and at
 * most three redirects are followed by hand, each target held to the same rule.
 * This is best-effort defense-in-depth: the rule resolves no name, so it does NOT
 * stop any other name whose address is internal, such as a public name that
 * points at a loopback address (or DNS rebinding). Run verifiers behind an
 * egress control. Pass `{ allowPrivateNetworkHosts: true }` for trusted
 * internal use. Both read the response within the limits of SPEC §4.4.2.
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
import {
  boundedDid,
  resolutionDeadline,
  resolveWithinLimits,
  type ResolutionDeadline,
} from "../delegation/did-resource-limits.js";
import { fetchStatusListJson } from "../delegation/status-list-fetch.js";
import { createDidKeyResolver } from "../delegation/did-key-resolver.js";
import {
  createDidWebResolver,
  isDidWeb,
} from "../delegation/did-web-resolver.js";
import {
  buildDidResolverRegistry,
  type DIDResolverRegistry,
} from "../delegation/did-resolver-registry.js";
import { getDidMethod } from "../utils/did-helpers.js";
import type { DIDDocument } from "../delegation/vc-verifier.js";
import type {
  StatusList2021Credential,
  DelegationRecord,
} from "../types/protocol.js";

export interface RuntimeFetchProviderOptions {
  /**
   * Allow outbound requests to private / loopback / link-local IP-literal hosts
   * and local names, such as `localhost`. Default `false` (such hosts are refused to blunt
   * SSRF). Enable only for trusted internal deployments. Only `true` opts in, as the rule reads
   * it: any other value, `1` or `'true'` included, leaves such hosts refused.
   */
  allowPrivateNetworkHosts?: boolean;
  /**
   * Optional DID method resolver registry. Entries dispatch by DID method before
   * built-in did:key and did:web fallback. A factory receives this fetch provider
   * so network-backed resolvers can share the same fetch implementation.
   */
  didResolvers?: DIDResolverRegistry;
}

export class RuntimeFetchProvider extends FetchProvider {
  private readonly didKeyResolver = createDidKeyResolver();
  private didWebResolver: ReturnType<typeof createDidWebResolver> | undefined;
  private readonly didResolvers: Record<string, { resolve(did: string): Promise<DIDDocument | null> }>;
  /**
   * The private-network rule's opt-out, read by every did:web and status-list
   * read through this provider, including the delegation gate's.
   */
  readonly allowPrivateNetworkHosts: boolean;

  constructor(options?: RuntimeFetchProviderOptions) {
    super();
    this.allowPrivateNetworkHosts = options?.allowPrivateNetworkHosts === true;
    this.didResolvers = buildDidResolverRegistry(options?.didResolvers, this);
  }

  /**
   * Resolve a DID to its DID Document. did:key is decoded locally (no network);
   * did:web is fetched from its HTTPS `/.well-known/did.json`. A configured
   * resolver for the DID's method is asked first, and the built-in one only
   * when it finds no document: a document of its that the limits refuse ends
   * the resolution. Both share one 5-second deadline, and a miss ends the
   * resolution too. Returns null for unsupported methods, a blocked
   * (private-network) did:web host, a refused document, a missed deadline or
   * any resolution failure (never throws).
   */
  async resolveDID(did: string): Promise<DIDDocument | null> {
    if (!boundedDid(did)) return null;
    const deadline = resolutionDeadline();
    try {
      return await this.resolveWithin(did, deadline);
    } catch {
      return null;
    } finally {
      deadline.clear();
    }
  }

  private async resolveWithin(did: string, deadline: ResolutionDeadline): Promise<DIDDocument | null> {
    const method = getDidMethod(did);
    const configuredResolver = method ? this.didResolvers[method] : undefined;
    if (configuredResolver) {
      const resolution = await resolveWithinLimits(configuredResolver, did, undefined, deadline);
      if (resolution.status === "found") return resolution.document;
      if (resolution.status === "refused") return null;
    }

    if (did.startsWith("did:key:")) {
      return this.didKeyResolver.resolve(did);
    }
    if (isDidWeb(did)) {
      // The did:web resolver only calls this.fetch(), under the private-network
      // rule, never resolveDID, so it does not recurse. Cache it to reuse its doc
      // cache. A read the deadline abandons ends at its own deadline.
      if (!this.didWebResolver) {
        this.didWebResolver = createDidWebResolver(this);
      }
      return deadline.within(this.didWebResolver.resolve(did));
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
    try {
      const json = await fetchStatusListJson(this, url);
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
}

/**
 * No-op {@link FetchProvider} for runtimes without a global `fetch`, and the
 * offline fallback when a verifier is constructed without one. Every network
 * lookup resolves empty so verification fails closed on anything that would
 * need the network, and the raw `fetch` escape hatch throws rather than
 * pretending to succeed. A single named definition (vs. an inline literal) so
 * it is covered once and reused everywhere the offline fallback is needed.
 */
export class NoopFetchProvider extends FetchProvider {
  async resolveDID(_did: string): Promise<DIDDocument | null> {
    return null;
  }
  async fetchStatusList(_url: string): Promise<StatusList2021Credential | null> {
    return null;
  }
  async fetchDelegationChain(_id: string): Promise<DelegationRecord[]> {
    return [];
  }
  async fetch(_url: string, _options?: unknown): Promise<Response> {
    throw new Error("fetch unavailable");
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
