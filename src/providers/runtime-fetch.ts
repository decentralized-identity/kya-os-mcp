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
 * label, or a special-use domain the rule lists as `LOCAL_DOMAINS`, such as
 * `localhost`, or a name under one), and a scheme other than http and https are
 * refused, a status list is read over https unless the operator binds its
 * exact http URL, and redirects are followed
 * by hand up to the limit of `utils/redirect-follower.ts`, each target held to
 * the same rule. Where the runtime resolves names, as Node does, this provider
 * also resolves each host before it connects, every redirect's included,
 * refuses a host with any address that is not public (so
 * did:web:169.254.169.254.nip.io is refused too), and connects only to the
 * addresses it checked, trying each in turn, pinned so a second lookup cannot
 * rebind it, by SafeFetch's
 * own means: the `lookup` and `transport` options are SafeFetch's seams. A
 * runtime that resolves no name, such as a Worker or a browser, keeps the rule
 * on the URL alone, and its egress must refuse private addresses. So does a
 * subclass whose `fetch` is its own: that `fetch` makes its own connections.
 * The hosts the operator names are its own: the did:web documents of the DIDs
 * in `trustedRootIssuers` and the status lists `statusListIssuers` binds are
 * read wherever they are. Pass `{ allowPrivateNetworkHosts: true }` for trusted
 * internal use, or `{ development: true }` in local development alone. Every
 * read keeps the limits of SPEC §4.4.2.
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
import { assertTrustedRootIssuers } from "../delegation/root-admission.js";
import { dependencyTimeout } from "../utils/deadline.js";
import { developmentMode } from "../utils/development-mode.js";
import { getDidMethod } from "../utils/did-helpers.js";
import { ADDRESS_PINNING, type AddressPinning } from "../utils/fetch-port.js";
import { addressPinning } from "../utils/pinned-connection.js";
import { providerName, warnHeldToUrlAlone } from "../utils/url-only-reads.js";
import { operatorNamedRequests } from "../utils/operator-named.js";
import type { DnsLookup, SafeFetchTransport } from "../utils/safe-fetch-types.js";
import { assertStatusListIssuers, statusListIssuersBind, type StatusListIssuers } from "../utils/statuslist-keeper.js";
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
   * Read DID documents and status lists on private and local hosts, such as a
   * `*.localhost` name in a local demo, as `allowPrivateNetworkHosts: true`
   * does, and a status list over http from such a host, which that opt-out
   * does not. Nothing else changes: checked redirects, byte caps and
   * deadlines all hold. For development only: while `NODE_ENV` is
   * `production` it throws when the provider is built, and it warns once per
   * process. A production deployment that reads intranet hosts sets
   * `allowPrivateNetworkHosts: true` instead. Any value but a boolean throws a
   * `TypeError`. A runtime with no `process`, such as Workers, has no
   * `NODE_ENV` to read unless its bundler defines `process.env.NODE_ENV`, so
   * there it does not throw: keep it out of production configuration.
   */
  development?: boolean;
  /**
   * Optional DID method resolver registry. Entries dispatch by DID method before
   * built-in did:key and did:web fallback. A factory receives this fetch provider
   * so network-backed resolvers can share the same fetch implementation.
   */
  didResolvers?: DIDResolverRegistry;
  /**
   * How long, in milliseconds, one `resolveDID`, across a configured resolver and the built-in one, or one `fetchStatusList` may take: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
  /**
   * The DNS seam of the reads this provider makes of hosts a counterparty
   * names, SafeFetch's `lookup`: it answers every address a host name
   * resolves to, and the provider refuses the host when any is not public.
   * Default: `node:dns`, where the runtime resolves names; where it does not,
   * as in a Worker or a browser, those reads go through the runtime's `fetch`
   * and are held to the URL alone. Inject one to resolve through a resolver
   * of your own, such as DNS over HTTPS, or in tests.
   */
  lookup?: DnsLookup;
  /**
   * The connection seam of those reads, SafeFetch's `transport`: it makes one
   * request connected to the address the provider checked. Default: SafeFetch's
   * default, `nodeHttpsTransport`, which pins the connection to that address,
   * where `node:https` loads. A serverless runtime where the pinned path is
   * present but broken passes `fetchTransport`, which connects by name after
   * the check, as SafeFetch's options say.
   */
  transport?: SafeFetchTransport;
  /**
   * The DIDs the verifier pins as roots, as its `trustedRootIssuers` names
   * them. The operator names these, so `resolveDID` reads their did:web
   * documents wherever they are, a private or local host included, through
   * this provider's `fetch`; every other DID is held to the rule. Pass the list
   * the verifier is given. Anything but an array of DIDs throws a `TypeError`.
   */
  trustedRootIssuers?: readonly string[];
  /**
   * The verifier's `statusListIssuers`, in the shape it takes. The operator
   * names the URLs and `https:` origins it binds, so `fetchStatusList` reads a
   * list at one wherever it is, a private or local host included, through this
   * provider's `fetch`, and an exact `http:` URL it binds over http; every
   * other list, and every redirect to http, is held to the rule and to https. Only where a list
   * may be read is decided here: which issuer must sign it is the status-list
   * reader's to decide. A value the verifier would refuse throws a `TypeError`.
   */
  statusListIssuers?: StatusListIssuers;
}

export class RuntimeFetchProvider extends FetchProvider {
  private readonly didKeyResolver = createDidKeyResolver();
  private didWebResolver: ReturnType<typeof createDidWebResolver> | undefined;
  private readonly didResolvers: Record<string, { resolve(did: string): Promise<DIDDocument | null> }>;
  /**
   * The private-network rule's opt-out, read by every did:web and status-list
   * read through this provider, including the delegation gate's: `true` when
   * `allowPrivateNetworkHosts` or `development` is.
   */
  readonly allowPrivateNetworkHosts: boolean;
  /** Whether `development` is on, of all the opt-outs the one that also reads a status list over http from a private or local host. */
  private readonly development: boolean;
  private readonly timeoutMs: number;
  private readonly pinning: () => Promise<AddressPinning | undefined>;
  private readonly trustedRootIssuers: readonly string[] | undefined;
  private readonly statusListIssuers: StatusListIssuers | undefined;

  constructor(options?: RuntimeFetchProviderOptions) {
    super();
    this.timeoutMs = dependencyTimeout(options?.dependencyTimeoutMs);
    this.development = developmentMode(options?.development, "RuntimeFetchProviderOptions.development");
    this.allowPrivateNetworkHosts = this.development || options?.allowPrivateNetworkHosts === true;
    assertTrustedRootIssuers(options?.trustedRootIssuers, "RuntimeFetchProviderOptions.");
    assertStatusListIssuers(options?.statusListIssuers);
    this.trustedRootIssuers = options?.trustedRootIssuers;
    this.statusListIssuers = options?.statusListIssuers;
    this.pinning = addressPinning({ lookup: options?.lookup, transport: options?.transport });
    this.didResolvers = buildDidResolverRegistry(options?.didResolvers, this, { dependencyTimeoutMs: this.timeoutMs });
  }

  /**
   * How the private-network rule connects this provider's reads to the
   * addresses it checks, while its `fetch` is the runtime's own: a subclass
   * whose `fetch` is its own makes its own connections, offers none, and
   * says once that its reads are held to the URL alone.
   */
  readonly [ADDRESS_PINNING] = (): Promise<AddressPinning | undefined> => {
    if (this.fetch === RuntimeFetchProvider.prototype.fetch) return this.pinning();
    warnHeldToUrlAlone(`${providerName(this, "A subclass of RuntimeFetchProvider")} has a fetch of its own, which makes its own connections`);
    return Promise.resolve(undefined);
  };

  /**
   * Resolve a DID to its DID Document. did:key is decoded locally (no network);
   * did:web is fetched from its HTTPS `/.well-known/did.json`. A configured
   * resolver for the DID's method is asked first, and the built-in one only
   * when it finds no document: a document of its that the limits refuse ends
   * the resolution. Both share one deadline, `dependencyTimeoutMs`, and a miss ends the
   * resolution too. Returns null for unsupported methods, a blocked
   * (private-network) did:web host, a refused document, a missed deadline or
   * any resolution failure (never throws).
   */
  async resolveDID(did: string): Promise<DIDDocument | null> {
    if (!boundedDid(did)) return null;
    const deadline = resolutionDeadline(this.timeoutMs);
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
    // Only a method the registry holds as its own: `constructor` or `__proto__` names no resolver.
    const configuredResolver = method !== null && Object.hasOwn(this.didResolvers, method) ? this.didResolvers[method] : undefined;
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
        this.didWebResolver = createDidWebResolver(this, {
          dependencyTimeoutMs: this.timeoutMs,
          ...(this.trustedRootIssuers === undefined ? {} : { trustedRootIssuers: this.trustedRootIssuers }),
        });
      }
      return deadline.within(this.didWebResolver.resolve(did));
    }
    return null;
  }

  /**
   * Fetch and validate a StatusList2021 credential by URL. Returns null on a
   * blocked (private-network) host, an http URL other than an exact one
   * `statusListIssuers` binds, or one on a private or local host under
   * `development`, a non-ok response,
   * malformed payload, or transport error (never throws). A request for a URL
   * `statusListIssuers` binds is read on any host, decided request by
   * request, so a redirect to a URL it does not bind is held to the rule
   * as any other. Bit decoding is the
   * verifier's job: this only retrieves the credential.
   */
  async fetchStatusList(url: string): Promise<StatusList2021Credential | null> {
    try {
      const issuers = this.statusListIssuers;
      const bound = issuers === undefined ? undefined : operatorNamedRequests(url, (hop) => statusListIssuersBind(hop, issuers));
      const json = await fetchStatusListJson(this, url, {
        timeoutMs: this.timeoutMs,
        development: this.development,
        ...(bound ? { operatorNamed: bound } : {}),
      });
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
