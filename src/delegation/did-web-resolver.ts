/**
 * DID:web Resolver
 *
 * Resolves did:web DIDs by fetching /.well-known/did.json from the domain.
 * Supports both root domain DIDs and path-based DIDs.
 *
 * Examples:
 *   did:web:example.com → https://example.com/.well-known/did.json
 *   did:web:example.com:agents:bot1 → https://example.com/agents/bot1/did.json
 *
 * @see https://w3c-ccg.github.io/did-method-web/
 */

import type { FetchProvider } from '../providers/base.js';
import type { DIDResolver, DIDDocument } from './vc-verifier.js';
import { logger } from '../logging/index.js';
import { hasIdTypeAndController } from './verification-method-shape.js';

import { admitParsedDidDocument, boundedDid, DidDocumentCache, type LoadedDidDocument } from './did-resource-limits.js';
import { dependencyTimeout } from '../utils/deadline.js';
import { developmentMode } from '../utils/development-mode.js';
import { admittingPrivateHosts, type PrivateNetworkTransport } from '../utils/private-network-rule.js';
import { fetchDidJson } from './read-did-json.js';
import { didWebToUrl, isDidWeb } from './did-web-url.js';

export { didWebToUrl, isDidWeb, parseDidWeb } from './did-web-url.js';

/**
 * Whether a document the walk admitted, an object whose `id` is a DID, states its
 * `verificationMethod`, when it states one, as an array of methods that each name an `id`, a
 * `type` and a `controller`.
 */
function hasWellFormedMethods(document: DIDDocument): boolean {
  const methods: unknown = (document as unknown as Record<string, unknown>)['verificationMethod'];
  return (
    methods === undefined ||
    (Array.isArray(methods) && methods.every((method) => hasIdTypeAndController(method)))
  );
}

/** Options of {@link DidWebResolver} and {@link createDidWebResolver}. */
export interface DidWebResolverOptions {
  /** How long a resolved document is cached, in milliseconds. Default 300,000. */
  cacheTtl?: number;
  /**
   * How long, in milliseconds, one read of a did:web document, headers and body, may take: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
  /**
   * Read documents on private and local hosts, such as a `*.localhost` name in a local demo, as a
   * provider with `allowPrivateNetworkHosts: true` does, whatever the provider. Nothing else
   * changes: the scheme rule, checked redirects, byte caps and deadlines all hold. For development
   * only: while `NODE_ENV` is `production` it throws when the resolver is built, and it warns once
   * per process. A production deployment that reads intranet hosts gives its fetch provider
   * `allowPrivateNetworkHosts: true` instead. Any value but a boolean throws a `TypeError`.
   */
  development?: boolean;
}

/**
 * DID:web resolver implementation
 */
export class DidWebResolver implements DIDResolver {
  private fetchProvider: PrivateNetworkTransport;
  private cache: DidDocumentCache;
  private cacheTtl: number;
  private readonly timeoutMs: number;

  constructor(fetchProvider: Pick<FetchProvider, 'fetch' | 'allowPrivateNetworkHosts'>, options?: DidWebResolverOptions) {
    const development = developmentMode(options?.development, 'DidWebResolverOptions.development');
    this.fetchProvider = development ? admittingPrivateHosts(fetchProvider) : fetchProvider;
    this.timeoutMs = dependencyTimeout(options?.dependencyTimeoutMs);
    this.cache = new DidDocumentCache(this.timeoutMs);
    this.cacheTtl = options?.cacheTtl ?? 300_000; // 5 minutes default
  }

  /**
   * Resolve a did:web DID to its DID Document
   *
   * @param did - The did:web DID to resolve
   * @returns The DID Document or null if resolution fails
   */
  async resolve(did: string): Promise<DIDDocument | null> {
    // Check if it's a did:web
    if (!boundedDid(did) || !isDidWeb(did)) {
      return null;
    }

    // Convert to URL
    const url = didWebToUrl(did);
    if (!url) {
      logger.warn(`[DidWebResolver] Invalid did:web format: ${did}`);
      return null;
    }

    // A cached document is frozen and was walked when it was fetched; concurrent
    // resolutions of one DID share one fetch.
    return this.cache.resolve(did, this.cacheTtl, () => this.fetchDocument(did, url));
  }

  /** Fetch, measure, freeze and check the document `did` names at `url`, or `null`. */
  private async fetchDocument(did: string, url: string): Promise<LoadedDidDocument | null> {
    try {
      const json: unknown = await fetchDidJson(this.fetchProvider, url, {}, this.timeoutMs);
      const measure = admitParsedDidDocument(json);
      if (!measure.ok) {
        logger.warn(`[DidWebResolver] DID Document from ${url} refused: ${measure.reason}`);
        return null;
      }

      const { document } = measure;
      if (!hasWellFormedMethods(document)) {
        logger.warn(`[DidWebResolver] Invalid DID Document structure from ${url}`);
        return null;
      }

      // Verify the id matches the DID
      if (document.id !== did) {
        logger.warn(`[DidWebResolver] DID Document id mismatch: expected ${did}, got ${document.id}`);
        return null;
      }

      return { document, bytes: measure.bytes };
    } catch (error) {
      logger.warn(
        `[DidWebResolver] Error resolving ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      return null;
    }
  }

  /**
   * Clear the resolution cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Clear a specific entry from the cache
   */
  clearCacheEntry(did: string): void {
    this.cache.delete(did);
  }
}

/**
 * Create a did:web resolver with the given fetch provider
 *
 * @param fetchProvider - Provider for making HTTP requests, read through the private-network rule
 *   unless it has `allowPrivateNetworkHosts: true` or `options.development` is true
 * @param options - Optional configuration
 * @returns DIDResolver implementation for did:web
 */
export function createDidWebResolver(
  fetchProvider: Pick<FetchProvider, 'fetch' | 'allowPrivateNetworkHosts'>,
  options?: DidWebResolverOptions
): DIDResolver {
  return new DidWebResolver(fetchProvider, options);
}

export { buildDidWebDocument, type BuildDidWebDocumentOptions } from './did-web-document.js';
