/**
 * DID:cheqd Resolver
 *
 * Resolves did:cheqd DIDs through an explicitly configured resolver endpoint.
 * It asks for the DID document alone (`Accept: application/did+ld+json`, W3C
 * DID Resolution), which the cheqd resolver answers without the resolution
 * metadata, and still accepts a Universal Resolver-style DID Resolution Result
 * (`{ didDocument: ... }`) from a resolver that sends one anyway. That envelope
 * is read within its own limits; the document inside it meets the document's.
 */

import type { FetchProvider } from '../../providers/base.js';
import type { DIDResolverFactory } from '../../delegation/did-resolver-registry.js';
import type { DIDDocument, DIDResolver, DidResolutionFailure } from '../../delegation/vc-verifier.js';
import {
  DidResolutionFailures, invalidDid, invalidDocument, readFailureOf, unservedMethod,
} from '../../delegation/did-resolution-failure.js';
import { hasIdTypeAndController } from '../../delegation/verification-method-shape.js';
import { dependencyTimeout } from '../../utils/deadline.js';
import { logger } from '../../logging/index.js';
import { isRecord, stripTrailingSlashes } from '../../utils/index.js';

import {
  admitParsedDidDocument, boundedDid, DID_RESOLUTION_ENVELOPE_READ, DidDocumentCache, type LoadedDidDocument,
} from '../../delegation/did-resource-limits.js';
import { fetchBoundedJson } from '../../utils/bounded-read.js';

/** The DID document alone, without resolution metadata (W3C DID Resolution). */
const DID_DOCUMENT_MEDIA_TYPE = 'application/did+ld+json';

export type DidCheqdNetwork = 'mainnet' | 'testnet';

export interface ParsedDidCheqd {
  network: DidCheqdNetwork;
  uniqueId: string;
}

export interface DidCheqdResolverOptions {
  resolverUrl: string;
  cacheTtl?: number;
  headers?: Record<string, string> | (() => Promise<Record<string, string>>);
  /**
   * How long, in milliseconds, one resolution, its `headers` function, request and body together, may take: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
}

interface DidResolutionResult {
  didDocument?: unknown;
}

export function isDidCheqd(did: string): boolean {
  return did.startsWith('did:cheqd:');
}

/**
 * The method-specific identifier of a did:cheqd DID, as cheqd's DID method (ADR 001) writes it:
 * `unique-id = *id-char / UUID`, `id-char = ALPHA / DIGIT`, a UUID in the RFC 4122 text form with
 * hex digits of either case. Nothing else is one: no `\`, `.`, `%`, `$`, white space or further
 * `:`, each of which would otherwise reach the request URL built from the DID.
 */
const UNIQUE_ID = /^(?:[0-9A-Za-z]+|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$/;

/**
 * `did` as a did:cheqd DID of mainnet or testnet, or `null` when it is not one: another method or
 * namespace, a DID URL with a path, query or fragment, or a unique id outside {@link UNIQUE_ID}.
 * The resolver asks its endpoint only for a DID this reads, so a counterparty that names a DID
 * chooses the identifier it asks for and nothing else about the request.
 */
export function parseDidCheqd(did: string): ParsedDidCheqd | null {
  const match = /^did:cheqd:(mainnet|testnet):(.*)$/s.exec(did);
  const uniqueId = match?.[2];
  if (!match || uniqueId === undefined || !UNIQUE_ID.test(uniqueId)) {
    return null;
  }
  return { network: match[1] as DidCheqdNetwork, uniqueId };
}

export class DidCheqdResolver implements DIDResolver {
  private readonly fetchProvider: FetchProvider;
  private readonly resolverUrl: string;
  private readonly cache: DidDocumentCache;
  private readonly cacheTtl: number;
  private readonly headers?: Record<string, string> | (() => Promise<Record<string, string>>);
  private readonly timeoutMs: number;
  private readonly failures = new DidResolutionFailures();

  constructor(fetchProvider: FetchProvider, options: DidCheqdResolverOptions) {
    this.fetchProvider = fetchProvider;
    this.resolverUrl = options.resolverUrl;
    this.cacheTtl = options.cacheTtl ?? 300_000;
    this.headers = options.headers;
    this.timeoutMs = dependencyTimeout(options.dependencyTimeoutMs);
    this.cache = new DidDocumentCache(this.timeoutMs);
  }

  async resolve(did: string): Promise<DIDDocument | null> {
    if (!boundedDid(did)) {
      return null;
    }
    if (!parseDidCheqd(did)) {
      // Asking the endpoint again could not change this, so it is a verdict, never a retry.
      return this.failed(did, isDidCheqd(did)
        ? invalidDid('the DID is not a did:cheqd DID of mainnet or testnet')
        : unservedMethod('the did:cheqd resolver', did));
    }
    return this.cache.resolve(did, this.cacheTtl, () => this.fetchDocument(did));
  }

  /**
   * Why the last resolution of `did` found no document: its deadline passed, the endpoint
   * unavailable, its answer over the byte cap, the document invalid, or the DID not a did:cheqd DID
   * of mainnet or testnet this resolver can ask for, which is `invalid_document` too. `undefined`
   * once a read of it has found one, and for a DID this resolver was never asked for.
   */
  lastFailure(did: string): DidResolutionFailure | undefined {
    return this.failures.get(did);
  }

  /**
   * Fetch, measure, freeze and check the document for `did`, or `null`. The read's one deadline
   * holds the configured headers too, so a headers function that never answers ends the resolution
   * at the deadline and leaves nothing pending for the next one to join.
   */
  private async fetchDocument(did: string): Promise<LoadedDidDocument | null> {
    const url = didCheqdToResolverUrl(did, this.resolverUrl);
    try {
      const init = this.requestHeaders().then((headers): RequestInit => ({ method: 'GET', headers }));
      const json = await fetchBoundedJson(this.fetchProvider, url, init, { ...DID_RESOLUTION_ENVELOPE_READ, timeoutMs: this.timeoutMs });
      const document = extractDidDocument(json);
      const measure = admitParsedDidDocument(document);
      if (!measure.ok || !isValidDIDDocument(document)) {
        const reason = measure.ok ? '' : `: ${measure.reason}`;
        logger.warn(`[DidCheqdResolver] Invalid DID Document resolving ${did}${reason}`);
        return this.failed(did, invalidDocument(url, `is not a valid DID document${reason}`));
      }

      if (document.id !== did) {
        logger.warn(`[DidCheqdResolver] DID Document id mismatch: expected ${did}, got ${document.id}`);
        return this.failed(did, invalidDocument(url, 'names another DID as its id'));
      }

      this.failures.clear(did);
      return { document, bytes: measure.bytes };
    } catch (error) {
      logger.warn(
        `[DidCheqdResolver] Error resolving ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return this.failed(did, readFailureOf(error, url, this.timeoutMs));
    }
  }

  /** Record `failure` as the last for `did`, and find no document. */
  private failed(did: string, failure: DidResolutionFailure): null {
    this.failures.record(did, failure);
    return null;
  }

  clearCache(): void {
    this.cache.clear();
  }

  clearCacheEntry(did: string): void {
    this.cache.delete(did);
  }

  /** The configured headers, with `Accept` set to the document's media type in place of any the caller set. */
  private async requestHeaders(): Promise<Headers> {
    const headers = new Headers(await this.resolveHeaders());
    headers.set('Accept', DID_DOCUMENT_MEDIA_TYPE);
    return headers;
  }

  private async resolveHeaders(): Promise<Record<string, string> | undefined> {
    if (!this.headers) {
      return undefined;
    }
    return typeof this.headers === 'function' ? this.headers() : this.headers;
  }
}

export function createDidCheqdResolver(
  fetchProvider: FetchProvider,
  options: DidCheqdResolverOptions,
): DIDResolver {
  return new DidCheqdResolver(fetchProvider, options);
}

/**
 * A `didResolvers` entry that builds the cheqd resolver over the registry owner's fetch provider.
 * The resolver waits as long as `options.dependencyTimeoutMs` says, or, when that is left out, as
 * long as the owner waits: the `dependencyTimeoutMs` of the delegation middleware or of the
 * `RuntimeFetchProvider` that holds the registry.
 */
export function cheqdResolver(options: DidCheqdResolverOptions): DIDResolverFactory {
  return (fetchProvider, context) => createDidCheqdResolver(
    fetchProvider,
    options.dependencyTimeoutMs === undefined ? { ...options, dependencyTimeoutMs: context?.dependencyTimeoutMs } : options,
  );
}

/**
 * The URL to ask `resolverUrl` for `did` at: the `{did}` of a template, or under
 * `/1.0/identifiers/`. The DID is written as one path segment, percent-encoded except for its
 * colons, which a path segment may hold (RFC 3986 section 3.3) and which resolvers expect as they
 * stand, so a DID of the method is written unchanged and any other string cannot add a segment, a
 * query or a fragment. A template takes it through a function, so `$&` and the other replacement
 * patterns in it are text.
 */
export function didCheqdToResolverUrl(did: string, resolverUrl: string): string {
  const base = stripTrailingSlashes(resolverUrl);
  const segment = encodeURIComponent(did).replace(/%3A/g, ':');
  if (base.includes('{did}')) {
    return base.replace('{did}', () => segment);
  }
  if (base.endsWith('/1.0/identifiers')) {
    return `${base}/${segment}`;
  }
  return `${base}/1.0/identifiers/${segment}`;
}

function extractDidDocument(value: unknown): unknown {
  if (isRecord(value) && value['didDocument'] !== undefined) {
    return (value as DidResolutionResult).didDocument;
  }
  return value;
}

function isValidDIDDocument(value: unknown): value is DIDDocument {
  if (!isRecord(value)) {
    return false;
  }

  if (typeof value['id'] !== 'string' || value['id'].length === 0) {
    return false;
  }

  if (value['alsoKnownAs'] !== undefined && !isStringArray(value['alsoKnownAs'])) {
    return false;
  }

  if (value['verificationMethod'] !== undefined) {
    if (!Array.isArray(value['verificationMethod'])) {
      return false;
    }
    for (const method of value['verificationMethod']) {
      if (!hasIdTypeAndController(method)) {
        return false;
      }
    }
  }

  return true;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}
