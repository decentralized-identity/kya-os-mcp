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
import type { DIDDocument, DIDResolver } from '../../delegation/vc-verifier.js';
import { hasIdTypeAndController } from '../../delegation/verification-method-shape.js';
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
}

interface DidResolutionResult {
  didDocument?: unknown;
}

export function isDidCheqd(did: string): boolean {
  return did.startsWith('did:cheqd:');
}

export function parseDidCheqd(did: string): ParsedDidCheqd | null {
  const match = /^did:cheqd:(mainnet|testnet):([^/?#]+)$/.exec(did);
  if (!match) {
    return null;
  }

  const uniqueId = match[2] ?? '';
  if (uniqueId.length === 0) {
    return null;
  }

  return {
    network: match[1] as DidCheqdNetwork,
    uniqueId,
  };
}

export class DidCheqdResolver implements DIDResolver {
  private readonly fetchProvider: FetchProvider;
  private readonly resolverUrl: string;
  private readonly cache: DidDocumentCache;
  private readonly cacheTtl: number;
  private readonly headers?: Record<string, string> | (() => Promise<Record<string, string>>);

  constructor(fetchProvider: FetchProvider, options: DidCheqdResolverOptions) {
    this.fetchProvider = fetchProvider;
    this.resolverUrl = options.resolverUrl;
    this.cacheTtl = options.cacheTtl ?? 300_000;
    this.headers = options.headers;
    this.cache = new DidDocumentCache();
  }

  async resolve(did: string): Promise<DIDDocument | null> {
    if (!boundedDid(did) || !parseDidCheqd(did)) {
      return null;
    }
    return this.cache.resolve(did, this.cacheTtl, () => this.fetchDocument(did));
  }

  /**
   * Fetch, measure, freeze and check the document for `did`, or `null`. The read's one deadline
   * holds the configured headers too, so a headers function that never answers ends the resolution
   * at the deadline and leaves nothing pending for the next one to join.
   */
  private async fetchDocument(did: string): Promise<LoadedDidDocument | null> {
    try {
      const init = this.requestHeaders().then((headers): RequestInit => ({ method: 'GET', headers }));
      const json = await fetchBoundedJson(
        this.fetchProvider, didCheqdToResolverUrl(did, this.resolverUrl), init, DID_RESOLUTION_ENVELOPE_READ,
      );
      const document = extractDidDocument(json);
      const measure = admitParsedDidDocument(document);
      if (!measure.ok || !isValidDIDDocument(document)) {
        const reason = measure.ok ? '' : `: ${measure.reason}`;
        logger.warn(`[DidCheqdResolver] Invalid DID Document resolving ${did}${reason}`);
        return null;
      }

      if (document.id !== did) {
        logger.warn(`[DidCheqdResolver] DID Document id mismatch: expected ${did}, got ${document.id}`);
        return null;
      }

      return { document, bytes: measure.bytes };
    } catch (error) {
      logger.warn(
        `[DidCheqdResolver] Error resolving ${did}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return null;
    }
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

export function cheqdResolver(options: DidCheqdResolverOptions): DIDResolverFactory {
  return (fetchProvider) => createDidCheqdResolver(fetchProvider, options);
}

export function didCheqdToResolverUrl(did: string, resolverUrl: string): string {
  const base = stripTrailingSlashes(resolverUrl);
  if (base.includes('{did}')) {
    return base.replace('{did}', did);
  }
  if (base.endsWith('/1.0/identifiers')) {
    return `${base}/${did}`;
  }
  return `${base}/1.0/identifiers/${did}`;
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
