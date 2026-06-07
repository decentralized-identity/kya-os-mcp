/**
 * DID:cheqd Resolver
 *
 * Resolves did:cheqd DIDs through an explicitly configured resolver endpoint.
 * The resolver accepts both Universal Resolver-style DID Resolution Results
 * (`{ didDocument: ... }`) and raw DID Documents.
 */

import type { FetchProvider } from '../../providers/base.js';
import type { DIDResolverFactory } from '../../delegation/did-resolver-registry.js';
import type { DIDDocument, DIDResolver, VerificationMethod } from '../../delegation/vc-verifier.js';
import { logger } from '../../logging/index.js';
import { isRecord, stripTrailingSlashes } from '../../utils/index.js';

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
  private readonly cache: Map<string, { document: DIDDocument; expiresAt: number }>;
  private readonly cacheTtl: number;
  private readonly headers?: Record<string, string> | (() => Promise<Record<string, string>>);

  constructor(fetchProvider: FetchProvider, options: DidCheqdResolverOptions) {
    this.fetchProvider = fetchProvider;
    this.resolverUrl = options.resolverUrl;
    this.cacheTtl = options.cacheTtl ?? 300_000;
    this.headers = options.headers;
    this.cache = new Map();
  }

  async resolve(did: string): Promise<DIDDocument | null> {
    if (!parseDidCheqd(did)) {
      return null;
    }

    const cached = this.cache.get(did);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.document;
    }

    try {
      const response = await this.fetchProvider.fetch(
        didCheqdToResolverUrl(did, this.resolverUrl),
        {
          method: 'GET',
          headers: await this.resolveHeaders(),
        },
      );

      if (!response.ok) {
        logger.warn(`[DidCheqdResolver] HTTP ${response.status} resolving ${did}`);
        return null;
      }

      let json: unknown;
      try {
        json = await response.json();
      } catch {
        logger.warn(`[DidCheqdResolver] Invalid JSON resolving ${did}`);
        return null;
      }

      const document = extractDidDocument(json);
      if (!document || !isValidDIDDocument(document)) {
        logger.warn(`[DidCheqdResolver] Invalid DID Document resolving ${did}`);
        return null;
      }

      if (document.id !== did) {
        logger.warn(`[DidCheqdResolver] DID Document id mismatch: expected ${did}, got ${document.id}`);
        return null;
      }

      this.cache.set(did, {
        document,
        expiresAt: Date.now() + this.cacheTtl,
      });

      return document;
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
      if (!isValidVerificationMethod(method)) {
        return false;
      }
    }
  }

  return true;
}

function isValidVerificationMethod(value: unknown): value is VerificationMethod {
  if (!isRecord(value)) {
    return false;
  }
  return (
    typeof value['id'] === 'string' &&
    value['id'].length > 0 &&
    typeof value['type'] === 'string' &&
    value['type'].length > 0 &&
    typeof value['controller'] === 'string' &&
    value['controller'].length > 0
  );
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}
