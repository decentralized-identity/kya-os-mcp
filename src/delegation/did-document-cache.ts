/**
 * A built-in network resolver's document cache (SPEC §4.4.2): at most 128 documents and 8 MiB of
 * their compact JSON, each for its TTL, evicting the least recently used. A TTL alone would not
 * bound what an attacker who names many DIDs can make a verifier hold.
 *
 * It holds only documents the walk admitted, which are frozen, so a hit is served as stored with no
 * second walk. Concurrent resolutions of one DID share one load until the resolution deadline: a
 * load still pending then is dropped, so no load that hangs can hold every later resolution of its
 * DID, and the next one starts afresh.
 */

import type { DIDDocument } from './vc-verifier.types.js';
import {
  DID_RESOLUTION_TIMEOUT_MS, MAX_CACHED_BYTES, MAX_CACHED_DOCUMENTS, MAX_DID_DOCUMENT_BYTES,
} from './did-resource-policy.js';

/** A document a resolver loaded and the walk admitted, with its compact JSON size. */
export interface LoadedDidDocument {
  readonly document: DIDDocument;
  readonly bytes: number;
}

interface Entry extends LoadedDidDocument {
  readonly expires: number;
}

export class DidDocumentCache {
  /** In order of use, least recent first. */
  private readonly entries = new Map<string, Entry>();
  private readonly loading = new Map<string, Promise<DIDDocument | null>>();
  private bytes = 0;

  /** The unexpired document cached for `did`, now the most recently used. */
  get(did: string): DIDDocument | undefined {
    const entry = this.entries.get(did);
    if (entry === undefined) return undefined;
    this.entries.delete(did);
    if (!(Date.now() < entry.expires)) {
      this.bytes -= entry.bytes;
      return undefined;
    }
    this.entries.set(did, entry);
    return entry.document;
  }

  /**
   * Cache `document` for `ttl` ms, evicting the least recently used entries until it fits. A size
   * that is not a whole number of bytes up to the document limit stores nothing.
   */
  set(did: string, document: DIDDocument, bytes: number, ttl: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_DID_DOCUMENT_BYTES) return;
    this.evict(did);
    while (this.entries.size >= MAX_CACHED_DOCUMENTS || this.bytes + bytes > MAX_CACHED_BYTES) {
      const leastRecent = this.entries.keys().next();
      if (leastRecent.done) return;
      this.evict(leastRecent.value);
    }
    this.entries.set(did, { document, bytes, expires: Date.now() + ttl });
    this.bytes += bytes;
  }

  /**
   * The cached document for `did`, else the one `load` resolves to, cached for `ttl` ms. Calls for
   * one DID while its load is pending share that load and its outcome, until the resolution
   * deadline drops it. A load caches its document only while it is still the DID's pending load:
   * one pending across the deadline, a `delete` of the DID, or a `clear`, caches nothing.
   */
  resolve(did: string, ttl: number, load: () => Promise<LoadedDidDocument | null>): Promise<DIDDocument | null> {
    const cached = this.get(did);
    if (cached !== undefined) return Promise.resolve(cached);
    const pending = this.loading.get(did);
    if (pending !== undefined) return pending;
    const drop = (): void => {
      if (this.loading.get(did) === loaded) this.loading.delete(did);
    };
    const loaded: Promise<DIDDocument | null> = load().then(result => {
      if (result === null) return null;
      if (this.loading.get(did) === loaded) this.set(did, result.document, result.bytes, ttl);
      return result.document;
    }).finally(() => {
      clearTimeout(deadline);
      drop();
    });
    const deadline = setTimeout(drop, DID_RESOLUTION_TIMEOUT_MS);
    this.loading.set(did, loaded);
    return loaded;
  }

  /** Forget `did`: its cached document, and any load pending for it, which then caches nothing. */
  delete(did: string): void {
    this.loading.delete(did);
    this.evict(did);
  }

  clear(): void {
    this.entries.clear();
    this.loading.clear();
    this.bytes = 0;
  }

  private evict(did: string): void {
    const entry = this.entries.get(did);
    if (entry === undefined) return;
    this.bytes -= entry.bytes;
    this.entries.delete(did);
  }
}
