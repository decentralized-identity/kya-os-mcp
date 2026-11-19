/**
 * In-Memory StatusList Storage Provider
 *
 * Memory-based implementation for testing and development.
 * NOT suitable for production (no persistence).
 */

import type { StatusList2021Credential, StatusListCredential } from '../../types/protocol.js';
import { base64urlEncodeFromBytes } from '../../utils/base64.js';
import { KeyedLock } from '../../utils/keyed-lock.js';
import type { StatusEntryOwner, StatusEntryOwnerStorageProvider } from '../status-entry-owner.js';
import type {
  ConditionalStatusListStorageProvider,
  HistoricalStatusListStorageProvider,
  StoredStatusList,
} from '../statuslist-storage.js';

function entryOwnerKey(statusListId: string, index: number): string {
  return `${statusListId}#${index}`;
}

function copyOwner(owner: StatusEntryOwner): StatusEntryOwner {
  return { delegationId: owner.delegationId, retired: owner.retired };
}

/**
 * The etag of a list no write to this class stored, as a subclass that keeps its lists elsewhere
 * holds: the SHA-256 of the list's JSON. Two lists share it only when they are the same list, so
 * a write made over a list read with it replaces only that list, and it is never one of the
 * etags this class gives its own writes, which are digits.
 */
async function contentEtag(credential: StatusListCredential): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(credential)));
  return `sha256:${base64urlEncodeFromBytes(new Uint8Array(digest))}`;
}

/**
 * Status lists in memory, with the conditional write and the record of whose each entry is.
 *
 * A subclass may override `getStatusList` and `setStatusList`, to count, log,
 * delay or copy what is stored: the conditional write reads and stores through
 * them. An override that calls the method it overrides keeps the etag this
 * class gives each write. One that keeps its lists elsewhere and never calls
 * `super` gets an etag made from the list it reads, so a write is still made
 * only over the list it was made from, and never creates a list over one that
 * is stored. That holds among the writes made through one instance only: a
 * subclass whose lists other instances or processes also write must implement
 * `getStatusListWithEtag` and `setStatusListIfMatch` itself, over a store that
 * compares and writes in one atomic step.
 *
 * An override of `setStatusList` must not call `setStatusListIfMatch` for the
 * same list. A conditional write stores through `setStatusList` while it holds
 * the list's turn, so the inner conditional write would wait for the outer one
 * to end, and the outer one for it: neither would ever settle.
 *
 * `L` is the type of the lists held, `StatusList2021Credential` unless given: build the store of a
 * manager whose `format` is `BitstringStatusList` as
 * `new MemoryStatusListStorage<BitstringStatusListCredential>()`, and one that holds lists of both
 * formats as `new MemoryStatusListStorage<StatusListCredential>()`.
 */
export class MemoryStatusListStorage<L extends StatusListCredential = StatusList2021Credential>
  implements
    HistoricalStatusListStorageProvider<L>,
    ConditionalStatusListStorageProvider<L>,
    StatusEntryOwnerStorageProvider<L>
{
  private statusLists = new Map<string, L>();
  private versions = new Map<string, L[]>();
  private indexCounters = new Map<string, number>();
  /** The owner of each entry, by `<statusListId>#<index>`. */
  private entryOwners = new Map<string, StatusEntryOwner>();
  /** For each list a write to this class stored, the etag that names that write. */
  private readonly etagsOfStoredLists = new Map<string, string>();
  /** Runs the conditional writes of each list one at a time. */
  private readonly conditionalWriteTurns = new KeyedLock();
  /**
   * Counts every write this store accepts, and is never reset, so no write
   * gets an etag an earlier one had, even after `clear()`.
   */
  private acceptedWriteCount = 0;

  async getStatusList(statusListId: string): Promise<L | null> {
    const value = this.statusLists.get(statusListId);
    return value === undefined ? null : structuredClone(value);
  }

  async setStatusList(statusListId: string, credential: L): Promise<void> {
    this.storeAsNewVersion(statusListId, credential);
  }

  /**
   * The list `getStatusList` reads, with the etag of the write to this class
   * that stored it, or, for a list no write to this class stored, an etag made
   * from the list itself. The etag is taken first, so a write that lands while
   * the list is read pairs an older etag with a newer list, which a
   * conditional write then refuses, and never the other way round.
   */
  async getStatusListWithEtag(statusListId: string): Promise<StoredStatusList<L> | null> {
    const etag = this.etagsOfStoredLists.get(statusListId);
    const credential = await this.getStatusList(statusListId);
    if (credential === null) return null;
    return { credential, etag: etag ?? (await contentEtag(credential)) };
  }

  /**
   * Store `credential` through `setStatusList` only while the stored list is
   * the one `etag` names, or, when `etag` is null, only while `getStatusList`
   * reads no list. Conditional writes of one list run one at a time, each
   * comparing only once the one before it has stored, so the compare-and-set
   * stays atomic even where a subclass's `setStatusList` waits before it
   * stores.
   */
  setStatusListIfMatch(statusListId: string, credential: L, etag: string | null): Promise<boolean> {
    return this.conditionalWriteTurns.run(statusListId, async () => {
      if ((await this.etagOfStoredList(statusListId)) !== etag) return false;
      await this.setStatusList(statusListId, credential);
      return true;
    });
  }

  async allocateIndex(statusListId: string): Promise<number> {
    const current = this.indexCounters.get(statusListId) || 0;
    const allocated = current;
    this.indexCounters.set(statusListId, current + 1);
    return allocated;
  }

  /** Record `owner` for an entry with no record yet, in one step, since nothing is awaited between the check and the write. */
  async setEntryOwnerIfAbsent(statusListId: string, index: number, owner: StatusEntryOwner): Promise<boolean> {
    const key = entryOwnerKey(statusListId, index);
    if (this.entryOwners.has(key)) return false;
    this.entryOwners.set(key, copyOwner(owner));
    return true;
  }

  async setEntryOwner(statusListId: string, index: number, owner: StatusEntryOwner): Promise<void> {
    this.entryOwners.set(entryOwnerKey(statusListId, index), copyOwner(owner));
  }

  async getEntryOwner(statusListId: string, index: number): Promise<StatusEntryOwner | null> {
    const owner = this.entryOwners.get(entryOwnerKey(statusListId, index));
    return owner === undefined ? null : copyOwner(owner);
  }

  getIndexCount(statusListId: string): number {
    return this.indexCounters.get(statusListId) || 0;
  }

  async getStatusListVersion(statusListId: string, version: number): Promise<L | null> {
    if (!Number.isSafeInteger(version) || version < 1) return null;
    const value = this.versions.get(statusListId)?.[version - 1];
    return value === undefined ? null : structuredClone(value);
  }

  async getStatusListVersionCount(statusListId: string): Promise<number> {
    return this.versions.get(statusListId)?.length ?? 0;
  }

  clear(): void {
    this.statusLists.clear();
    this.versions.clear();
    this.indexCounters.clear();
    this.entryOwners.clear();
    this.etagsOfStoredLists.clear();
  }

  getAllStatusListIds(): string[] {
    return Array.from(this.statusLists.keys());
  }

  /**
   * The etag `getStatusListWithEtag` reads for the list stored now, or null
   * when `getStatusList` reads none.
   */
  private async etagOfStoredList(statusListId: string): Promise<string | null> {
    const etag = this.etagsOfStoredLists.get(statusListId);
    if (etag !== undefined) return etag;
    const credential = await this.getStatusList(statusListId);
    return credential === null ? null : contentEtag(credential);
  }

  /** Store a copy of `credential` as the list's newest version, with a new etag. */
  private storeAsNewVersion(statusListId: string, credential: L): void {
    const snapshot = structuredClone(credential);
    this.statusLists.set(statusListId, snapshot);
    this.etagsOfStoredLists.set(statusListId, String(++this.acceptedWriteCount));
    const history = this.versions.get(statusListId) ?? [];
    history.push(snapshot);
    this.versions.set(statusListId, history);
  }
}
