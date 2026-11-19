/**
 * In-Memory StatusList Storage Provider
 *
 * Memory-based implementation for testing and development.
 * NOT suitable for production (no persistence).
 */

import type { StatusList2021Credential } from '../../types/protocol.js';
import type {
  ConditionalStatusListStorageProvider,
  HistoricalStatusListStorageProvider,
  StoredStatusList,
} from '../statuslist-storage.js';

function clone(credential: StatusList2021Credential): StatusList2021Credential {
  return structuredClone(credential);
}

/**
 * Status lists in memory, with the conditional write.
 *
 * A subclass may override `getStatusList` and `setStatusList`, to count, log,
 * delay or copy what is stored: the conditional write reads and stores through
 * them. Each override must call the method it overrides, since the etag
 * follows the writes that reach this class. A subclass that keeps its lists
 * elsewhere must implement `getStatusListWithEtag` and `setStatusListIfMatch`
 * itself.
 */
export class MemoryStatusListStorage
  implements HistoricalStatusListStorageProvider, ConditionalStatusListStorageProvider
{
  private statusLists = new Map<string, StatusList2021Credential>();
  private versions = new Map<string, StatusList2021Credential[]>();
  private indexCounters = new Map<string, number>();
  readonly #etags = new Map<string, string>();
  /** The last conditional write of each list, which the next one waits for. */
  readonly #conditionalWrites = new Map<string, Promise<void>>();
  /**
   * Counts every write this store accepts, and is never reset, so no write
   * gets an etag an earlier one had, even after `clear()`.
   */
  #writes = 0;

  async getStatusList(statusListId: string): Promise<StatusList2021Credential | null> {
    const value = this.statusLists.get(statusListId);
    return value === undefined ? null : clone(value);
  }

  async setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void> {
    this.#store(statusListId, credential);
  }

  /**
   * The list `getStatusList` reads, with the etag of the write that stored it.
   * The etag is taken first, so a write that lands while the list is read
   * pairs an older etag with a newer list, which a conditional write then
   * refuses, and never the other way round.
   */
  async getStatusListWithEtag(statusListId: string): Promise<StoredStatusList | null> {
    const etag = this.#etags.get(statusListId);
    const credential = await this.getStatusList(statusListId);
    return credential === null || etag === undefined ? null : { credential, etag };
  }

  /**
   * Store `credential` through `setStatusList` only while the stored list is
   * the one `etag` names, or no list is stored when `etag` is null. Conditional
   * writes of one list run one at a time, each comparing only once the one
   * before it has stored, so the compare-and-set stays atomic even where a
   * subclass's `setStatusList` waits before it stores.
   */
  setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean> {
    const previous = this.#conditionalWrites.get(statusListId) ?? Promise.resolve();
    const write = previous.then(async () => {
      if ((this.#etags.get(statusListId) ?? null) !== etag) return false;
      await this.setStatusList(statusListId, credential);
      return true;
    });
    this.#conditionalWrites.set(
      statusListId,
      write.then(
        () => undefined,
        () => undefined,
      ),
    );
    return write;
  }

  async allocateIndex(statusListId: string): Promise<number> {
    const current = this.indexCounters.get(statusListId) || 0;
    const allocated = current;
    this.indexCounters.set(statusListId, current + 1);
    return allocated;
  }

  getIndexCount(statusListId: string): number {
    return this.indexCounters.get(statusListId) || 0;
  }

  async getStatusListVersion(
    statusListId: string,
    version: number,
  ): Promise<StatusList2021Credential | null> {
    if (!Number.isSafeInteger(version) || version < 1) return null;
    const value = this.versions.get(statusListId)?.[version - 1];
    return value === undefined ? null : clone(value);
  }

  async getStatusListVersionCount(statusListId: string): Promise<number> {
    return this.versions.get(statusListId)?.length ?? 0;
  }

  clear(): void {
    this.statusLists.clear();
    this.versions.clear();
    this.indexCounters.clear();
    this.#etags.clear();
  }

  getAllStatusListIds(): string[] {
    return Array.from(this.statusLists.keys());
  }

  /** Store a copy of `credential` as the list's newest version, with a new etag. */
  #store(statusListId: string, credential: StatusList2021Credential): void {
    const snapshot = clone(credential);
    this.statusLists.set(statusListId, snapshot);
    this.#etags.set(statusListId, String(++this.#writes));
    const history = this.versions.get(statusListId) ?? [];
    history.push(snapshot);
    this.versions.set(statusListId, history);
  }
}
