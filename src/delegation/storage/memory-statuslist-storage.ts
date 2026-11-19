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

export class MemoryStatusListStorage
  implements HistoricalStatusListStorageProvider, ConditionalStatusListStorageProvider
{
  private statusLists = new Map<string, StatusList2021Credential>();
  private versions = new Map<string, StatusList2021Credential[]>();
  private indexCounters = new Map<string, number>();
  private etags = new Map<string, string>();
  /**
   * Counts every write this store accepts, and is never reset, so no write
   * gets an etag an earlier one had, even after `clear()`.
   */
  private writes = 0;

  async getStatusList(statusListId: string): Promise<StatusList2021Credential | null> {
    const value = this.statusLists.get(statusListId);
    return value === undefined ? null : clone(value);
  }

  async setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void> {
    this.store(statusListId, credential);
  }

  async getStatusListWithEtag(statusListId: string): Promise<StoredStatusList | null> {
    const value = this.statusLists.get(statusListId);
    const etag = this.etags.get(statusListId);
    return value === undefined || etag === undefined ? null : { credential: clone(value), etag };
  }

  /**
   * Store `credential` only while the stored list is the one `etag` names, or
   * no list is stored when `etag` is null. The comparison and the write run in
   * one synchronous step, so no other write can land between them.
   */
  async setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean> {
    if ((this.etags.get(statusListId) ?? null) !== etag) return false;
    this.store(statusListId, credential);
    return true;
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
    this.etags.clear();
  }

  getAllStatusListIds(): string[] {
    return Array.from(this.statusLists.keys());
  }

  /** Store a copy of `credential` as the list's newest version, with a new etag. */
  private store(statusListId: string, credential: StatusList2021Credential): void {
    const snapshot = clone(credential);
    this.statusLists.set(statusListId, snapshot);
    this.etags.set(statusListId, String(++this.writes));
    const history = this.versions.get(statusListId) ?? [];
    history.push(snapshot);
    this.versions.set(statusListId, history);
  }
}
