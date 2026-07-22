/**
 * In-Memory StatusList Storage Provider
 *
 * Memory-based implementation for testing and development.
 * NOT suitable for production (no persistence).
 */

import type { StatusList2021Credential } from '../../types/protocol.js';
import type { HistoricalStatusListStorageProvider } from '../statuslist-manager.js';

function clone(credential: StatusList2021Credential): StatusList2021Credential {
  return structuredClone(credential);
}

export class MemoryStatusListStorage implements HistoricalStatusListStorageProvider {
  private statusLists = new Map<string, StatusList2021Credential>();
  private versions = new Map<string, StatusList2021Credential[]>();
  private indexCounters = new Map<string, number>();

  async getStatusList(statusListId: string): Promise<StatusList2021Credential | null> {
    const value = this.statusLists.get(statusListId);
    return value === undefined ? null : clone(value);
  }

  async setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void> {
    const snapshot = clone(credential);
    this.statusLists.set(statusListId, snapshot);
    const history = this.versions.get(statusListId) ?? [];
    history.push(snapshot);
    this.versions.set(statusListId, history);
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
  }

  getAllStatusListIds(): string[] {
    return Array.from(this.statusLists.keys());
  }
}
