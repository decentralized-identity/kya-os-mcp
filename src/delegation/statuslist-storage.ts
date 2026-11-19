/**
 * StatusList Storage
 *
 * The store a `StatusList2021Manager` keeps its status lists in.
 *
 * Every change to a list reads the whole list, sets or clears one bit, signs the list again and
 * writes the whole list back. A manager serialises its own changes, but it cannot see another
 * manager's: two managers over one store, as two replicas, two serverless instances, or a process
 * that builds a manager per request have, can each read the same list, and the second write then
 * replaces the first and loses its change. A store that implements the conditional write
 * ({@link ConditionalStatusListStorageProvider}) refuses a write over a list that changed since
 * the writer read it, and the manager applies its own change again to the list now stored. A store
 * that does not is safe only with one manager writing to it.
 */

import type { StatusList2021Credential, StatusListCredential } from '../types/protocol.js';

/**
 * Where a `StatusList2021Manager` keeps its status lists.
 *
 * A store with only these methods cannot tell which list a writer read, so the last write wins:
 * it is safe with one manager writing to it. Where more than one manager writes, implement
 * {@link ConditionalStatusListStorageProvider} too.
 *
 * `L` is the type of the lists the store holds, here and on every other store contract. It
 * defaults to `StatusList2021Credential`, the lists a manager writes unless its `format` says
 * otherwise, so a store written before the manager had a `format` compiles as it is. Type a store
 * that holds the lists of a manager built with `format: 'BitstringStatusList'` with
 * `BitstringStatusListCredential`, and one that holds lists of both formats with
 * `StatusListCredential`. A manager takes a store typed for either format or for both.
 */
export interface StatusListStorageProvider<L extends StatusListCredential = StatusList2021Credential> {
  getStatusList(statusListId: string): Promise<L | null>;
  setStatusList(statusListId: string, credential: L): Promise<void>;
  /**
   * The next unused index of the list. Each index MUST be handed out once across every manager of
   * the store, or two credentials share one bit.
   */
  allocateIndex(statusListId: string): Promise<number>;
}

/** Optional immutable-history extension used by audit replay/export adapters. */
export interface HistoricalStatusListStorageProvider<L extends StatusListCredential = StatusList2021Credential>
  extends StatusListStorageProvider<L> {
  getStatusListVersion(statusListId: string, version: number): Promise<L | null>;
  getStatusListVersionCount(statusListId: string): Promise<number>;
}

/** A status list as a conditional store holds it, with the etag of the write that stored it. */
export interface StoredStatusList<L extends StatusListCredential = StatusList2021Credential> {
  readonly credential: L;
  /**
   * Names the write that stored `credential`: a string that is not empty, and that no other write
   * of this `statusListId` has had or will have, even after the list is deleted and stored again.
   * Otherwise a writer that read an old list could match a new one and replace it. Draw it from a
   * sequence that never resets, or make it a random UUID; a version column that starts again when
   * its row is created again repeats. A strong hash of the stored bytes, such as their SHA-256, is
   * safe too: it repeats only where the bytes do, and a write over a list identical to the one read
   * replaces nothing another writer stored. An object store's own ETag, which S3 and R2 compare
   * with `If-Match`, qualifies on the same ground, as does a GCS object's generation number, which
   * `ifGenerationMatch` compares.
   */
  readonly etag: string;
}

/**
 * The optional conditional write, for a store that more than one manager writes to: two replicas,
 * two serverless instances, or a process that builds a manager per request. A manager over such a
 * store writes a list only over the list it read. When another writer stored the list in between,
 * the store refuses the write, and the manager waits a moment, reads the list again, applies its
 * own change to it, signs it and tries again, so no writer's change is lost. That holds once every
 * writer of the store writes this way: a writer that still writes through `setStatusList`, as one
 * on 1.25.0 or earlier does, can replace a list another writer stored. `MemoryStatusListStorage`
 * implements it.
 *
 * Over a store without it a manager reads and writes each list as before, and the last write wins,
 * so use such a store with one manager only. The first write a manager makes to one warns once per
 * process.
 */
export interface ConditionalStatusListStorageProvider<L extends StatusListCredential = StatusList2021Credential>
  extends StatusListStorageProvider<L> {
  /**
   * The list stored under `statusListId` with its etag, or null when none is stored. It MUST read
   * where `setStatusListIfMatch` checks the etag, such as a database's primary rather than a
   * replica that may lag it, or a writer keeps reading an old list and every write it makes is
   * refused.
   */
  getStatusListWithEtag(statusListId: string): Promise<StoredStatusList<L> | null>;

  /**
   * Store `credential` under `statusListId` only while the stored list is the one `etag` names,
   * or, when `etag` is null, only while no list is stored. Resolves true when it stored the list
   * and false when it did not. A store that cannot be reached throws, as `setStatusList` does.
   *
   * The comparison and the write MUST be one atomic step for every writer of the store, as a
   * conditional `UPDATE ... WHERE etag = ?`, a compare-and-set, or an HTTP `If-Match` (and
   * `If-None-Match: *` for null) make them. A write through `setStatusList` MUST change the etag
   * too.
   */
  setStatusListIfMatch(statusListId: string, credential: L, etag: string | null): Promise<boolean>;
}

/** Whether `storage` implements the conditional write: both of its methods. */
export function supportsConditionalWrite<L extends StatusListCredential>(
  storage: StatusListStorageProvider<L>,
): storage is ConditionalStatusListStorageProvider<L> {
  return 'getStatusListWithEtag' in storage &&
    typeof storage.getStatusListWithEtag === 'function' &&
    'setStatusListIfMatch' in storage &&
    typeof storage.setStatusListIfMatch === 'function';
}
