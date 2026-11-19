/**
 * StatusList Storage
 *
 * The store a `StatusList2021Manager` keeps its status lists in, and how the manager writes a
 * list to it.
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

import type { StatusList2021Credential } from '../types/protocol.js';
import { warnOncePerProcess } from '../utils/warn-once.js';

/**
 * Where a `StatusList2021Manager` keeps its status lists.
 *
 * A store with only these methods cannot tell which list a writer read, so the last write wins:
 * it is safe with one manager writing to it. Where more than one manager writes, implement
 * {@link ConditionalStatusListStorageProvider} too.
 */
export interface StatusListStorageProvider {
  getStatusList(statusListId: string): Promise<StatusList2021Credential | null>;
  setStatusList(statusListId: string, credential: StatusList2021Credential): Promise<void>;
  /**
   * The next unused index of the list. Each index MUST be handed out once across every manager of
   * the store, or two credentials share one bit.
   */
  allocateIndex(statusListId: string): Promise<number>;
}

/** Optional immutable-history extension used by audit replay/export adapters. */
export interface HistoricalStatusListStorageProvider extends StatusListStorageProvider {
  getStatusListVersion(
    statusListId: string,
    version: number,
  ): Promise<StatusList2021Credential | null>;
  getStatusListVersionCount(statusListId: string): Promise<number>;
}

/** A status list as a conditional store holds it, with the etag of the write that stored it. */
export interface StoredStatusList {
  readonly credential: StatusList2021Credential;
  /**
   * Names the write that stored `credential`. Any string serves, such as a row version, a counter
   * or an HTTP ETag, as long as every write the store accepts gives the list one it has not had
   * before.
   */
  readonly etag: string;
}

/**
 * The optional conditional write, for a store that more than one manager writes to: two replicas,
 * two serverless instances, or a process that builds a manager per request. A manager over such a
 * store writes a list only over the list it read. When another writer stored the list in between,
 * the store refuses the write, and the manager reads the list again, applies its own change to it,
 * signs it and tries again, so no writer's change is lost. `MemoryStatusListStorage` implements
 * it.
 *
 * Over a store without it a manager reads and writes each list as before, and the last write wins,
 * so use such a store with one manager only. Building a manager over one warns once per process.
 */
export interface ConditionalStatusListStorageProvider extends StatusListStorageProvider {
  /** The list stored under `statusListId` with its etag, or null when none is stored. */
  getStatusListWithEtag(statusListId: string): Promise<StoredStatusList | null>;

  /**
   * Store `credential` under `statusListId` only while the stored list is the one `etag` names,
   * or, when `etag` is null, only while no list is stored. Resolves true when it stored the list
   * and false when it did not. A store that cannot be reached throws, as `setStatusList` does.
   *
   * The comparison and the write MUST be one atomic step for every writer of the store, as a
   * conditional `UPDATE ... WHERE version = ?`, a compare-and-set, or an HTTP `If-Match` (and
   * `If-None-Match: *` for null) make them. A write through `setStatusList` MUST change the etag
   * too.
   */
  setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean>;
}

/**
 * How many times a manager tries to write a list to a conditional store before it gives up. Each
 * refusal means another writer's change to the list landed first, so a write still refused after
 * this many is contention its caller should hear about rather than wait out.
 */
export const STATUS_LIST_WRITE_ATTEMPTS = 10;

/**
 * Thrown by `StatusList2021Manager` when a conditional store refused a write of a list every time
 * it was tried, because another writer stored the list first each time. Nothing stale was stored:
 * this change was not made, and the list keeps every other writer's. Make the change again.
 */
export class StatusListWriteConflictError extends Error {
  readonly code = 'STATUS_LIST_WRITE_CONFLICT' as const;

  constructor(
    readonly statusListId: string,
    readonly attempts: number,
  ) {
    super(
      `Status list ${statusListId} was not written: another writer stored it first each of the ` +
        `${attempts} times it was tried, so this change was not made. Make the change again.`,
    );
    this.name = 'StatusListWriteConflictError';
  }
}

function supportsConditionalWrite(
  storage: StatusListStorageProvider,
): storage is ConditionalStatusListStorageProvider {
  return 'getStatusListWithEtag' in storage &&
    typeof storage.getStatusListWithEtag === 'function' &&
    'setStatusListIfMatch' in storage &&
    typeof storage.setStatusListIfMatch === 'function';
}

/** Where every copy of this package records that the warning about a store with no conditional write was given. */
const UNCONDITIONAL_STORE_WARNED = Symbol.for('@kya-os/mcp/statuslist-unconditional-store-warned');

/** Fixed words, so nothing a store or a caller holds is ever written into the log line. */
const UNCONDITIONAL_STORE_WARNING =
  '[kya-os] StatusList2021Manager was built over a status-list store with no conditional write, so ' +
  'when two managers write one list, as two replicas or a manager built per request do, the last ' +
  "write replaces the other's and a revocation can be lost. Implement getStatusListWithEtag and " +
  'setStatusListIfMatch on the store, as MemoryStatusListStorage does, or write through one manager ' +
  'per store.';

/** Warn once per process when `storage` has no conditional write. */
export function warnUnlessConditional(storage: StatusListStorageProvider): void {
  if (!supportsConditionalWrite(storage)) {
    warnOncePerProcess(UNCONDITIONAL_STORE_WARNED, UNCONDITIONAL_STORE_WARNING);
  }
}

/** What a change to a stored list comes to: the signed list to store, if any, and the answer. */
export interface StatusListChange<T> {
  /** The signed list to store, or none when the stored list stands as it is. */
  readonly write?: StatusList2021Credential;
  readonly result: T;
}

/**
 * Apply `change` to the list `storage` holds under `statusListId`, store the list it gives, and
 * answer what it answered.
 *
 * Over a conditional store the write names the list it was made from. When another writer stored
 * the list first, the store refuses it, and `change` is applied again to the list now stored, so
 * only this writer's own change is added to every change before it. After
 * {@link STATUS_LIST_WRITE_ATTEMPTS} refusals it throws {@link StatusListWriteConflictError}, with
 * nothing stored. Over any other store the list is read and written once, and a write another
 * manager made in between is lost.
 *
 * @throws {TypeError} when the store's `setStatusListIfMatch` resolves to anything but a boolean,
 *   since the write cannot then be known to have been stored or refused.
 */
export async function commitStatusListChange<T>(
  storage: StatusListStorageProvider,
  statusListId: string,
  change: (stored: StatusList2021Credential | null) => Promise<StatusListChange<T>>,
): Promise<T> {
  if (!supportsConditionalWrite(storage)) {
    const { write, result } = await change(await storage.getStatusList(statusListId));
    if (write !== undefined) await storage.setStatusList(statusListId, write);
    return result;
  }

  for (let attempt = 1; attempt <= STATUS_LIST_WRITE_ATTEMPTS; attempt++) {
    const stored = await storage.getStatusListWithEtag(statusListId);
    const { write, result } = await change(stored?.credential ?? null);
    if (write === undefined) return result;
    const written: unknown = await storage.setStatusListIfMatch(statusListId, write, stored?.etag ?? null);
    if (typeof written !== 'boolean') {
      throw new TypeError(
        'ConditionalStatusListStorageProvider.setStatusListIfMatch must resolve true when it stored ' +
          'the list and false when it refused it',
      );
    }
    if (written) return result;
  }
  throw new StatusListWriteConflictError(statusListId, STATUS_LIST_WRITE_ATTEMPTS);
}
