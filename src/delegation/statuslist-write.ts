/**
 * StatusList Write
 *
 * How a `StatusList2021Manager` writes a change to a list. Over a store without the conditional
 * write the list is read and written once. Over a store with it, a write another writer got in
 * before is refused, and the change is applied again to the list now stored, after a wait that is
 * random and grows with each refusal, up to a bound on how many refusals a change outlasts.
 */

import type { StatusList2021Credential } from '../types/protocol.js';
import { describeOptionValue } from '../utils/describe-value.js';
import { supportsConditionalWrite, type StatusListStorageProvider } from './statuslist-storage.js';

/** How many refused writes a change outlasts by default, before {@link StatusListWriteConflictError}. */
export const DEFAULT_MAX_WRITE_CONFLICTS = 32;

/** The longest wait between two tries of a write, in milliseconds. */
const LONGEST_WRITE_BACKOFF_MS = 100;

/** The options of a `StatusList2021Manager` that say how it retries a refused write. */
export interface StatusListWriteRetryOptions {
  /**
   * How many times a conditional store may refuse the write of one change, because another writer
   * stored the list first, before the manager gives up with {@link StatusListWriteConflictError}:
   * a whole number, 0 or more, so a change is tried at most this many times and once more.
   * Default 32. Any other value throws a `TypeError` naming the option.
   */
  maxWriteConflicts?: number;
  /** Waits `ms` milliseconds before a refused write is tried again. Injectable for tests; defaults to a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** A number from 0 up to 1, which picks each wait. Injectable for tests; defaults to `Math.random`. */
  random?: () => number;
}

/** A retry policy with every option resolved. */
export interface StatusListWriteRetry {
  readonly maxConflicts: number;
  readonly sleep: (ms: number) => Promise<void>;
  readonly random: () => number;
}

function sleepFor(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The retry policy `options` set, with the defaults for what they leave out. Throws a `TypeError`
 * naming the option, as `[kya-os] maxWriteConflicts must be ...`, for a `maxWriteConflicts` that is
 * not a whole number, 0 or more, so a mistyped option fails where the manager is built.
 */
export function writeRetryOf(options: StatusListWriteRetryOptions | undefined): StatusListWriteRetry {
  const maxConflicts: unknown = options?.maxWriteConflicts;
  if (maxConflicts !== undefined && !(Number.isSafeInteger(maxConflicts) && (maxConflicts as number) >= 0)) {
    throw new TypeError(
      `[kya-os] maxWriteConflicts must be a whole number, 0 or more (got ${describeOptionValue(maxConflicts)})`,
    );
  }
  return {
    maxConflicts: (maxConflicts as number | undefined) ?? DEFAULT_MAX_WRITE_CONFLICTS,
    sleep: options?.sleep ?? sleepFor,
    random: options?.random ?? Math.random,
  };
}

/**
 * The wait after the `conflicts`th refusal, in milliseconds: a random part of a delay that doubles
 * from 2 ms up to {@link LONGEST_WRITE_BACKOFF_MS}, so writers that lost one race to the same
 * winner spread out instead of meeting its next write head on.
 */
function backoffMs(conflicts: number, random: () => number): number {
  return random() * Math.min(LONGEST_WRITE_BACKOFF_MS, 2 ** conflicts);
}

/**
 * Thrown by `StatusList2021Manager` when a conditional store refused a write of a list every time
 * it was tried, because another writer stored the list first each time. Nothing stale was stored:
 * this change was not made, and the list keeps every other writer's. Make the change again.
 * `attempts` is how many times it was tried. Tell one from any copy of the package with
 * {@link isStatusListWriteConflict}.
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

/**
 * True for a {@link StatusListWriteConflictError}, told by its `code`, so one thrown by another
 * copy of this package in the process is known too, where `instanceof` is false. Such a change was
 * not made, and making it again is safe.
 */
export function isStatusListWriteConflict(error: unknown): boolean {
  return typeof error === 'object' &&
    error !== null &&
    (error as { code?: unknown }).code === 'STATUS_LIST_WRITE_CONFLICT';
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
 * the list first, the store refuses it, and after a wait `change` is applied again to the list now
 * stored, so only this writer's own change is added to every change before it. After
 * `retry.maxConflicts` refusals it throws {@link StatusListWriteConflictError}, with nothing
 * stored. Over any other store the list is read and written once, and a write another manager
 * made in between is lost.
 *
 * @throws {TypeError} when the store reads a stored list with an etag that is not a string, or is
 *   empty, before anything is written; and when its `setStatusListIfMatch` resolves anything but
 *   a boolean, since the write cannot then be known to have been stored or refused.
 */
export async function commitStatusListChange<T>(
  storage: StatusListStorageProvider,
  statusListId: string,
  change: (stored: StatusList2021Credential | null) => Promise<StatusListChange<T>>,
  retry: StatusListWriteRetry,
): Promise<T> {
  if (!supportsConditionalWrite(storage)) {
    const { write, result } = await change(await storage.getStatusList(statusListId));
    if (write !== undefined) await storage.setStatusList(statusListId, write);
    return result;
  }

  const attempts = retry.maxConflicts + 1;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1) await retry.sleep(backoffMs(attempt - 1, retry.random));
    const stored = (await storage.getStatusListWithEtag(statusListId)) ?? null;
    // A stored list read with no etag would be written as a creation, which a store that inserts
    // or replaces on a null etag would take over the list another writer just stored.
    if (stored !== null && (typeof stored.etag !== 'string' || stored.etag === '')) {
      throw new TypeError(
        'ConditionalStatusListStorageProvider.getStatusListWithEtag must answer a stored list with its etag, ' +
          'a string that is not empty',
      );
    }
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
  throw new StatusListWriteConflictError(statusListId, attempts);
}
