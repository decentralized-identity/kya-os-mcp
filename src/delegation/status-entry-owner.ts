/**
 * Which delegation each status list entry was allocated to: the optional storage contract that
 * records it, and how `StatusList2021Manager` writes and reads that record.
 *
 * A delegation credential carries its status entry, and whoever signs the credential writes it. An
 * agent that signs a re-delegation can write any entry, another delegation's included, so carrying
 * an entry never makes it the delegation's own. The record kept here does: the operator names the
 * delegation when it allocates the entry, and a delegation graph built with the manager as
 * `statusEntryOwners` registers the entry for no other, and cascading revocation sets and clears
 * it for no other.
 */

import type { CredentialStatus } from '../types/protocol.js';
import { describeOptionValue } from '../utils/describe-value.js';
import { parseStatusListIndex } from '../utils/statuslist-bits.js';
import type { StatusListStorageProvider } from './statuslist-manager.js';

/** Options of `StatusList2021Manager.allocateStatusEntry`. */
export interface StatusEntryAllocationOptions {
  /**
   * The id the delegation the entry is for is registered under in the delegation graph. The
   * manager records the entry as that delegation's, and a graph built with the manager as
   * `statusEntryOwners` then registers it for no other. Choose the id as the operator, the one you
   * register the delegation under: never read it from the credential a presenter submits, whose
   * signer could then name any delegation's id. Needs a storage provider that can record it
   * ({@link StatusEntryOwnerStorageProvider}); `MemoryStatusListStorage` can.
   */
  delegationId?: string;
}

/** What tells which delegation a status list entry was allocated to. `StatusList2021Manager` is one. */
export interface StatusEntryOwners {
  /**
   * The id of the delegation `credentialStatus` was allocated to, or `undefined` when no owner was
   * recorded for it: it was allocated without a `delegationId`, or not yet, or is not an entry of
   * a list this manager issues, by that list's exact id.
   */
  getStatusEntryOwner(credentialStatus: CredentialStatus): Promise<string | undefined>;
}

/**
 * Optional, stronger storage contract: a provider that also records which delegation each entry
 * was allocated to. `allocateStatusEntry(purpose, { delegationId })` needs it, and throws for a
 * provider without it rather than allocate an entry whose owner it cannot keep.
 */
export interface StatusEntryOwnerStorageProvider extends StatusListStorageProvider {
  /**
   * Record that entry `index` of list `statusListId` was allocated to `delegationId`. Called once
   * per entry, after `allocateIndex` gave the index, so the record never needs to change.
   */
  setEntryOwner(statusListId: string, index: number, delegationId: string): Promise<void>;
  /** The delegation entry `index` of list `statusListId` was allocated to, or `null` when none was recorded. */
  getEntryOwner(statusListId: string, index: number): Promise<string | null>;
}

function recordsOwners(storage: StatusListStorageProvider): storage is StatusEntryOwnerStorageProvider {
  return (
    'setEntryOwner' in storage &&
    typeof storage.setEntryOwner === 'function' &&
    'getEntryOwner' in storage &&
    typeof storage.getEntryOwner === 'function'
  );
}

/** Whether `value` can tell an entry's owner, as a status list a host wraps or stubs may not. */
export function readsStatusEntryOwners(value: unknown): value is StatusEntryOwners {
  return (
    typeof value === 'object' &&
    value !== null &&
    'getStatusEntryOwner' in value &&
    typeof value.getStatusEntryOwner === 'function'
  );
}

/** Records an entry's owner once `allocateIndex` has given its index. */
export type EntryOwnerRecorder = (statusListId: string, index: number) => Promise<void>;

const RECORD_NOTHING: EntryOwnerRecorder = async () => undefined;

/**
 * How `allocateStatusEntry` records the owner `options` names, decided before it takes an index:
 * a recorder that does nothing when no `delegationId` is given. Throws a `TypeError` for a
 * `delegationId` that is not a non-empty string, and for a storage provider that cannot record it,
 * so no index is taken for an entry whose owner would be lost.
 */
export function entryOwnerRecorder(
  storage: StatusListStorageProvider,
  options: StatusEntryAllocationOptions | undefined,
): EntryOwnerRecorder {
  const delegationId: unknown = options?.delegationId;
  if (delegationId === undefined) return RECORD_NOTHING;
  if (typeof delegationId !== 'string' || delegationId === '') {
    throw new TypeError(
      `allocateStatusEntry was given ${describeOptionValue(delegationId)} as delegationId: it must be a non-empty ` +
        'string, the id the delegation is registered under in the delegation graph',
    );
  }
  if (!recordsOwners(storage)) {
    throw new TypeError(
      'allocateStatusEntry was given a delegationId, but the status list storage provider cannot record which ' +
        'delegation an entry was allocated to. Implement setEntryOwner and getEntryOwner ' +
        '(StatusEntryOwnerStorageProvider), as MemoryStatusListStorage does, or allocate without a delegationId.',
    );
  }
  return (statusListId, index) => storage.setEntryOwner(statusListId, index, delegationId);
}

/**
 * The delegation `credentialStatus` was allocated to, as `storage` recorded it, or `undefined`.
 * The index is read as the manager reads its own records, so an index written another way names
 * the same entry; one that is neither a decimal string nor a whole number throws.
 */
export async function readEntryOwner(
  storage: StatusListStorageProvider,
  credentialStatus: CredentialStatus,
): Promise<string | undefined> {
  if (!recordsOwners(storage)) return undefined;
  const index = parseStatusListIndex(credentialStatus.statusListIndex, { acceptNumber: true });
  const owner = await storage.getEntryOwner(credentialStatus.statusListCredential, index);
  return owner ?? undefined;
}
