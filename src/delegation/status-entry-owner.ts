/**
 * Which delegation each status list entry was allocated to: the optional storage contract that
 * records it, and how `StatusList2021Manager` writes and reads that record.
 *
 * A delegation credential carries its status entry, and whoever signs the credential writes it. An
 * agent that signs a re-delegation can write any entry, another delegation's included, so carrying
 * an entry never makes it the delegation's own. The record kept here does: the operator names the
 * delegation when it allocates the entry, and a delegation graph built with the manager as
 * `statusEntryOwners` registers the entry for no other, and cascading revocation sets and clears
 * it for no other. When that graph removes the delegation, the entry is retired, and no delegation
 * is registered with it again.
 */

import type { CredentialStatus, StatusList2021Credential, StatusListCredential } from '../types/protocol.js';
import { describeOptionValue, describeValue } from '../utils/describe-value.js';
import { parseStatusListIndex } from '../utils/statuslist-bits.js';
import type { StatusListStorageProvider } from './statuslist-storage.js';

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

/** Whose a status list entry is: the record `allocateStatusEntry(purpose, { delegationId })` keeps. */
export interface StatusEntryOwner {
  /** The delegation the entry was allocated to. */
  readonly delegationId: string;
  /**
   * Whether the entry was retired: the delegation was removed from a graph that reads owners, so
   * no delegation, under any id, may be registered with the entry again. Revoking and restoring
   * still read the entry as that delegation's.
   */
  readonly retired: boolean;
}

/** What tells which delegation a status list entry was allocated to. `StatusList2021Manager` is one. */
export interface StatusEntryOwners {
  /**
   * The owner of `credentialStatus`, or `undefined` when none was recorded for it: it was allocated
   * without a `delegationId`, or not yet.
   */
  getStatusEntryOwner(credentialStatus: CredentialStatus): Promise<StatusEntryOwner | undefined>;
  /** Retire `credentialStatus`, keeping its owner; an entry with no owner recorded is left as it is. */
  retireStatusEntry(credentialStatus: CredentialStatus): Promise<void>;
}

/**
 * Optional, stronger storage contract: a provider that also records whose each entry is.
 * `allocateStatusEntry(purpose, { delegationId })` needs it, and throws for a provider without it
 * rather than allocate an entry whose owner it cannot keep. Key the records by the list id exactly
 * as given, and keep them apart from the lists: no write of a list, through `setStatusList` or
 * `setStatusListIfMatch`, may change a record. A list a writer read before an entry was retired,
 * and wrote back after, would otherwise bring the entry back for registration.
 */
export interface StatusEntryOwnerStorageProvider<L extends StatusListCredential = StatusList2021Credential>
  extends StatusListStorageProvider<L> {
  /**
   * Record `owner` for entry `index` of list `statusListId`, which `allocateIndex` just gave, only
   * while no record of that entry exists, retired or not. Resolve true when it recorded `owner`,
   * and false, leaving the record as it is, when one exists. The check and the write MUST be one
   * atomic step for every writer of the store, as a conditional insert or a compare-and-set makes
   * them, so an index `allocateIndex` ever gives twice is refused rather than given a second owner.
   */
  setEntryOwnerIfAbsent(statusListId: string, index: number, owner: StatusEntryOwner): Promise<boolean>;
  /** Rewrite the record of entry `index` of list `statusListId` as `owner`: retired, when its delegation is removed. */
  setEntryOwner(statusListId: string, index: number, owner: StatusEntryOwner): Promise<void>;
  /** The owner recorded for entry `index` of list `statusListId`, or `null` when none was recorded. */
  getEntryOwner(statusListId: string, index: number): Promise<StatusEntryOwner | null>;
}

function recordsOwners(storage: StatusListStorageProvider<StatusListCredential>): storage is StatusEntryOwnerStorageProvider<StatusListCredential> {
  return (
    'setEntryOwnerIfAbsent' in storage &&
    typeof storage.setEntryOwnerIfAbsent === 'function' &&
    'setEntryOwner' in storage &&
    typeof storage.setEntryOwner === 'function' &&
    'getEntryOwner' in storage &&
    typeof storage.getEntryOwner === 'function'
  );
}

/** Whether `value` can tell and retire an entry's owner, as a status list a host wraps or stubs may not. */
export function readsStatusEntryOwners(value: unknown): value is StatusEntryOwners {
  return (
    typeof value === 'object' &&
    value !== null &&
    'getStatusEntryOwner' in value &&
    typeof value.getStatusEntryOwner === 'function' &&
    'retireStatusEntry' in value &&
    typeof value.retireStatusEntry === 'function'
  );
}

/**
 * Records an entry's owner once `allocateIndex` has given its index, only where the entry has no
 * record yet, and throws, recording nothing, where it has one.
 */
export type EntryOwnerRecorder = (statusListId: string, index: number) => Promise<void>;

const RECORD_NOTHING: EntryOwnerRecorder = async () => undefined;

/**
 * How `allocateStatusEntry` records the owner `options` names, decided before it takes an index:
 * a recorder that does nothing when no `delegationId` is given. Throws a `TypeError` for a
 * `delegationId` that is not a non-empty string, and for a storage provider that cannot record it,
 * so no index is taken for an entry whose owner would be lost.
 */
export function entryOwnerRecorder(
  storage: StatusListStorageProvider<StatusListCredential>,
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
        'delegation an entry was allocated to. Implement setEntryOwnerIfAbsent, setEntryOwner and getEntryOwner ' +
        '(StatusEntryOwnerStorageProvider), as MemoryStatusListStorage does, or allocate without a delegationId.',
    );
  }
  return async (statusListId, index) => {
    const recorded: unknown = await storage.setEntryOwnerIfAbsent(statusListId, index, { delegationId, retired: false });
    if (recorded === true) return;
    if (typeof recorded !== 'boolean') {
      throw new TypeError(
        'StatusEntryOwnerStorageProvider.setEntryOwnerIfAbsent must resolve true when it recorded the owner and ' +
          'false when the entry already had one',
      );
    }
    throw new Error(
      `Status list ${describeValue(statusListId)} gave index ${index}, which already has an owner recorded, so no ` +
        'entry was allocated: allocateIndex must give each index once across every manager of the store',
    );
  };
}

/**
 * The delegation `credentialStatus` was allocated to, as `storage` recorded it, or `undefined`.
 * The index is read as the manager reads its own records, so an index written another way names
 * the same entry; one that is neither a decimal string nor a whole number throws.
 */
export async function readEntryOwner(
  storage: StatusListStorageProvider<StatusListCredential>,
  credentialStatus: CredentialStatus,
): Promise<StatusEntryOwner | undefined> {
  if (!recordsOwners(storage)) return undefined;
  const index = parseStatusListIndex(credentialStatus.statusListIndex, { acceptNumber: true });
  const owner = await storage.getEntryOwner(credentialStatus.statusListCredential, index);
  return owner ?? undefined;
}

/** Retire `credentialStatus` in `storage`'s records, keeping its owner, when it has one and is not retired yet. */
export async function retireEntryOwner(
  storage: StatusListStorageProvider<StatusListCredential>,
  credentialStatus: CredentialStatus,
): Promise<void> {
  if (!recordsOwners(storage)) return;
  const index = parseStatusListIndex(credentialStatus.statusListIndex, { acceptNumber: true });
  const owner = await storage.getEntryOwner(credentialStatus.statusListCredential, index);
  if (owner === null || owner.retired) return;
  await storage.setEntryOwner(credentialStatus.statusListCredential, index, { delegationId: owner.delegationId, retired: true });
}
