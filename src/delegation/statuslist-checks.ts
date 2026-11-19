/**
 * StatusList Checks
 *
 * What a `StatusList2021Manager` holds an entry and a stored list to before it reads or changes a
 * bit, or allocates an entry: an entry one bit wide, a list stored under the id it was created
 * with, and a list of the format the manager allocates entries in.
 */

import type { CredentialStatus, StatusListCredential } from '../types/protocol.js';
import { describeValue } from '../utils/describe-value.js';
import { RefusalError } from '../utils/refusal.js';
import { acceptEntrySize } from '../utils/statuslist-acceptance.js';
import type { StatusListFormat } from '../utils/statuslist-format.js';
import { storedFormatOf } from './statuslist-terms.js';

/**
 * Throw unless `credentialStatus` is one bit wide, as the shared rule decides it
 * ({@link acceptEntrySize}). The manager reads and writes the bit at an entry's index, and an entry
 * of another `statusSize` keeps its status in other bits, so the bit at its index is another
 * entry's. It throws before any list is read from storage.
 */
export function assertOneBitEntry(credentialStatus: CredentialStatus): void {
  const size = acceptEntrySize(credentialStatus.statusSize);
  if (!size.valid) {
    throw new RefusalError('delegation_malformed', size.reason);
  }
}

/**
 * Throw unless `statusList` is a list stored under `statusListId` with that id: an `Error` when none
 * is stored, and a `RefusalError` of code `delegation_malformed` when the list stored there was
 * created under another id, which a storage provider that reads two spellings of a URL as one list
 * hands back, so that no entry of it is changed through the other spelling.
 */
export function assertStoredUnder(
  statusList: StatusListCredential | null,
  statusListId: string
): asserts statusList is StatusListCredential {
  if (!statusList) {
    throw new Error(`Status list not found: ${statusListId}`);
  }
  if (statusList.id !== statusListId) {
    throw new RefusalError(
      'delegation_malformed',
      `Status list ${describeValue(statusListId)} reads as the list ${describeValue(statusList.id)}, so no ` +
        'entry of it is set or cleared: an entry names its list by the id the list was created with'
    );
  }
}

/**
 * Throw a `TypeError` unless `statusList`, the list stored under `statusListId`, is of `format`,
 * the format of the entries the manager allocates. Each specification has an entry name a list of
 * its own: Bitstring Status List v1.0 §2.1 has the credential a `BitstringStatusListEntry` names
 * "express a type property that includes the BitstringStatusListCredential value", so an entry
 * allocated on a list of the other format would name a list no verifier of its own format reads.
 */
export function assertAllocatedIn(statusList: StatusListCredential, format: StatusListFormat, statusListId: string): void {
  const stored = storedFormatOf(statusList);
  if (stored !== format) {
    throw new TypeError(
      `[kya-os] Status list ${statusListId} is a ${stored}, and this manager allocates the entries of a ${format}: ` +
        `set format to "${stored}", or give the manager a statusListBaseUrl of its own`
    );
  }
}
