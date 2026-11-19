/**
 * StatusList Checks
 *
 * What a `StatusList2021Manager` holds an entry and a stored list to before it reads or changes a
 * bit: an entry one bit wide, and a list stored under the id it was created with.
 */

import type { CredentialStatus, StatusList2021Credential } from '../types/protocol.js';
import { describeValue } from '../utils/describe-value.js';
import { RefusalError } from '../utils/refusal.js';
import { acceptEntrySize } from '../utils/statuslist-acceptance.js';

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
  statusList: StatusList2021Credential | null,
  statusListId: string
): asserts statusList is StatusList2021Credential {
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
