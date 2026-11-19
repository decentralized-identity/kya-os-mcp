/**
 * What `CascadingRevocationManager` throws when it leaves a status list entry unchanged that a
 * revocation would set or a restore would clear. It is the operator's error, not a refusal of a
 * credential, so it is no `RefusalError` and carries no refusal code: a host does not pass it to a
 * presenter. Its message quotes each id and entry it names (`describeValue`), since a re-delegation's
 * issuer writes the entry it carries.
 */

import type { CredentialStatus } from '../types/protocol.js';
import { describeValue } from '../utils/describe-value.js';
import type { RevocationEvent } from './cascading-revocation.js';
import { entryKey } from './delegation-status-entry.js';

/**
 * Why an entry was left unchanged:
 *
 * - `allocated-to-another`: the status list manager allocated it to another delegation, one
 *   outside the subtree a revocation reaches, or other than the one a restore restores;
 * - `registered-to-another`: another delegation is registered with it, so clearing it would
 *   restore that delegation too (a graph that reads no owners);
 * - `refused-by-status-list`: the status list manager refused to change it, as it does an entry of
 *   a list it does not issue; `cause` is its error.
 */
export type StatusEntryUnchangedReason = 'allocated-to-another' | 'registered-to-another' | 'refused-by-status-list';

/** A status list entry left unchanged, and the delegation that carries it. */
export interface UnchangedStatusEntry {
  readonly delegationId: string;
  /** The entry the delegation's node holds, with its index in canonical decimal. */
  readonly credentialStatus: CredentialStatus;
  readonly reason: StatusEntryUnchangedReason;
  /** The status list manager's error, for `refused-by-status-list`. */
  readonly cause?: unknown;
}

/**
 * A revocation or restore left a status list entry unchanged. A revocation throws it once it has
 * revoked the whole subtree, with the event of each delegation in `events`: each is revoked in the
 * delegation graph, but a verifier that reads only the status list does not see the revocation of
 * those in `unchanged`. A restore throws it before it changes anything, with no events, and the
 * delegation stays revoked.
 */
export class StatusEntryUnchangedError extends Error {
  override readonly name = 'StatusEntryUnchangedError';

  constructor(
    message: string,
    readonly events: readonly RevocationEvent[],
    readonly unchanged: readonly UnchangedStatusEntry[],
  ) {
    super(message);
  }
}

/** How many entries a message names; `unchanged` holds every one. */
const NAMED_ENTRIES = 5;

const REVOCATION_REASONS: Record<StatusEntryUnchangedReason, string> = {
  'allocated-to-another':
    'it was allocated to a delegation outside the subtree, and setting it would revoke that delegation too',
  'registered-to-another':
    'another delegation outside the subtree is registered with it, and setting it would revoke that delegation too',
  'refused-by-status-list': 'the status list manager refused to set it',
};

const RESTORE_REASONS: Record<StatusEntryUnchangedReason, string> = {
  'allocated-to-another':
    'it was allocated to another delegation, and clearing it would restore that delegation too',
  'registered-to-another':
    'another delegation is registered with it, and clearing it would restore that delegation too',
  'refused-by-status-list': 'the status list manager refused to clear it',
};

function quotedEntry(entry: CredentialStatus): string {
  return describeValue(entryKey(entry));
}

/** The error a revocation of `root` throws for the entries `unchanged` it left, once `events` are done. */
export function revocationLeftUnchanged(
  root: string,
  events: readonly RevocationEvent[],
  unchanged: readonly UnchangedStatusEntry[],
): StatusEntryUnchangedError {
  const one = unchanged.length === 1;
  const named = unchanged
    .slice(0, NAMED_ENTRIES)
    .map(
      ({ delegationId, credentialStatus, reason }) =>
        `entry ${quotedEntry(credentialStatus)} of delegation ${describeValue(delegationId)}, since ` +
        REVOCATION_REASONS[reason],
    );
  const more = unchanged.length - named.length;
  if (more > 0) named.push(`and ${more} more, each in the error's unchanged entries`);
  return new StatusEntryUnchangedError(
    `Revoking delegation ${describeValue(root)} left ${one ? 'one status list entry' : `${unchanged.length} status list entries`} ` +
      `unchanged, so a verifier that reads only the status list does not see ${one ? 'that revocation' : 'those revocations'}: ` +
      `${named.join('; ')}. Each such delegation is revoked in the delegation graph; issue it again with an entry ` +
      'allocated for it.',
    events,
    unchanged,
  );
}

/** The error a restore throws for the entry it left set, before it changes anything. */
export function restoreLeftUnchanged(unchanged: UnchangedStatusEntry): StatusEntryUnchangedError {
  return new StatusEntryUnchangedError(
    `Delegation ${describeValue(unchanged.delegationId)} was not restored: its status list entry ` +
      `${quotedEntry(unchanged.credentialStatus)} was left unchanged, since ${RESTORE_REASONS[unchanged.reason]}. ` +
      'It stays revoked; issue the delegation again with an entry allocated for it.',
    [],
    [unchanged],
  );
}

/** What a revocation that could not record itself says of an entry it left unchanged. */
export function unchangedEntryClause(unchanged: UnchangedStatusEntry): string {
  return (
    `its status list entry ${quotedEntry(unchanged.credentialStatus)} was left unchanged, since ` +
    REVOCATION_REASONS[unchanged.reason]
  );
}
