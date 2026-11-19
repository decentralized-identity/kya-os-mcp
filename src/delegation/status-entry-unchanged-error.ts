/**
 * What `CascadingRevocationManager` throws when it leaves a status list entry unchanged that a
 * revocation would set or a restore would clear. It is the operator's error, not a refusal of a
 * credential, so it is no `RefusalError` and carries no refusal code: a host does not pass it to a
 * presenter. Its message quotes each id and entry it names (`describeValue`), since a re-delegation's
 * issuer writes the entry it carries. A revocation that also could not mark a delegation throws
 * `RevocationStalledError` instead, a transient `RefusalError` the caller retries, which carries the
 * entries left unchanged with the rest of the walk's reports.
 */

import type { CredentialStatus } from '../types/protocol.js';
import { describeTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { RefusalError } from '../utils/refusal.js';
import { NODE_TURN_WAIT_MS } from './graph-node-turns.js';
import type { RevocationEvent } from './cascading-revocation.js';
import { entryKey } from './delegation-status-entry.js';

/**
 * Why an entry was left unchanged:
 *
 * - `allocated-to-another`: the status list manager allocated it to another delegation, one
 *   outside the subtree a revocation reaches, or other than the one a restore restores;
 * - `registered-to-another`: another delegation is registered with it, so clearing it would
 *   restore that delegation too;
 * - `unreadable-entry`: the entry the node stores names no bit, as an index no list can hold,
 *   stored before entries were checked, does; `cause` is the refusal;
 * - `status-list-error`: the status list manager could not change it, as for an index past the end
 *   of its list, a list it never created, or an entry that names its list by another spelling;
 *   `cause` is its error.
 */
export type StatusEntryUnchangedReason =
  | 'allocated-to-another'
  | 'registered-to-another'
  | 'unreadable-entry'
  | 'status-list-error';

/** A status list entry left unchanged, and the delegation that carries it. */
export interface UnchangedStatusEntry {
  readonly delegationId: string;
  /** The entry the delegation's node holds, with its index in canonical decimal; absent for `unreadable-entry`. */
  readonly credentialStatus?: CredentialStatus;
  readonly reason: StatusEntryUnchangedReason;
  /** The error behind `unreadable-entry` and `status-list-error`. */
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
  'unreadable-entry': 'the entry it stores cannot be read',
  'status-list-error': 'the status list manager could not set it',
};

const RESTORE_REASONS: Record<StatusEntryUnchangedReason, string> = {
  'allocated-to-another':
    'it was allocated to another delegation, and clearing it would restore that delegation too',
  'registered-to-another':
    'another delegation is registered with it, and clearing it would restore that delegation too',
  'unreadable-entry': 'the entry it stores cannot be read',
  'status-list-error': 'the status list manager could not clear it',
};

/** How a message names the entry of `unchanged`: quoted, or as unread. */
function namedEntry(unchanged: UnchangedStatusEntry): string {
  return unchanged.credentialStatus === undefined
    ? 'entry'
    : `entry ${describeValue(entryKey(unchanged.credentialStatus))}`;
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
      (entry) =>
        `${namedEntry(entry)} of delegation ${describeValue(entry.delegationId)}, since ` +
        REVOCATION_REASONS[entry.reason],
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
    `Delegation ${describeValue(unchanged.delegationId)} was not restored: its status list ` +
      `${namedEntry(unchanged)} was left unchanged, since ${RESTORE_REASONS[unchanged.reason]}. ` +
      'It stays revoked; issue the delegation again with an entry allocated for it.',
    [],
    [unchanged],
  );
}

/** A delegation whose revocation nothing recorded: its graph mark was dropped, and its entry not set. */
export interface UnrecordedRevocation {
  readonly delegationId: string;
  /** Its entry, when it has one, left unchanged. */
  readonly unchanged?: UnchangedStatusEntry;
}

/**
 * The error of a revocation the graph storage provider did not record: `first` says why of the
 * first such delegation, and `more` counts the others of the subtree.
 */
export function revocationNotRecorded(first: UnrecordedRevocation, more: number): Error {
  const why =
    first.unchanged === undefined
      ? 'it has no status list entry'
      : `its status list ${namedEntry(first.unchanged)} was left unchanged, since ${REVOCATION_REASONS[first.unchanged.reason]}`;
  const others =
    more === 0
      ? ''
      : more === 1
        ? ' The revocation of one more delegation of the subtree was not recorded either.'
        : ` The revocations of ${more} more delegations of the subtree were not recorded either.`;
  return new Error(
    `Revocation of delegation ${describeValue(first.delegationId)} was not recorded: ${why}, and the graph storage ` +
      'provider did not persist DelegationNode.revoked, the only record of a revocation that sets no status list ' +
      `entry. A DelegationGraphStorageProvider must store the revoked field.${others}`,
  );
}

/** What a revocation of a subtree did, as the error it throws when it did not land in full carries it. */
export interface RevocationReports {
  /** The event of each delegation whose revocation landed: marked in the graph, or set on its status list. */
  readonly events: readonly RevocationEvent[];
  /** Each delegation the revocation could not mark, since its turn at the node did not come. */
  readonly stalled: readonly string[];
  /** Each revocation the graph storage provider did not record, with no status list entry set for it. */
  readonly unrecorded: readonly UnrecordedRevocation[];
  /** Each status list entry the revocation left unchanged. */
  readonly unchanged: readonly UnchangedStatusEntry[];
}

/**
 * A revocation that could not mark every delegation of its subtree in the graph, since another
 * change to a node did not finish in time: a transient `deadline_exceeded`, so the caller revokes
 * again. It carries every report of the walk, which went on past each such node.
 */
export class RevocationStalledError extends RefusalError implements RevocationReports {
  override readonly name = 'RevocationStalledError';
  readonly events: readonly RevocationEvent[];
  readonly stalled: readonly string[];
  readonly unrecorded: readonly UnrecordedRevocation[];
  readonly unchanged: readonly UnchangedStatusEntry[];

  constructor(message: string, reports: RevocationReports) {
    super('deadline_exceeded', message);
    this.events = reports.events;
    this.stalled = reports.stalled;
    this.unrecorded = reports.unrecorded;
    this.unchanged = reports.unchanged;
  }
}

/**
 * The error of a revocation of `root` that could not mark the delegations `reports.stalled` names
 * in the graph, the first of them named in its message. Every other delegation of the subtree is
 * marked.
 */
export function revocationStalled(root: string, reports: RevocationReports): RevocationStalledError {
  const [first, ...rest] = reports.stalled;
  const more = rest.length;
  const others =
    more === 0
      ? ''
      : more === 1
        ? ' One more delegation of the subtree was not marked either.'
        : ` ${more} more delegations of the subtree were not marked either.`;
  return new RevocationStalledError(
    `Revocation of delegation ${describeValue(root)} did not land in full: delegation ${describeValue(first)} was not ` +
      'marked revoked, since another change to its node in the graph did not finish within ' +
      `${describeTimeout(NODE_TURN_WAIT_MS)}.${others} Revoke delegation ${describeValue(root)} again`,
    reports,
  );
}
