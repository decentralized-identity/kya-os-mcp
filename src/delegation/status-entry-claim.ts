/**
 * Whose a status list entry is: one reading for the delegation graph, which registers a delegation
 * with an entry, and for cascading revocation, which sets and clears it.
 *
 * A graph built with `statusEntryOwners` reads the delegation the status list manager allocated
 * each entry to. It registers a delegation only with an entry allocated to that delegation, and a
 * revocation sets an entry only when that delegation lies in the subtree it revokes, and a
 * restore clears one only for that delegation.
 *
 * A graph built without it cannot tell, and warns once. It refuses an entry another registered
 * delegation holds, when its storage provider can look one up. A revocation always sets the entry,
 * and reports the delegations outside the subtree that hold it too; a restore never clears an entry
 * another delegation holds. The same holds, in a graph built with owners, for an entry whose owner
 * was never recorded.
 *
 * Internal: not re-exported from the delegation barrel, but for {@link StatusEntryClaim}.
 */

import type { CredentialStatus } from '../types/protocol.js';
import { describeValue } from '../utils/describe-value.js';
import { RefusalError } from '../utils/refusal.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import type { DelegationGraphManager } from './delegation-graph.js';
import type { StatusEntryOwners } from './status-entry-owner.js';
import type { StatusEntryUnchangedReason } from './status-entry-unchanged-error.js';

/** Whose a status list entry is, as the delegation graph reads it. */
export interface StatusEntryClaim {
  /**
   * `allocation`: `ids` is the one delegation the status list manager allocated the entry to.
   * `registration`: no owner was recorded, or the graph reads none, and `ids` are the delegations
   * registered with the entry, in any order, or none.
   */
  readonly by: 'allocation' | 'registration';
  readonly ids: readonly string[];
}

/** What a graph reads an entry's claim from. */
export interface StatusEntrySources {
  /** The record of each entry's owner, for a graph built with `statusEntryOwners`. */
  readonly owners?: StatusEntryOwners;
  /** The delegations registered with an entry, or `undefined` when the storage provider cannot look them up. */
  readonly registered: (entry: CredentialStatus) => Promise<readonly string[] | undefined>;
}

/** Whose `entry` is, by `sources`, or `undefined` when nothing can tell. */
export async function readClaim(
  entry: CredentialStatus,
  sources: StatusEntrySources,
): Promise<StatusEntryClaim | undefined> {
  const owner = await sources.owners?.getStatusEntryOwner(entry);
  if (owner !== undefined) return { by: 'allocation', ids: [owner] };
  const ids = await sources.registered(entry);
  return ids === undefined ? undefined : { by: 'registration', ids };
}

const UNWIRED_WARNED = Symbol.for('@kya-os/mcp/status-entry-owners-unwired-warned');

/** Fixed words, so nothing a credential's issuer wrote is ever written into the log line. */
const UNWIRED_WARNING =
  '[kya-os] A delegation was registered with a status list entry by a delegation graph built without ' +
  'statusEntryOwners, so the graph cannot tell which delegation an entry was allocated to. It refuses an entry ' +
  'another registered delegation holds, when its storage provider implements getNodeIdsByStatusEntry, but it ' +
  'cannot refuse an entry allocated and not yet registered, nor the entry of a delegation removed from the ' +
  'graph: a re-delegation that carries such an entry is registered, and revoking or restoring it changes that ' +
  'entry. Allocate each entry with allocateStatusEntry(purpose, { delegationId }) and pass that ' +
  'StatusList2021Manager to the graph as statusEntryOwners, which refuses both.';

/**
 * The refusal of registering `delegationId` with the entry it carries. It reads the same whatever
 * the entry is, so it tells a presenter neither whose the entry is nor whether it is in use.
 */
function registrationRefused(delegationId: string): RefusalError {
  return new RefusalError(
    'delegation_malformed',
    `Delegation ${describeValue(delegationId)} cannot be registered with the status list entry it carries: a ` +
      'delegation must be registered with an entry allocated for it. Allocate one with ' +
      'allocateStatusEntry(purpose, { delegationId }), and register the delegation with that entry.',
  );
}

/**
 * Throw unless `delegationId` may be registered with `entry`: by `sources.owners`, the entry was
 * allocated to it; without them, no other delegation is registered with it.
 */
export async function assertRegistrable(
  delegationId: string,
  entry: CredentialStatus,
  sources: StatusEntrySources,
): Promise<void> {
  if (sources.owners !== undefined) {
    if ((await sources.owners.getStatusEntryOwner(entry)) !== delegationId) throw registrationRefused(delegationId);
    return;
  }
  warnOncePerProcess(UNWIRED_WARNED, UNWIRED_WARNING);
  const registered = await sources.registered(entry);
  if (registered?.some((id) => id !== delegationId)) throw registrationRefused(delegationId);
}

/** How a graph reads claims and walks chains, for cascading revocation. */
type ClaimReader = Pick<DelegationGraphManager, 'getStatusEntryClaim' | 'isAncestor'>;

/** What revoking a delegation does with its entry: leaves it unchanged, or sets it, revoking `sharedWith` too. */
export interface RevocationDecision {
  readonly unchanged?: StatusEntryUnchangedReason;
  readonly sharedWith?: readonly string[];
}

/** The ids of `ids` that are neither `delegationId` nor in the subtree of `root`. */
async function outsideSubtree(
  ids: readonly string[],
  delegationId: string,
  root: string,
  graph: ClaimReader,
): Promise<string[]> {
  const outside: string[] = [];
  for (const id of ids) {
    if (id !== delegationId && !(await graph.isAncestor(root, id))) outside.push(id);
  }
  return outside;
}

/**
 * What a revocation of `root` does with `entry`, the entry of `delegationId` in its subtree. An
 * entry allocated to a delegation outside the subtree is left unchanged. Any other entry is set,
 * and the delegations outside the subtree registered with it are named, since setting it revokes
 * them too.
 */
export async function revocationDecision(
  delegationId: string,
  root: string,
  entry: CredentialStatus,
  graph: ClaimReader,
): Promise<RevocationDecision> {
  const claim = await graph.getStatusEntryClaim(entry);
  if (claim === undefined) return {};
  const outside = await outsideSubtree(claim.ids, delegationId, root, graph);
  if (outside.length === 0) return {};
  return claim.by === 'allocation' ? { unchanged: 'allocated-to-another' } : { sharedWith: outside };
}

/**
 * Why a restore of `delegationId` must leave `entry` set, or `undefined` when it may clear it: the
 * entry is no other delegation's, by allocation or by registration.
 */
export async function restoreRefusal(
  delegationId: string,
  entry: CredentialStatus,
  graph: ClaimReader,
): Promise<StatusEntryUnchangedReason | undefined> {
  const claim = await graph.getStatusEntryClaim(entry);
  if (claim === undefined || claim.ids.every((id) => id === delegationId)) return undefined;
  return claim.by === 'allocation' ? 'allocated-to-another' : 'registered-to-another';
}
