/**
 * Whose a status list entry is, as the delegation graph and cascading revocation read it: one rule
 * for registering a delegation with an entry, and for setting and clearing the entry's bit.
 *
 * An entry belongs to the delegation the status list manager allocated it to, when the manager
 * recorded one (`allocateStatusEntry(purpose, { delegationId })`). Otherwise it belongs to each
 * delegation the graph has registered with it, when the graph's storage provider can look them up.
 * With neither record nothing says whose the entry is, so it is taken, as before, for the
 * delegation that carries it, and the operator is warned once.
 *
 * A delegation may be registered with an entry, and restored, only when the entry is no other
 * delegation's. A revocation sets an entry only when every delegation the entry belongs to lies in
 * the subtree it revokes, so revoking a delegation never revokes one outside that subtree.
 *
 * Internal: not re-exported from the delegation barrel.
 */

import type { CredentialStatus } from '../types/protocol.js';
import { RefusalError } from '../utils/refusal.js';
import { warnOncePerProcess } from '../utils/warn-once.js';
import type { DelegationGraphManager } from './delegation-graph.js';
import { entryKey } from './delegation-status-entry.js';
import type { StatusEntryOwners } from './status-entry-owner.js';

/** The records that say whose an entry is. */
export interface StatusEntryRecords {
  /** The status list manager's record of the delegation each entry was allocated to, when there is one. */
  readonly owners?: StatusEntryOwners;
  /** The graph, which looks up the delegations registered with an entry and walks their chains. */
  readonly graph: Pick<DelegationGraphManager, 'getDelegationIdsByStatusEntry' | 'isAncestor'>;
}

/** How whose an entry is was read: from the owner recorded at allocation, or from the graph's registrations. */
type ClaimSource = 'allocation' | 'registration';

/** The delegations an entry belongs to, and how that was read. */
interface Claim {
  readonly ids: readonly string[];
  readonly by: ClaimSource;
}

/** An entry a revocation left unchanged, since it belongs to a delegation the revocation does not reach. */
export interface UnsetEntry {
  readonly delegationId: string;
  readonly key: string;
  readonly by: ClaimSource;
  /** The delegation the revocation was asked for, whose subtree it reaches. */
  readonly root: string;
}

const OWNERS_UNKNOWN_WARNED = Symbol.for('@kya-os/mcp/status-entry-owners-unknown-warned');

/** Fixed words, so nothing a credential's issuer wrote is ever written into the log line. */
const OWNERS_UNKNOWN_WARNING =
  '[kya-os] A status list entry was registered, set or cleared with no record of whose it is: the status list ' +
  'manager recorded no owner for it, and the delegation graph storage provider cannot look up the delegations ' +
  'registered with it. The entry a delegation carries was taken as its own, so a re-delegation that names ' +
  "another delegation's entry can revoke or restore that delegation. Allocate each entry with " +
  'allocateStatusEntry(purpose, { delegationId }), or implement getNodeIdsByStatusEntry in the graph storage ' +
  'provider, as MemoryDelegationGraphStorage does.';

async function claimOf(entry: CredentialStatus, records: StatusEntryRecords): Promise<Claim | undefined> {
  const owner = await records.owners?.getStatusEntryOwner(entry);
  if (owner !== undefined) return { ids: [owner], by: 'allocation' };
  const registered = await records.graph.getDelegationIdsByStatusEntry(entry);
  if (registered !== undefined) return { ids: registered, by: 'registration' };
  warnOncePerProcess(OWNERS_UNKNOWN_WARNED, OWNERS_UNKNOWN_WARNING);
  return undefined;
}

/** Whether `entry`, by `records`, is a delegation's other than `delegationId`, and how that was read. */
async function otherClaim(
  delegationId: string,
  entry: CredentialStatus,
  records: StatusEntryRecords,
): Promise<ClaimSource | undefined> {
  const claim = await claimOf(entry, records);
  return claim?.ids.some((id) => id !== delegationId) ? claim.by : undefined;
}

function anotherDelegation(by: ClaimSource): string {
  return by === 'allocation' ? 'was allocated to another delegation' : 'is registered to another delegation';
}

function outsideSubtree(by: ClaimSource, root: string): string {
  const verb = by === 'allocation' ? 'was allocated to' : 'is registered to';
  return `${verb} a delegation outside the subtree of ${root}`;
}

/**
 * The refusal of registering `delegationId` with the entry of key `key`, which `by` says is
 * another delegation's. The memory store's atomic path throws it too.
 */
export function registrationRefused(delegationId: string, key: string, by: ClaimSource): RefusalError {
  return new RefusalError(
    'delegation_malformed',
    `Delegation ${delegationId} cannot be registered with status list entry ${key}: the entry ` +
      `${anotherDelegation(by)}, and revoking or restoring either delegation would change the other's status. ` +
      'Register each delegation with an entry allocated for it, from allocateStatusEntry(purpose, { delegationId }).',
  );
}

/** Throw unless `delegationId` may be registered with `entry`: the entry is no other delegation's. */
export async function assertRegistrable(
  delegationId: string,
  entry: CredentialStatus,
  records: StatusEntryRecords,
): Promise<void> {
  const by = await otherClaim(delegationId, entry, records);
  if (by !== undefined) throw registrationRefused(delegationId, entryKey(entry), by);
}

/**
 * Throw unless restoring `delegationId` may clear `entry`: the entry is no other delegation's, so
 * clearing it restores no delegation but this one.
 */
export async function assertRestorable(
  delegationId: string,
  entry: CredentialStatus,
  records: StatusEntryRecords,
): Promise<void> {
  const by = await otherClaim(delegationId, entry, records);
  if (by === undefined) return;
  throw new RefusalError(
    'delegation_malformed',
    `Delegation ${delegationId} was not restored: its status list entry ${entryKey(entry)} ${anotherDelegation(by)}, ` +
      "and clearing it would restore that delegation's status too. It stays revoked; issue the delegation again " +
      'with an entry allocated for it.',
  );
}

/**
 * Why a revocation of `root` must leave `entry`, the entry of `delegationId` in its subtree,
 * unchanged, or `undefined` when it may set it: every delegation the entry belongs to lies in the
 * subtree of `root`. The delegation being revoked lies there, so an entry that is its alone costs
 * no walk up the graph.
 */
export async function entryLeftUnset(
  delegationId: string,
  root: string,
  entry: CredentialStatus,
  records: StatusEntryRecords,
): Promise<UnsetEntry | undefined> {
  const claim = await claimOf(entry, records);
  if (claim === undefined) return undefined;
  for (const id of claim.ids) {
    if (id !== delegationId && !(await records.graph.isAncestor(root, id))) {
      return { delegationId, key: entryKey(entry), by: claim.by, root };
    }
  }
  return undefined;
}

/** What a revocation that could not record itself says of an entry it left unchanged. */
export function unsetEntryClause(unset: UnsetEntry): string {
  return `its status list entry ${unset.key} ${outsideSubtree(unset.by, unset.root)}, so it was left unchanged`;
}

/**
 * The refusal a revocation throws once it has revoked every delegation of the subtree, for the
 * entries `unset` it left unchanged, or `undefined` when it left none. Each such delegation is
 * revoked in the graph alone.
 */
export function entriesLeftUnset(unset: readonly UnsetEntry[]): RefusalError | undefined {
  const [first] = unset;
  if (first === undefined) return undefined;
  if (unset.length === 1) {
    return new RefusalError(
      'delegation_malformed',
      `Delegation ${first.delegationId} is revoked in the delegation graph, but its status list entry ${first.key} ` +
        `was left unchanged: the entry ${outsideSubtree(first.by, first.root)}, and setting it would revoke that ` +
        'delegation too. A verifier that reads only the status list does not see this revocation; issue the ' +
        'delegation again with an entry allocated for it.',
    );
  }
  const named = unset.map(({ delegationId, key }) => `${delegationId} (${key})`);
  return new RefusalError(
    'delegation_malformed',
    `Delegations ${named.slice(0, -1).join(', ')} and ${named[named.length - 1]} are revoked in the delegation ` +
      'graph, but their status list entries were left unchanged: each entry belongs to a delegation outside the ' +
      `subtree of ${first.root}, and setting it would revoke that delegation too. A verifier that reads only the ` +
      'status list does not see these revocations; issue each delegation again with an entry allocated for it.',
  );
}
