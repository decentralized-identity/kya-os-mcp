/**
 * When registering an already-registered delegation id is a harmless repeat
 * and when it is a conflict — one rule shared by `DelegationGraphManager` and
 * the memory store's atomic path.
 *
 * Internal: not re-exported from the delegation barrel.
 */

import type { CredentialStatus } from '../types/protocol.js';
import type { DelegationNode } from './delegation-graph.js';

/**
 * The first caller-supplied field on which `incoming` differs from the stored
 * node, or `undefined` when registering it again would change nothing.
 *
 * Compared: every field a caller passes to `registerDelegation` — `parentId`,
 * `issuerDid`, `subjectDid`, `credentialStatusId` and `credentialStatus`. An
 * absent field, `undefined` and `null` are the same, since a store that
 * persists nodes may drop or null out any of them. Not compared: `children`,
 * which later registrations of other nodes derive, and `revoked`, which
 * revocation sets. A repeat registration supplies neither, so it must leave
 * both as stored: overwriting them is what read a revoked subtree as live
 * again.
 */
export function registrationConflict(
  stored: DelegationNode,
  incoming: DelegationNode,
): string | undefined {
  if ((stored.parentId ?? null) !== (incoming.parentId ?? null)) return 'parentId';
  if (stored.issuerDid !== incoming.issuerDid) return 'issuerDid';
  if (stored.subjectDid !== incoming.subjectDid) return 'subjectDid';
  if ((stored.credentialStatusId ?? undefined) !== (incoming.credentialStatusId ?? undefined)) {
    return 'credentialStatusId';
  }
  if (!sameStatusEntry(stored.credentialStatus, incoming.credentialStatus)) {
    return 'credentialStatus';
  }
  return undefined;
}

/**
 * Member-wise equality of two status entries, in any member order. Members are
 * compared by value when they are strings, as every standard member is;
 * anything nested compares by identity, so an unusual entry reads as a
 * conflict rather than a repeat.
 */
function sameStatusEntry(
  a: CredentialStatus | null | undefined,
  b: CredentialStatus | null | undefined,
): boolean {
  if (!a || !b) {
    return !a && !b;
  }
  const left = a as unknown as Record<string, unknown>;
  const right = b as unknown as Record<string, unknown>;
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  return [...keys].every((key) => (left[key] ?? undefined) === (right[key] ?? undefined));
}
