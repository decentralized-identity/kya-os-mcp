/**
 * The status list entry behind a delegation graph node — one reading shared by
 * cascading revocation, which flips and reads it, and by the graph, which
 * refuses an entry another delegation holds.
 *
 * Internal: only {@link statusEntryKey}, which a storage provider indexes nodes
 * by, is re-exported, through `delegation-graph.ts`.
 */

import type { CredentialStatus } from '../types/protocol.js';
import { parseStatusListIndex } from '../utils/statuslist-bits.js';
import type { DelegationNode } from './delegation-graph.js';

/** `<statusListCredential>#<index>`, the form the status list manager mints. */
const STATUS_ENTRY_ID = /^(.+)#(\d+)$/;

/**
 * Read a legacy `credentialStatusId` as a revocation status list entry, or
 * `undefined` when it does not name a list and an index. A W3C
 * `credentialStatus.id` may be any URI (`urn:uuid:…`, say); such a node has no
 * bit to flip, and the graph's own `revoked` mark carries its revocation. An
 * index past the safe integer range throws: it names an entry, just not one
 * any list can hold, so it must not read as "no entry".
 */
export function parseCredentialStatusId(credentialStatusId: string): CredentialStatus | undefined {
  const match = STATUS_ENTRY_ID.exec(credentialStatusId);
  if (!match) {
    return undefined;
  }
  const [, statusListCredential, index] = match;
  return {
    id: credentialStatusId,
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: String(parseStatusListIndex(index!)),
    statusListCredential: statusListCredential!,
  };
}

/**
 * The node's status list entry: the structured `credentialStatus` when stored,
 * else the parsed legacy `credentialStatusId`, else `undefined` (no entry).
 * A stored entry is the operator's own record, so its index is read as
 * `StatusList2021Manager.updateStatus` reads one: a storage layer may hand it
 * back as a whole number, and the entry then names it as a decimal string. An
 * index that is neither throws.
 */
export function nodeStatusEntry(node: DelegationNode): CredentialStatus | undefined {
  if (node.credentialStatus) {
    return canonicalStatusEntry(node.credentialStatus);
  }
  return node.credentialStatusId ? parseCredentialStatusId(node.credentialStatusId) : undefined;
}

/**
 * `entry` with its index read as the operator's own record is read (see
 * {@link nodeStatusEntry}) and written in canonical decimal, so two ways of
 * writing one index name one entry. An index that is neither throws.
 */
export function canonicalStatusEntry(entry: CredentialStatus): CredentialStatus {
  const index = parseStatusListIndex(entry.statusListIndex, { acceptNumber: true });
  return { ...entry, statusListIndex: String(index) };
}

/**
 * The key of a canonical entry ({@link canonicalStatusEntry}):
 * `<statusListCredential>#<index>`, the bit it sets. Its purpose, type and `id`
 * are left out, since they do not change which bit that is.
 */
export function entryKey(entry: CredentialStatus): string {
  return `${entry.statusListCredential}#${entry.statusListIndex}`;
}

/**
 * The key of the status list entry that revoking `node` sets:
 * `<statusListCredential>#<index>`, with the index in canonical decimal, as
 * `StatusList2021Manager` writes an entry's `id`. Two nodes have the same key
 * exactly when revoking either sets the same bit, however each writes the
 * entry. `undefined` for a node that has no entry to set. Throws, as revoking
 * the node would, for an index that no list can hold.
 *
 * A storage provider that implements `getNodeIdsByStatusEntry` indexes its
 * nodes by this key.
 */
export function statusEntryKey(node: DelegationNode): string | undefined {
  const entry = nodeStatusEntry(node);
  return entry === undefined ? undefined : entryKey(entry);
}
