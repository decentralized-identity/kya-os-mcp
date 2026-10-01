/**
 * The status list entry behind a delegation graph node — one reading shared by
 * cascading revocation, which flips and reads it.
 *
 * Internal: not re-exported from the delegation barrel.
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
 */
export function nodeStatusEntry(node: DelegationNode): CredentialStatus | undefined {
  if (node.credentialStatus) {
    return node.credentialStatus;
  }
  return node.credentialStatusId ? parseCredentialStatusId(node.credentialStatusId) : undefined;
}
