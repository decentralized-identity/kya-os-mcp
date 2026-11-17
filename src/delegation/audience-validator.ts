/**
 * Delegation Audience Validation
 *
 * Validates if a delegation's audience matches the server DID.
 * Supports both single server DID and multiple server DIDs.
 */

import type { DelegationRecord } from '../types/protocol.js';

/**
 * Whether `delegation`'s audience admits `serverDid`: it names none, it is that DID, or it is a list
 * that holds it. An audience of any other kind, such as a number or an object, admits no server,
 * and is never read as a list, so this does not throw for one.
 */
export function verifyDelegationAudience(
  delegation: DelegationRecord,
  serverDid: string
): boolean {
  const audience: unknown = delegation.constraints.audience;
  if (!audience) {
    return true;
  }

  if (typeof audience === 'string') {
    return audience === serverDid;
  }

  return Array.isArray(audience) && audience.includes(serverDid);
}
