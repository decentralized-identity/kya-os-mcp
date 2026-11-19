/**
 * The delegation a proof names in its payload (SPEC.md §7.8).
 *
 * Two signed members of a proof's payload name a delegation: `delegationRef`, the reference of the
 * credential presented, and `delegationChainDigest`, the digest of the chain, root first. A server's
 * response proof carries them for the chain it evaluated. A holder's request proof states its
 * delegation in its protected header instead (`./stated-delegation.ts`), which every released
 * verifier reads past; one that also carries these members is held to them, and refused beside any
 * other delegation.
 *
 * Pure: no transport, no framework, no key material.
 */

import type { ProofMeta } from '../types/protocol.js';

/** The members of a proof that name a delegation. */
export type DelegationNames = Pick<ProofMeta, 'delegationRef' | 'delegationChainDigest'>;

/** The delegation a call presented, as the server that verified it reads it. */
export interface PresentedDelegation {
  /** The reference of the credential the call presented, or `undefined` when it shows no id. */
  delegationRef?: string | undefined;
  /**
   * The digest of the chain the server evaluated for it, root first, the presented credential
   * last. It is asked for only when a proof names a chain.
   */
  chainDigest(): Promise<string>;
}

/**
 * Whether `names`, a proof's, name a delegation other than `presented`: a `delegationRef` that is
 * not the presented credential's reference, or a `delegationChainDigest` that is not the digest of
 * the chain the server evaluated. A proof that names neither names no delegation. A member that is
 * present names one, whatever its value, so an empty one, which no signature covers, names none
 * the server could have presented.
 *
 * @throws what `presented.chainDigest` throws
 */
export async function namesAnotherDelegation(names: DelegationNames, presented: PresentedDelegation): Promise<boolean> {
  if (names.delegationRef !== undefined && names.delegationRef !== presented.delegationRef) return true;
  return names.delegationChainDigest !== undefined && names.delegationChainDigest !== (await presented.chainDigest());
}
