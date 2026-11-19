/**
 * The delegation a request proof names (SPEC.md §7.8).
 *
 * A holder-binding proof covers the tool name and the business arguments; the delegation rides
 * beside it in `_kyaos_delegation`, a control argument outside the request hash. On its own the
 * proof is therefore good beside any delegation of its subject, and a party on the path that holds
 * another of them, from another Responsible Party say, can put it in place of the one the agent
 * chose without any key. A proof names its delegation by the two members SPEC §7.8 defines, which
 * its signature covers: `delegationRef`, the reference of the credential presented, and
 * `delegationChainDigest`, the digest of the chain, root first. A server holds a proof that names a
 * delegation to it, and refuses it beside any other.
 *
 * Pure: no transport, no framework, no key material.
 */

import { digestDelegationChain, type ReceivedCredential, type Sha256 } from './chain-digest.js';
import { delegationRefOf } from './delegation-ref.js';
import type { ProofMeta } from '../types/protocol.js';

/** The members of a proof that name a delegation. */
export type DelegationNames = Pick<ProofMeta, 'delegationRef' | 'delegationChainDigest'>;

/** The delegation a call presented, as the server that verified it reads it. */
export interface PresentedDelegation {
  /** The reference of the credential the call presented, or `undefined` when it shows no id. */
  delegationRef?: string;
  /**
   * The digest of the chain the server evaluated for it, root first, the presented credential
   * last. It is asked for only when a proof names a chain.
   */
  chainDigest(): Promise<string>;
}

/**
 * The names a proof gives `chain`, root first, each credential as it is presented (an object, or a
 * VC-JWT by its string): the reference of its last credential, where that shows an id, and the
 * digest of the whole chain.
 *
 * @throws {TypeError} for an empty chain, and `NoSignedFormError` for a credential with no signed
 *   form, as `digestDelegationChain` does.
 */
export async function namesOfDelegationChain(chain: readonly unknown[], hash: Sha256): Promise<DelegationNames> {
  const { chain: delegationChainDigest } = await digestDelegationChain(chain as readonly ReceivedCredential[], hash);
  const delegationRef = await delegationRefOf(chain.at(-1), hash);
  return { ...(delegationRef === undefined ? {} : { delegationRef }), delegationChainDigest };
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
