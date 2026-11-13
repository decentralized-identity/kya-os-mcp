/**
 * KYA-OS Entity Card — status-list PROOF check (W3C Data Integrity, `eddsa-jcs-2022`).
 *
 * W3C Bitstring Status List v1.0 has a verifier check every proof on the status-list credential
 * before it reads a bit: the list is what says a credential is revoked, so a list nobody verified
 * lets whoever serves it clear a revocation. {@link createRevocationChecker} takes that check as
 * its `verifyStatusList` seam, the way the rest of the card layer takes credential proofs, and
 * {@link createStatusListProofVerifier} is a ready implementation for lists signed with
 * `DataIntegrityProof` / `eddsa-jcs-2022` by an Ed25519 key in the list issuer's DID document.
 *
 * The cryptosuite itself is in ./data-integrity; a status list is an assertion by its issuer, so
 * the proof purpose is `assertionMethod`, and the issuer's DID document must list the key under
 * `assertionMethod`. Every failure returns `false`.
 */

import type { DIDResolver } from '../delegation/vc-verifier.types.js';
import { ASSERTION_METHOD } from '../delegation/verification-relationship.js';
import { signEddsaJcs2022, verifyEddsaJcs2022, type EddsaJcs2022Proof } from './data-integrity.js';
import type { ProofSigner } from './proof/types.js';

/**
 * Checks a fetched status-list credential's proof. Resolves `true` only when the proof verifies
 * under a key the list's `issuer` lists under `assertionMethod`, since the revocation checker
 * decides by that `issuer` whom the list speaks for; `false` or a throw rejects the list, and the
 * revocation checker then fails closed.
 */
export type StatusListProofVerifier = (credential: Record<string, unknown>) => boolean | Promise<boolean>;

/** Dependencies for {@link createStatusListProofVerifier}. */
export interface StatusListProofVerifierDeps {
  /** Resolves the list issuer's DID document, e.g. `createDidWebResolver` or `createDidKeyResolver`. */
  didResolver: DIDResolver;
}

/**
 * Build a {@link StatusListProofVerifier} for `DataIntegrityProof` / `eddsa-jcs-2022` status lists.
 * Pass it to {@link createRevocationChecker} as `verifyStatusList`.
 */
export function createStatusListProofVerifier(deps: StatusListProofVerifierDeps): StatusListProofVerifier {
  return async function verifyStatusList(credential: Record<string, unknown>): Promise<boolean> {
    try {
      return await verifyEddsaJcs2022(credential, deps.didResolver, ASSERTION_METHOD);
    } catch {
      return false;
    }
  };
}

/**
 * Sign a status-list credential as its issuer, the publishing side of
 * {@link createStatusListProofVerifier}. `signer.kid` must be a verification method of the list's
 * `issuer` that its DID document lists under `assertionMethod`; any {@link ProofSigner} with
 * `signRaw` works.
 */
export function signStatusListCredential<T extends Record<string, unknown>>(
  credential: T,
  signer: ProofSigner,
  options: { created?: string } = {},
): Promise<T & { proof: EddsaJcs2022Proof }> {
  return signEddsaJcs2022(credential, signer, { proofPurpose: ASSERTION_METHOD, created: options.created });
}
