/**
 * KYA-OS Entity Card: delegation-hop PROOF, signed and checked (W3C Data Integrity, `eddsa-jcs-2022`).
 *
 * SPEC.md §6.10 leaves per-hop signature verification to an injected seam: the chain rules prove a
 * hop attenuates its parent, not that its issuer signed it. {@link createDelegationProofVerifier}
 * is a ready implementation of that seam for hops signed with `DataIntegrityProof` /
 * `eddsa-jcs-2022` by an Ed25519 key in the delegator's DID document, the cryptosuite the profile
 * names. The key must belong to the hop's own `issuer`, so a hop cannot borrow another party's
 * signature. {@link signDelegationCredential} is the issuing side, for a Responsible Party minting
 * the root and for a delegate re-delegating below it. The proof purpose is `assertionMethod`, the
 * purpose the profile's credentials carry today (SPEC.md §6.2). Every verification failure returns
 * `false`.
 */

import type { DIDResolver } from '../delegation/vc-verifier.types.js';
import { signEddsaJcs2022, verifyEddsaJcs2022 } from './data-integrity.js';
import { DelegationCredentialSchema, type DelegationCredential } from './delegation.js';
import type { ProofSigner } from './proof/types.js';

/** The proof purpose of a delegation hop's `eddsa-jcs-2022` proof. */
const HOP_PROOF_PURPOSE = 'assertionMethod';

/**
 * Checks one `DelegationCredential` hop's proof. Resolves `true` only when the proof verifies;
 * `false` or a throw rejects the hop, and the chain with it. It takes the credential exactly as
 * received, since the signature covers every member, including ones a schema does not name.
 */
export type DelegationProofVerifier = (credential: Record<string, unknown>) => boolean | Promise<boolean>;

/** Dependencies for {@link createDelegationProofVerifier}. */
export interface DelegationProofVerifierDeps {
  /** Resolves each delegator's DID document, e.g. `createDidKeyResolver` or `createDidWebResolver`. */
  didResolver: DIDResolver;
}

/**
 * Build a {@link DelegationProofVerifier} for `DataIntegrityProof` / `eddsa-jcs-2022` hops. Pass it
 * to {@link verifyRequestDelegation} (or {@link requireDelegation}) as `verifyHopProof`.
 */
export function createDelegationProofVerifier(deps: DelegationProofVerifierDeps): DelegationProofVerifier {
  return async function verifyHopProof(credential: Record<string, unknown>): Promise<boolean> {
    try {
      return await verifyEddsaJcs2022(credential, deps.didResolver, HOP_PROOF_PURPOSE);
    } catch {
      return false;
    }
  };
}

/**
 * A `DelegationCredential` before its issuer signs it. A key-remapping type rather than `Omit`:
 * the credential type has an index signature (unknown members pass through), and `Omit` over one
 * drops every named member.
 */
export type UnsignedDelegationCredential = {
  [K in keyof DelegationCredential as K extends 'proof' ? never : K]: DelegationCredential[K];
};

/**
 * Sign one delegation hop as its issuer. `signer` is the issuer's Ed25519 key (`signer.kid` a
 * verification method of `credential.issuer`), e.g. from `ed25519SignerFromJwk`; any
 * {@link ProofSigner} with `signRaw` works, a KMS or non-extractable key included. Throws when the
 * credential is not a §6.10 `DelegationCredential` or the signer cannot sign for its issuer.
 */
export async function signDelegationCredential(
  credential: UnsignedDelegationCredential,
  signer: ProofSigner,
  options: { created?: string } = {},
): Promise<DelegationCredential> {
  const parsed = DelegationCredentialSchema.safeParse(credential);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`not a DelegationCredential at ${issue?.path.join('.') ?? '(root)'}: ${issue?.message ?? 'invalid'}`);
  }
  return signEddsaJcs2022(credential, signer, { proofPurpose: HOP_PROOF_PURPOSE, created: options.created });
}
