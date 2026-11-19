/**
 * The proof of a delegated call: a holder's request proof, held to the delegation the call presents.
 *
 * `assertHolderBinding` proves the caller holds the key of a delegation's subject. It says nothing
 * of which delegation: the credential rides beside the proof, outside the request hash, so a party
 * on the path that holds another delegation of the same subject can put it in place of the one the
 * holder chose, or take the delegation away so that authority retained for another one answers.
 * {@link verifyDelegatedCallProof} is the one check an enforcement point makes of a delegated call's
 * proof. It takes the credential the call presented as a required input, so the comparison cannot
 * be left out by leaving out an argument, and it reads what the proof states only from what the
 * proof's signature covers: the protected header that verified (SPEC §7.8, `./stated-delegation.ts`)
 * and the signed payload members `delegationRef` and `delegationChainDigest`.
 *
 * Pure but for the default hash: no transport, no framework, no key material.
 */

import { delegationChainDigest, delegationCredentialDigest, type ReceivedCredential, type Sha256 } from './chain-digest.js';
import { delegationRefOf } from './delegation-ref.js';
import {
  bindHolder,
  HOLDER_BINDING_ERROR,
  type AssertHolderBindingInput,
  type HolderBindingResult,
  type SignedRequestProof,
} from './holder-binding.js';
import { namesAnotherDelegation, type DelegationNames, type PresentedDelegation } from './named-delegation.js';
import { ancestryPinning } from './parent-commitment.js';
import {
  requestBindingMode,
  statedDelegationOf,
  statementRefusal,
  type RequestBindingMode,
  type StatedDelegation,
} from './stated-delegation.js';
import type { Digest } from '../audit/types.js';
import { webCryptoSha256 } from '../utils/domain-digest.js';

export interface VerifyDelegatedCallProofInput extends AssertHolderBindingInput {
  /**
   * The delegation credential the call presented, as it was received (an object, or a VC-JWT by its
   * string), or `null` for a call that presented none. Required: a proof is held to it.
   */
  presented: ReceivedCredential | null;
  /**
   * The ancestors `presented` was evaluated under, root first, each as it was read. Leave it out for
   * a credential with no parent. It is what a `delegationChainDigest` a proof states is compared
   * with, and what `ancestorsPinned` reports on.
   */
  ancestors?: readonly ReceivedCredential[];
  /**
   * How a proof that does not name `presented` is taken ({@link RequestBindingMode}): `prefer`, the
   * default, binds it, and `require` does not. Any other value throws a `TypeError`.
   */
  mode?: RequestBindingMode;
  /** SHA-256 for the digests compared; the runtime's WebCrypto when left out. */
  hash?: Sha256;
}

/** What a bound proof says of its delegation, each member as the proof's signature covers it. */
export interface ProofDelegationClaims extends DelegationNames {
  /** What the protected header states (SPEC §7.8). */
  readonly statement: Exclude<StatedDelegation, { kind: 'malformed' }>;
}

export interface DelegatedCallProofResult extends HolderBindingResult {
  /**
   * On `bound`: whether the proof names the delegation the call is made under. `false` only under
   * `prefer`, for a proof that states nothing, or that states `none` beside a presented credential:
   * such a proof is good beside any delegation of its subject, and `require` refuses it.
   */
  named?: boolean;
  /**
   * On `bound` beside a presented credential: whether that credential fixes every ancestor it was
   * evaluated under, each hop stating its parent's digest (`./parent-commitment.ts`). With `named`,
   * the holder's signature then fixes the whole chain.
   */
  ancestorsPinned?: boolean;
  /**
   * On `bound`: what the proof says of its delegation. For a call that presented none, authorize it
   * only under authority retained for a credential these admit ({@link admitsRetainedDelegation}).
   */
  claims?: ProofDelegationClaims;
}

/** A delegation as the party that verified it holds it, with the SPEC §7.8 digest of its credential. */
export interface HeldDelegation extends PresentedDelegation {
  readonly credentialDigest: Digest;
}

/**
 * Whether `claims`, a bound proof's, admit authority retained under `held`: a proof that names a
 * credential admits that credential alone, and one that names none admits any.
 *
 * @throws what `held.chainDigest` throws
 */
export async function admitsRetainedDelegation(claims: ProofDelegationClaims, held: HeldDelegation): Promise<boolean> {
  if (claims.statement.kind === 'credential' && claims.statement.digest !== held.credentialDigest) return false;
  return !(await namesAnotherDelegation(claims, held));
}

const unbound = (reason: string, cause: string): DelegatedCallProofResult => ({
  status: 'unbound',
  errorCode: HOLDER_BINDING_ERROR,
  reason,
  cause,
});

/** The delegation claims of a proof that bound, from what its signature covers. */
function claimsOf(signed: SignedRequestProof): { statement: StatedDelegation } & DelegationNames {
  const { delegationRef, delegationChainDigest: chain } = signed.meta;
  return {
    statement: statedDelegationOf(signed.protectedHeader),
    ...(delegationRef === undefined ? {} : { delegationRef }),
    ...(chain === undefined ? {} : { delegationChainDigest: chain }),
  };
}

/**
 * Verify the request proof of a delegated call: that the caller holds the key of `subjectDid`, as
 * `assertHolderBinding` does, and that the proof was made for the delegation the call presented.
 *
 * Beside a presented credential, a proof that names another one (in its protected header, or by a
 * signed `delegationRef` or `delegationChainDigest`) does not bind, under either mode, and neither
 * does one whose statement is malformed. A proof that names none binds under `prefer` with
 * `named: false`, and does not bind under `require`. Beside no credential, a proof that states
 * nothing does not bind under `require`; whatever the proof names is given back as `claims`, for
 * the caller to select the authority it retains by.
 *
 * A subject that is not a did:key is `not_applicable`, as for `assertHolderBinding`: its proof is
 * not verified, so nothing it states is read.
 *
 * @throws {TypeError} for a `mode` that is neither `prefer` nor `require`
 */
export async function verifyDelegatedCallProof(input: VerifyDelegatedCallProofInput): Promise<DelegatedCallProofResult> {
  const mode = requestBindingMode(input.mode, 'mode');
  const { presented, ancestors = [], hash = webCryptoSha256 } = input;
  const { result, signed } = await bindHolder(input);
  if (signed === undefined) return result;

  const claims = claimsOf(signed);
  let presentedDigest: Digest | null = null;
  let pinning: Awaited<ReturnType<typeof ancestryPinning>> | undefined;
  try {
    if (presented !== null) {
      presentedDigest = await delegationCredentialDigest(presented, hash);
      const own = presentedDigest;
      const held: HeldDelegation = {
        credentialDigest: own,
        delegationRef: await delegationRefOf(presented, hash),
        chainDigest: async () => {
          const digests: Digest[] = [];
          for (const ancestor of ancestors) digests.push(await delegationCredentialDigest(ancestor, hash));
          return delegationChainDigest([...digests, own], hash);
        },
      };
      if (await namesAnotherDelegation(claims, held)) {
        return unbound('Request proof names another delegation than the one presented', 'delegation_mismatch');
      }
      pinning = await ancestryPinning([...ancestors, presented], hash);
    }
  } catch {
    return unbound('The delegation the request proof names could not be compared with the one presented', 'delegation_unchecked');
  }

  const refusal = statementRefusal(claims.statement, presentedDigest, mode);
  if (refusal !== undefined) return unbound(refusal.reason, refusal.cause);
  if (pinning === 'mismatch') {
    return unbound('A credential of the delegation chain states a parent digest that is not its parent\'s', 'ancestor_mismatch');
  }

  const { statement } = claims;
  const named = presented === null ? statement.kind !== 'absent' : statement.kind === 'credential';
  return {
    status: 'bound',
    named,
    ...(pinning === undefined ? {} : { ancestorsPinned: pinning === 'pinned' }),
    // A malformed statement was refused above.
    claims: claims as ProofDelegationClaims,
  };
}
