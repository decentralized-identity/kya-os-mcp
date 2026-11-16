/**
 * What a verifier holds of a call, and how it fails to match what a proof
 * binds (SPEC.md §7.8): `findBindingMismatch`, the one comparison
 * `ProofVerifier` applies, with the terms it reports in and the reason and
 * error code of each. The request and response are compared by
 * `findContentBindingMismatch` (`./generator.ts`), over the canonical hashes
 * the signer computes too; the outcome a proof records and the delegation
 * chain it binds are compared here.
 */

import { digestDelegationChain, type ReceivedCredential, type Sha256 } from '../delegation/chain-digest.js';
import { delegationRefOf } from '../delegation/delegation-ref.js';
import { NoSignedFormError } from '../delegation/signed-form.js';
import type { ProofMeta } from '../types/protocol.js';
import { PROOF_VERIFICATION_ERROR_CODES, type ProofVerificationErrorCode } from './errors.js';
import { findContentBindingMismatch, type ToolRequest, type ToolResponse } from './generator.js';

/** The outcome a proof states. One that states none records a call that was allowed. */
type ProofOutcome = NonNullable<ProofMeta['outcome']>;

/** How received content fails to match the hashes a proof binds. */
export type ContentBindingMismatch =
  | 'request'
  | 'response'
  | 'response-missing'
  | 'response-unexpected';

/**
 * How what a verifier holds fails to match what a proof binds: the `details`
 * of a verification that failed for that reason. `binding` names the
 * comparison that failed.
 *
 * - `request`, `response`, `response-missing`, `response-unexpected`: the
 *   request or response is not the one the proof hashes
 *   (`CONTENT_BINDING_MISMATCH`).
 * - `outcome`: the proof states another outcome than the one required of it;
 *   `outcome` is the one it states (`OUTCOME_MISMATCH`).
 * - `delegation-chain-unbound`, `delegation-chain`, `delegation-ref`: the
 *   proof binds no chain, another chain, or names another credential than the
 *   supplied chain's last (`DELEGATION_BINDING_MISMATCH`).
 */
export type ProofBindingMismatch =
  | { binding: ContentBindingMismatch }
  | { binding: 'outcome'; outcome: ProofOutcome }
  | { binding: 'delegation-chain-unbound' | 'delegation-chain' | 'delegation-ref' };

type Binding = ProofBindingMismatch['binding'];

/** The `reason` of a verification that failed for each mismatch. */
const BINDING_REASONS: Record<Binding, string> = {
  request: 'Request hash mismatch: the proof does not bind the request you supplied',
  'response-missing':
    'Proof binds a response (responseHash present) but no response was supplied to verify against: pass expected.response',
  'response-unexpected':
    'A response was supplied but the proof binds none: content/proof mismatch',
  response:
    'Response hash mismatch: received content differs from what the server signed (possible substitution / MITM)',
  outcome:
    'Outcome mismatch: the proof does not state the outcome required of it. What a refusal names of a delegation is what was presented, not what the server accepted',
  'delegation-chain-unbound':
    'A delegation chain was supplied but the proof binds none (no delegationChainDigest)',
  'delegation-chain':
    'Delegation chain digest mismatch: the chain you supplied is not the one the server evaluated',
  'delegation-ref':
    "Delegation reference mismatch: the proof's delegationRef is not the reference of the last credential of the chain you supplied",
};

/** The `errorCode` of a verification that failed for each mismatch. */
const BINDING_ERROR_CODES: Record<Binding, ProofVerificationErrorCode> = {
  request: PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
  'response-missing': PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
  'response-unexpected': PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
  response: PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
  outcome: PROOF_VERIFICATION_ERROR_CODES.OUTCOME_MISMATCH,
  'delegation-chain-unbound': PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH,
  'delegation-chain': PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH,
  'delegation-ref': PROOF_VERIFICATION_ERROR_CODES.DELEGATION_BINDING_MISMATCH,
};

/**
 * What a verifier holds of a call, to compare with what a proof binds: the
 * request it sent, the response it received, and, to check which delegation
 * chain the server evaluated, that chain.
 */
export interface ExpectedContent {
  request: ToolRequest;
  response?: ToolResponse;
  /**
   * The delegation chain, root first, each credential in the form the server
   * evaluated it in: an object with its `proof`, or a compact VC-JWT (SPEC
   * §7.8). Any copy in that form will do, since the digest covers what its
   * issuer signed and not how it was stored; a VC-JWT and the object it
   * decodes to are two forms, with two digests.
   *
   * When given, the proof must carry a `delegationChainDigest` and it must be
   * this chain's; its `delegationRef` must be the reference of the chain's
   * last credential (`delegationRefOf`), or absent when that credential shows
   * no id; and it must record a call that was allowed, unless `outcome` says
   * otherwise. The last is what makes a match mean the server accepted the
   * chain: a refusal is signed too, and names what was presented.
   *
   * When omitted, or `null`, both claims are covered by the signature but
   * compared with nothing: a caller that holds only its own credential cannot
   * recompute a digest over ancestors the server resolved.
   */
  delegationChain?: readonly ReceivedCredential[] | null;
  /**
   * The outcome the proof must state. A proof with no `outcome` states
   * `allowed`. Defaults to `allowed` when `delegationChain` is given, and to
   * no requirement otherwise. To check what a refusal recorded of the
   * delegation presented with it, pass the chain and the refusal's outcome
   * (`denied`, say).
   */
  outcome?: ProofOutcome;
}

/**
 * Compare what a verifier holds of a call with what a proof binds;
 * `undefined` means they match. The request and the response are compared as
 * `ProofGenerator.verifyProof` compares them; the outcome when the caller
 * states one or supplies a delegation chain, and a chain only when the caller
 * supplies it, each fail-closed (see {@link ExpectedContent}).
 */
export async function findBindingMismatch(
  meta: Pick<ProofMeta, 'requestHash' | 'responseHash' | 'prf' | 'outcome' | 'delegationRef' | 'delegationChainDigest'>,
  expected: ExpectedContent,
  hash: Sha256,
): Promise<ProofBindingMismatch | undefined> {
  const content = await findContentBindingMismatch(meta, expected, hash);
  if (content === 'request') return { binding: content };
  // A chain given as `null` is none, as an outcome given as `null` is: both
  // implementations of this comparison read it so (conformance/verify.py).
  const chain = expected.delegationChain ?? undefined;
  // The outcome before the response, so a refusal handed to a caller that
  // expected the call to be allowed is reported as that, whatever response
  // came with it.
  const outcome = outcomeMismatch(meta.outcome, expected.outcome, chain !== undefined);
  if (outcome !== undefined) return outcome;
  if (content !== undefined) return { binding: content };
  return chain === undefined ? undefined : delegationMismatch(meta, chain, hash);
}

/** What a verification that failed for `mismatch` says of it. */
export function bindingFailure(mismatch: ProofBindingMismatch): {
  reason: string;
  errorCode: ProofVerificationErrorCode;
  details: ProofBindingMismatch;
} {
  const { binding } = mismatch;
  return { reason: BINDING_REASONS[binding], errorCode: BINDING_ERROR_CODES[binding], details: mismatch };
}

/**
 * The outcome a proof states, against the one required of it: `required`, or
 * `allowed` when a delegation chain is supplied (see {@link ExpectedContent}).
 */
function outcomeMismatch(
  stated: ProofMeta['outcome'],
  required: ProofOutcome | undefined,
  chainSupplied: boolean,
): ProofBindingMismatch | undefined {
  const outcome = stated ?? 'allowed';
  const requiredOutcome = required ?? (chainSupplied ? 'allowed' : undefined);
  if (requiredOutcome !== undefined && outcome !== requiredOutcome) {
    return { binding: 'outcome', outcome };
  }
  return undefined;
}

/**
 * The delegation a proof binds, against the chain a verifier supplied: the
 * proof must carry this chain's digest, and name its last credential (see
 * {@link ExpectedContent}).
 */
async function delegationMismatch(
  meta: Pick<ProofMeta, 'delegationRef' | 'delegationChainDigest'>,
  chain: readonly ReceivedCredential[],
  hash: Sha256,
): Promise<ProofBindingMismatch | undefined> {
  if (meta.delegationChainDigest === undefined) return { binding: 'delegation-chain-unbound' };
  if (meta.delegationChainDigest !== (await suppliedChainDigest(chain, hash))) {
    return { binding: 'delegation-chain' };
  }
  // The digest matched, so the chain has a last credential. An empty
  // `delegationRef` is not in the payload the signature covers
  // (buildProofJwsPayload), so the proof names none.
  const reference = await delegationRefOf(chain[chain.length - 1], hash);
  if ((meta.delegationRef || undefined) !== reference) return { binding: 'delegation-ref' };
  return undefined;
}

/**
 * The digest of a chain a verifier supplied. Undefined for one that has no
 * digest: an empty chain, a value that is not an array, as an untyped caller
 * may pass, or a chain with a credential that has no signed form (SPEC §7.8).
 * No proof binds such a chain, so it is a mismatch like any other and not a
 * failure to verify.
 */
async function suppliedChainDigest(
  chain: readonly ReceivedCredential[],
  hash: Sha256,
): Promise<string | undefined> {
  if (!Array.isArray(chain) || chain.length === 0) return undefined;
  try {
    return (await digestDelegationChain(chain, hash)).chain;
  } catch (error) {
    if (error instanceof NoSignedFormError) return undefined;
    throw error;
  }
}
