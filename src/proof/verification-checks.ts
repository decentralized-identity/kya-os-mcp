/**
 * The checks of a proof that need no verifier state: its structure, the binding of its signer to
 * the DID it claims and to what the caller expects, and the result an unexpected error gives.
 * `./verifier.ts` runs them.
 */

import {
  validateDetachedProof,
  type DetachedProof,
} from "../types/protocol.js";
import { PROOF_VERIFICATION_ERROR_CODES } from "./errors.js";
import type { ProofVerificationOptions, ProofVerificationResult } from "./verifier-types.js";

/**
 * Validate proof structure
 */
export async function validateProofStructure(
  proof: DetachedProof
): Promise<ProofVerificationResult & { proof?: DetachedProof }> {
  const validationResult = validateDetachedProof(proof);
  if (!validationResult.success) {
    return {
      valid: false,
      reason: "Invalid proof structure",
      errorCode: PROOF_VERIFICATION_ERROR_CODES.INVALID_PROOF_STRUCTURE,
      error: new Error(
        `Proof validation failed: ${validationResult.error?.message}`
      ),
      details: {
        validationError: validationResult.error?.message,
      },
    };
  }
  return {
    valid: true,
    proof: validationResult.data,
  };
}

/**
 * Bind the signing key to the principal. `kid` names the signing key; when
 * it is an absolute DID URL its DID part must be `meta.did`, or a proof could
 * claim a victim's DID while being signed by a key another DID publishes. A
 * relative `kid` is resolved against `meta.did`. Then apply the caller's
 * expected signer and audience, if given.
 */
export function validateSigner(
  meta: DetachedProof["meta"],
  options: ProofVerificationOptions = {},
): ProofVerificationResult {
  const kidOwner = didOfKid(meta.kid);
  if (kidOwner !== undefined && kidOwner !== meta.did) {
    return {
      valid: false,
      reason: "Proof kid names a key of a different DID than meta.did",
      errorCode: PROOF_VERIFICATION_ERROR_CODES.KID_DID_MISMATCH,
      details: { did: meta.did, kid: meta.kid },
    };
  }
  if (options.expectedDid !== undefined && meta.did !== options.expectedDid) {
    return {
      valid: false,
      reason: "Proof was not issued by the expected DID",
      errorCode: PROOF_VERIFICATION_ERROR_CODES.DID_MISMATCH,
      details: { did: meta.did, expectedDid: options.expectedDid },
    };
  }
  if (options.expectedAudience !== undefined) {
    const allowed = Array.isArray(options.expectedAudience)
      ? options.expectedAudience
      : [options.expectedAudience];
    if (!allowed.includes(meta.audience)) {
      return {
        valid: false,
        reason: "Proof is addressed to a different audience",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.AUDIENCE_MISMATCH,
        details: { audience: meta.audience, expectedAudience: options.expectedAudience },
      };
    }
  }
  return { valid: true };
}

/**
 * The DID an absolute DID URL `kid` (`did:…#frag`, the form proofs carry)
 * names, or undefined for a relative `kid` (`frag` or `#frag`), which is
 * resolved against the proof's `did`.
 */
function didOfKid(kid: string): string | undefined {
  return kid.startsWith("did:") ? kid.split("#")[0] : undefined;
}

/**
 * Handle verification errors consistently
 */
export function handleVerificationError(error: unknown): ProofVerificationResult {
  return {
    valid: false,
    reason: "Proof verification error",
    errorCode: PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_ERROR,
    error: error instanceof Error ? error : new Error(String(error)),
    details: {
      errorMessage: error instanceof Error ? error.message : String(error),
    },
  };
}
