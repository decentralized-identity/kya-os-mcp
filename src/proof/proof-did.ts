/**
 * The proof verifier's DID resolution, within the DID resource limits (SPEC.md §4.4.2). A detached
 * proof names its signer's DID and key id, so both are refused before anything quotes or resolves
 * them, and the document the signer's `FetchProvider.resolveDID` returns is bounded before a key is
 * taken from it.
 */

import { boundedIdentifiers, resolveBoundedDid } from "../delegation/did-resource-limits.js";
import type { DIDDocument } from "../delegation/vc-verifier.types.js";
import type { FetchProvider } from "../providers/base.js";
import { ProofVerificationError, PROOF_VERIFICATION_ERROR_CODES } from "./errors.js";

/** Throws when `did` is empty, or when it or `kid`, when given, is over its length limit. */
export function checkProofIdentifiers(did: string, kid?: string): void {
  if (did === "") {
    throw new ProofVerificationError(PROOF_VERIFICATION_ERROR_CODES.DID_DOCUMENT_NOT_FOUND, "DID is empty");
  }
  if (!boundedIdentifiers(did, kid)) {
    throw new ProofVerificationError(
      PROOF_VERIFICATION_ERROR_CODES.DID_DOCUMENT_NOT_FOUND,
      "DID or key identifier exceeds resource limit",
    );
  }
}

/**
 * `did`'s document from `fetcher.resolveDID`, within the resolution deadline and the document
 * limits. The walk trusts only its own brand: a document a built-in resolver admitted, frozen as it
 * was measured, is not walked again, whichever provider, subclass or wrapper returns it; any other
 * document, `RuntimeFetchProvider`'s for a configured resolver and did:key included, is walked on
 * each resolution.
 */
export function resolveProofDid(fetcher: FetchProvider, did: string, kid?: string): Promise<DIDDocument | null> {
  return resolveBoundedDid({ resolve: (value) => fetcher.resolveDID(value) }, did, kid);
}
