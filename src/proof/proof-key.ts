/** Detached proof key retrieval, with the shared assertion relationship and DID resource limits. */
import type { FetchProvider } from '../providers/base.js';
import type { Ed25519JWK } from '../utils/crypto-service.js';
import { assertionMethodRefusal, selectAssertionMethod } from '../delegation/verification-relationship.js';
import { verificationMethodJwk } from '../delegation/verification-method-key.js';
import { logger } from '../logging/index.js';
import { checkProofIdentifiers, resolveProofDid } from './proof-did.js';
import { ProofVerificationError, PROOF_VERIFICATION_ERROR_CODES as codes } from './errors.js';

/** Retrieve only the key that the signer's own assertionMethod authorizes for the proof. */
export async function fetchProofKey(
  fetcher: FetchProvider, did: string, kid?: string, timeoutMs?: number,
): Promise<Ed25519JWK | null> {
  try {
    checkProofIdentifiers(did, kid);
    // Reject a foreign absolute kid before fetching; retain the public API's bare-fragment shorthand.
    if (kid?.startsWith('did:') && kid.split('#')[0] !== did) {
      throw new ProofVerificationError(codes.KID_DID_MISMATCH,
        `kid ${kid} names a key of a different DID than ${did}`, { did, kid });
    }
    const doc = await resolveProofDid(fetcher, did, kid, timeoutMs);
    if (!doc) throw new ProofVerificationError(codes.DID_DOCUMENT_NOT_FOUND, `DID document not found: ${did}`, { did });
    const name = kid && !kid.startsWith('did:') && !kid.startsWith('#') ? `#${kid}` : kid;
    const selected = selectAssertionMethod(doc, did, name);
    if ('refused' in selected) {
      throw new ProofVerificationError(
        selected.refused === 'another DID' ? codes.KID_DID_MISMATCH : codes.VERIFICATION_METHOD_NOT_FOUND,
        assertionMethodRefusal(selected, 'Proof kid', name, did), { did, kid },
      );
    }
    const method = selected.method;
    const jwk = verificationMethodJwk(method);
    if (!jwk) {
      throw new ProofVerificationError(codes.PUBLIC_KEY_NOT_FOUND,
        'Verification method has no usable public key (publicKeyJwk / publicKeyMultibase / publicKeyBase58)',
        { did, kid, verificationMethodId: method.id });
    }
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) {
      throw new ProofVerificationError(codes.INVALID_JWK_FORMAT,
        `Unsupported key type or curve: kty=${jwk.kty}, crv=${jwk.crv}`,
        { did, kid, jwk: { kty: jwk.kty, crv: jwk.crv } });
    }
    // Built-in resolvers freeze documents: never attach a kid to their published key in place.
    return { ...jwk, kid: (jwk as Ed25519JWK).kid || method.id } as Ed25519JWK;
  } catch (error) {
    if (error instanceof ProofVerificationError) throw error;
    logger.error('[ProofVerifier] Failed to fetch public key from DID', { error });
    throw new ProofVerificationError(codes.DID_RESOLUTION_FAILED,
      `DID resolution failed: ${error instanceof Error ? error.message : String(error)}`,
      { did, kid, originalError: error instanceof Error ? error.message : String(error) });
  }
}
