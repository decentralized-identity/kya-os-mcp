/**
 * The check of a delegation credential's embedded signature: an Ed25519
 * signature carried in `proof.proofValue` (SPEC.md §6.2).
 *
 * It is checked over the credential's signed form (SPEC §7.8), the one the
 * chain digest hashes: the same content and the same signature bytes, so
 * nothing can verify as one thing and be digested as another. The middleware
 * checks every embedded proof with it, and so does the conformance kit's
 * reference adapter: the suite holds this package to the vectors, and
 * `conformance/verify.py` checks the vectors by a reading of its own.
 *
 * Pure: no transport, no framework, no key material.
 */

import type { CryptoProvider } from '../providers/base.js';
import { readCredentialProofValue, type DelegationCredential } from '../types/protocol.js';
import { bytesToBase64 } from '../utils/base64.js';
import { ed25519KeyBytes } from '../utils/ed25519-public-key.js';
import {
  CredentialContentError,
  NoSignedFormError,
  signedCredential,
  signingInput,
  type SignedCredential,
} from './signed-form.js';
import type { SignatureVerificationFunction } from './vc-verifier.types.js';

/** What a credential's signature is checked over, or why it cannot be. */
function signedOrReason(vc: DelegationCredential): { signed: SignedCredential; data: Uint8Array } | { reason: string } {
  try {
    const signed = signedCredential(vc);
    return { signed, data: signingInput(signed) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // Only a refusal of the signature string is about the proofValue. What the
    // credential holds, and anything else that fails to read it, is about
    // its content.
    if (!(error instanceof NoSignedFormError) || error instanceof CredentialContentError) {
      return { reason: `Unreadable credential content: ${message}` };
    }
    return {
      reason: readCredentialProofValue(vc.proof as Record<string, unknown>)
        ? `Unreadable proofValue: ${message}`
        : 'Missing proofValue in proof',
    };
  }
}

/**
 * The `signatureVerifier` of a `DelegationCredentialVerifier` for embedded
 * Ed25519 proofs, checking with `crypto`. A credential refused for what it
 * carries is told why: it has no proof, no `proofValue` in it, or one that
 * is no signature (`Unreadable proofValue`); what its issuer signed has no
 * canonical form or nests too deep (`Unreadable credential content`); or the
 * key has no `x`, or one that is not an Ed25519 key as SPEC.md §7.4 reads one,
 * which is refused as `did_invalid`, since the issuer's DID document lists no
 * usable key for the proof.
 */
export function embeddedSignatureVerifier(crypto: Pick<CryptoProvider, 'verify'>): SignatureVerificationFunction {
  return async (vc: DelegationCredential, publicKeyJwk: unknown) => {
    if (!vc.proof) return { valid: false, reason: 'Missing proof' };

    const read = signedOrReason(vc);
    if ('reason' in read) return { valid: false, reason: read.reason };

    // The key is read as a proof's key is (SPEC §7.4); the provider takes base64.
    const jwk = publicKeyJwk as { x?: unknown };
    if (!jwk.x) return { valid: false, reason: 'No x field in publicKeyJwk', code: 'did_invalid' };
    let publicKey: string;
    try {
      publicKey = bytesToBase64(ed25519KeyBytes(jwk));
    } catch (error) {
      return { valid: false, reason: `Unreadable x in publicKeyJwk: ${(error as Error).message}`, code: 'did_invalid' };
    }

    // The crypto provider is the host's: the signature holds only on the literal `true`.
    const valid = (await crypto.verify(read.data, read.signed.signature, publicKey)) === true;
    return { valid, reason: valid ? undefined : 'Signature verification failed' };
  };
}
