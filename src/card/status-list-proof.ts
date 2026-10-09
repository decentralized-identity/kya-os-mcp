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
 * The construction is the cryptosuite's, step for step: the proof options without `proofValue`,
 * carrying the document's `@context`, and the document without `proof`, each RFC 8785-canonicalized
 * and SHA-256 hashed; the signature is Ed25519 over the two hashes concatenated, `proofValue` is
 * base58btc multibase. The key is the issuer's verification method `proof.verificationMethod`
 * names, and that method must belong to the list's `issuer`. Every failure returns `false`.
 */

import { canonicalize } from 'json-canonicalize';
import { isRecord } from '../utils/guards.js';
import { base58Decode } from '../utils/base58.js';
import { verificationMethodJwk } from '../delegation/verification-method-key.js';
import type { DIDResolver, VerificationMethod } from '../delegation/vc-verifier.types.js';
import { ed25519VerifyRaw, sha256 } from './proof/canonical.js';

/**
 * Checks a fetched status-list credential's proof. Resolves `true` only when the proof verifies;
 * `false` or a throw rejects the list, and the revocation checker then fails closed.
 */
export type StatusListProofVerifier = (credential: Record<string, unknown>) => boolean | Promise<boolean>;

/** Dependencies for {@link createStatusListProofVerifier}. */
export interface StatusListProofVerifierDeps {
  /** Resolves the list issuer's DID document, e.g. `createDidWebResolver` or `createDidKeyResolver`. */
  didResolver: DIDResolver;
}

const ED25519_SIGNATURE_LENGTH = 64;
/** A 64-byte signature is at most 88 base58 characters; bound the decode before it runs. */
const MAX_PROOF_VALUE_BASE58 = 100;

/**
 * Build a {@link StatusListProofVerifier} for `DataIntegrityProof` / `eddsa-jcs-2022` status lists.
 * Pass it to {@link createRevocationChecker} as `verifyStatusList`.
 */
export function createStatusListProofVerifier(deps: StatusListProofVerifierDeps): StatusListProofVerifier {
  return async function verifyStatusList(credential: Record<string, unknown>): Promise<boolean> {
    try {
      return await verifyEddsaJcs2022(credential, deps.didResolver);
    } catch {
      return false;
    }
  };
}

async function verifyEddsaJcs2022(document: Record<string, unknown>, didResolver: DIDResolver): Promise<boolean> {
  const proof = document.proof;
  // One proof object: a proof set or chain is not a shape this check reads.
  if (!isRecord(proof)) return false;
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') return false;
  if (proof.proofPurpose !== 'assertionMethod') return false;
  const { proofValue, verificationMethod } = proof;
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) return false;
  if (typeof verificationMethod !== 'string') return false;

  const issuer = issuerOf(document);
  const did = verificationMethod.split('#')[0];
  if (issuer === undefined || did !== issuer) return false;

  const signature = base58Decode(proofValue.slice(1), MAX_PROOF_VALUE_BASE58);
  if (signature.length !== ED25519_SIGNATURE_LENGTH) return false;

  const didDocument = await didResolver.resolve(did);
  const method = didDocument?.verificationMethod?.find((vm) => methodId(vm, did) === verificationMethod);
  const jwk = method ? verificationMethodJwk(method) : undefined;
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return false;

  const unsecured: Record<string, unknown> = { ...document };
  delete unsecured.proof;
  const options: Record<string, unknown> = { ...proof };
  delete options.proofValue;
  if (options['@context'] !== undefined) {
    // The proof may name its own @context only as a prefix of the document's.
    if (!startsWith(contexts(document['@context']), contexts(options['@context']))) return false;
    unsecured['@context'] = options['@context'];
  }
  if (unsecured['@context'] !== undefined) options['@context'] = unsecured['@context'];

  const encoder = new TextEncoder();
  const proofHash = await sha256(encoder.encode(canonicalize(options)));
  const documentHash = await sha256(encoder.encode(canonicalize(unsecured)));
  const hashData = new Uint8Array(proofHash.length + documentHash.length);
  hashData.set(proofHash, 0);
  hashData.set(documentHash, proofHash.length);
  return ed25519VerifyRaw(jwk, signature, hashData);
}

/** The credential's `issuer` DID, whether a bare string or an `{ id }` object. */
function issuerOf(document: Record<string, unknown>): string | undefined {
  const issuer = document.issuer;
  if (typeof issuer === 'string') return issuer;
  return isRecord(issuer) && typeof issuer.id === 'string' ? issuer.id : undefined;
}

/** A verification method's absolute id: DID documents may write it relative (`#key-1`). */
function methodId(method: VerificationMethod, did: string): string {
  return method.id.startsWith('#') ? `${did}${method.id}` : method.id;
}

function contexts(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function startsWith(whole: unknown[], prefix: unknown[]): boolean {
  return prefix.length <= whole.length && prefix.every((entry, i) => canonicalize(entry) === canonicalize(whole[i]));
}
