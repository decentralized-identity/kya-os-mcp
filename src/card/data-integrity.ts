/**
 * KYA-OS Entity Card: W3C Data Integrity `eddsa-jcs-2022` signing and verification, shared by the
 * status-list proof (./status-list-proof) and the delegation-hop proof (./delegation-proof).
 *
 * The construction is the cryptosuite's, step for step: the proof options without `proofValue`,
 * carrying the document's `@context`, and the document without `proof`, each RFC 8785-canonicalized
 * and SHA-256 hashed; the signature is Ed25519 over the two hashes concatenated, `proofValue` is
 * base58btc multibase. The key is the issuer's verification method `proof.verificationMethod`
 * names, and that method must belong to the document's `issuer`, whose DID document must list it
 * under the verification relationship the proof purpose names
 * (../delegation/verification-relationship). Every failure returns `false`.
 */

import { canonicalize } from 'json-canonicalize';
import { resolveBoundedDid } from '../delegation/did-resource-limits.js';
import { isRecord, issuerOf } from '../utils/guards.js';
import { base58Decode, base58Encode } from '../utils/base58.js';
import { base64urlDecodeToBytes } from '../utils/base64.js';
import { verificationMethodJwk } from '../delegation/verification-method-key.js';
import type { DIDResolver } from '../delegation/vc-verifier.types.js';
import {
  retrieveVerificationMethod,
  type VerificationRelationship,
} from '../delegation/verification-relationship.js';
import { ed25519VerifyRaw, sha256 } from './proof/canonical.js';
import type { ProofSigner } from './proof/types.js';

const ED25519_SIGNATURE_LENGTH = 64;
/** A 64-byte signature is at most 88 base58 characters; bound the decode before it runs. */
const MAX_PROOF_VALUE_BASE58 = 100;

/**
 * Verify a document's single `DataIntegrityProof` / `eddsa-jcs-2022` proof made for `proofPurpose`
 * by an Ed25519 key the issuer's DID document lists under the `proofPurpose` verification
 * relationship. Resolves `true` only when every check passes; a malformed proof, an unresolvable
 * key or a key listed only for other purposes resolves `false`. A throwing resolver propagates, so
 * a caller that wants a boolean wraps the call.
 */
export async function verifyEddsaJcs2022(
  document: Record<string, unknown>,
  didResolver: DIDResolver,
  proofPurpose: VerificationRelationship,
): Promise<boolean> {
  const proof = document.proof;
  // One proof object: a proof set or chain is not a shape this check reads.
  if (!isRecord(proof)) return false;
  if (proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022') return false;
  if (proof.proofPurpose !== proofPurpose) return false;
  const { proofValue, verificationMethod } = proof;
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z')) return false;
  if (typeof verificationMethod !== 'string') return false;

  const issuer = issuerOf(document.issuer);
  const did = verificationMethod.split('#')[0];
  if (issuer === undefined || did !== issuer) return false;

  const signature = base58Decode(proofValue.slice(1), MAX_PROOF_VALUE_BASE58);
  if (signature.length !== ED25519_SIGNATURE_LENGTH) return false;

  const didDocument = await resolveBoundedDid(didResolver, did, verificationMethod);
  const method = didDocument
    ? retrieveVerificationMethod(didDocument, did, verificationMethod, proofPurpose)
    : undefined;
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

  return ed25519VerifyRaw(jwk, signature, await hashData(options, unsecured));
}

/**
 * A `DataIntegrityProof` / `eddsa-jcs-2022` proof as {@link signEddsaJcs2022} writes it. A type
 * alias, not an interface, so it stays assignable to the open `proof` member of a credential type.
 */
export type EddsaJcs2022Proof = {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
};

/** Options for {@link signEddsaJcs2022}. */
export interface EddsaJcs2022SignOptions {
  proofPurpose: string;
  /** The proof's `created` timestamp (default: the current time). */
  created?: string;
}

/**
 * Add an `eddsa-jcs-2022` proof to `document`, signed through `signer.signRaw` so a KMS, HSM or
 * non-extractable key works as well as an in-process one. The signer's `kid` becomes
 * `proof.verificationMethod`, so it must be a DID URL under the document's `issuer`: a proof a
 * verifier would reject is refused here instead. Throws when the signer is not Ed25519, has no
 * `signRaw`, or the document already carries a proof.
 */
export async function signEddsaJcs2022<T extends Record<string, unknown>>(
  document: T,
  signer: ProofSigner,
  options: EddsaJcs2022SignOptions,
): Promise<T & { proof: EddsaJcs2022Proof }> {
  if (signer.alg !== undefined && signer.alg !== 'EdDSA') {
    throw new Error(`eddsa-jcs-2022 needs an Ed25519 signer, got ${signer.alg}`);
  }
  if (!signer.signRaw) throw new Error('eddsa-jcs-2022 needs a signer with signRaw');
  if (document.proof !== undefined) throw new Error('document already carries a proof');
  const issuer = issuerOf(document.issuer);
  if (issuer === undefined || signer.kid.split('#')[0] !== issuer) {
    throw new Error(`signer key ${signer.kid} is not a verification method of the issuer ${String(issuer)}`);
  }

  const proof = {
    type: 'DataIntegrityProof' as const,
    cryptosuite: 'eddsa-jcs-2022' as const,
    created: options.created ?? new Date().toISOString(),
    verificationMethod: signer.kid,
    proofPurpose: options.proofPurpose,
  };
  const config: Record<string, unknown> = { ...proof };
  if (document['@context'] !== undefined) config['@context'] = document['@context'];
  const signature = base64urlDecodeToBytes(await signer.signRaw(await hashData(config, document)));
  if (signature.length !== ED25519_SIGNATURE_LENGTH) throw new Error('signer returned a malformed Ed25519 signature');
  return { ...document, proof: { ...proof, proofValue: `z${base58Encode(signature)}` } };
}

/** The cryptosuite's hash data: SHA-256 of the canonical proof options, then of the canonical document. */
async function hashData(options: Record<string, unknown>, unsecured: Record<string, unknown>): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const proofHash = await sha256(encoder.encode(canonicalize(options)));
  const documentHash = await sha256(encoder.encode(canonicalize(unsecured)));
  const data = new Uint8Array(proofHash.length + documentHash.length);
  data.set(proofHash, 0);
  data.set(documentHash, proofHash.length);
  return data;
}

function contexts(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function startsWith(whole: unknown[], prefix: unknown[]): boolean {
  return prefix.length <= whole.length && prefix.every((entry, i) => canonicalize(entry) === canonicalize(whole[i]));
}
