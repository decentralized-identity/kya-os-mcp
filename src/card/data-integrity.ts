/**
 * KYA-OS Entity Card: W3C Data Integrity `eddsa-jcs-2022` signing and verification, shared by the
 * status-list proof (./status-list-proof) and the delegation-hop proof (./delegation-proof).
 *
 * The construction is the cryptosuite's, step for step (W3C vc-di-eddsa §3.3): the proof states the
 * document's `@context` (§3.3.1 step 2), and the proof without `proofValue` and the document without
 * `proof` are each RFC 8785-canonicalized (../utils/canonical-json, which reads a member named
 * `toJSON` as data and refuses a value with no JSON form, such as an `undefined` member) and SHA-256
 * hashed; the signature is Ed25519 over the two hashes concatenated, `proofValue` is base58btc
 * multibase. A verifier puts `@context` in the configuration only when the proof states one, which
 * the document's must start with (§3.3.2 step 4), and during 1.x also accepts the shape 1.22.0 to
 * 1.25.0 issued ({@link verifiesAsLegacyProof}). The key is the issuer's verification method
 * `proof.verificationMethod` names, and that method must belong to the document's `issuer`, whose
 * DID document must list it under the verification relationship the proof purpose names
 * (../delegation/verification-relationship). A proof that does not verify returns `false`; an
 * issuer DID document that cannot be read throws a coded refusal instead, as the delegation
 * verifier codes it, since that says nothing about the proof.
 */

import { resolveExplained, unresolvedIssuer, type ExplainedResolution } from '../delegation/did-resolution-failure.js';
import { logger } from '../logging/index.js';
import { DeadlineExceededError } from '../utils/deadline.js';
import { RefusalError, refusalCodeOf } from '../utils/refusal.js';
import { loggedWords, WITHHELD_SUFFIX } from '../utils/thrown-words.js';
import { canonicalizeJson, canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { isRecord, issuerOf } from '../utils/guards.js';
import { base58Decode, base58Encode } from '../utils/base58.js';
import { base64urlDecodeToBytes } from '../utils/base64.js';
import { verificationMethodJwk } from '../delegation/verification-method-key.js';
import type { DIDDocument, DIDResolver } from '../delegation/vc-verifier.types.js';
import {
  retrieveVerificationMethod,
  type VerificationRelationship,
} from '../delegation/verification-relationship.js';
import { ed25519VerifyRaw, sha256, type RawSigningJwk } from './proof/canonical.js';
import type { ProofSigner } from './proof/types.js';

const ED25519_SIGNATURE_LENGTH = 64;
/** A 64-byte signature is at most 88 base58 characters; bound the decode before it runs. */
const MAX_PROOF_VALUE_BASE58 = 100;

/**
 * Verify a document's single `DataIntegrityProof` / `eddsa-jcs-2022` proof made for `proofPurpose`
 * by an Ed25519 key the issuer's DID document lists under the `proofPurpose` verification
 * relationship. Resolves `true` only when every check passes; a malformed proof, a key the document
 * does not list or lists only for other purposes resolves `false`. An issuer DID document that
 * cannot be read throws a {@link RefusalError} coded by why, as {@link issuerDocument} says, and one
 * not read within `timeoutMs`, by default 5,000 ms, a {@link DeadlineExceededError}, so a caller
 * that wants a boolean wraps the call, as {@link verifyEddsaJcs2022Proof} does.
 */
export async function verifyEddsaJcs2022(
  document: Record<string, unknown>,
  didResolver: DIDResolver,
  proofPurpose: VerificationRelationship,
  timeoutMs?: number,
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
  if (!issuer || did !== issuer) return false;

  const signature = base58Decode(proofValue.slice(1), MAX_PROOF_VALUE_BASE58);
  if (signature.length !== ED25519_SIGNATURE_LENGTH) return false;

  const didDocument = await issuerDocument(didResolver, did, verificationMethod, timeoutMs);
  const method = retrieveVerificationMethod(didDocument, did, verificationMethod, proofPurpose);
  const jwk = method ? verificationMethodJwk(method) : undefined;
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return false;

  return eddsaJcs2022Verifies(document, proof, signature, jwk);
}

/**
 * The cryptosuite's check, W3C vc-di-eddsa §3.3.2, with the 1.x allowance beside it: whether
 * `signature`, decoded from `proof.proofValue`, is the Ed25519 signature of `jwk` over `document`
 * and its `proof`. A proof that states `@context` verifies only when the document's `@context`
 * starts with it, entry for entry, and is signed with it as the document's. One that states none
 * verifies when signed without it, as §3.3.2 reads it, or, until 2.0.0, with the document's
 * `@context` in its configuration ({@link verifiesAsLegacyProof}). Where the key comes from is the
 * caller's to check, as {@link verifyEddsaJcs2022} does.
 */
export async function eddsaJcs2022Verifies(
  document: Record<string, unknown>,
  proof: Record<string, unknown>,
  signature: Uint8Array,
  jwk: RawSigningJwk,
): Promise<boolean> {
  const unsecured: Record<string, unknown> = { ...document };
  delete unsecured.proof;
  const options: Record<string, unknown> = { ...proof };
  delete options.proofValue;
  if (options['@context'] !== undefined) {
    if (!startsWith(contexts(document['@context']), contexts(options['@context']))) return false;
    unsecured['@context'] = options['@context'];
  }
  const documentHash = await jcsHash(unsecured);
  const signedWith = async (configuration: Record<string, unknown>): Promise<boolean> =>
    ed25519VerifyRaw(jwk, signature, hashData(await jcsHash(configuration), documentHash));
  if (await signedWith(options)) return true;
  return verifiesAsLegacyProof(options, unsecured['@context'], signedWith);
}

/**
 * LEGACY, for the 1.x line only; remove at 2.0.0 (DEPRECATIONS.md). From 1.22.0 to 1.25.0 the
 * library, like other issuers then, signed the document's `@context` in the proof configuration
 * but did not state it in the proof, so a proof that states no `@context` is checked once more
 * with the document's in its configuration. It checks only such a proof of a document that has a
 * `@context`, and only once the standard check has refused it: one more signature check, over the
 * document hash already taken, on a refusal alone.
 */
async function verifiesAsLegacyProof(
  options: Record<string, unknown>,
  documentContext: unknown,
  signedWith: (configuration: Record<string, unknown>) => Promise<boolean>,
): Promise<boolean> {
  if (options['@context'] !== undefined || documentContext === undefined) return false;
  return signedWith({ ...options, '@context': documentContext });
}

/**
 * {@link verifyEddsaJcs2022} as a proof verifier seam answers: `true` or `false` for the proof, a
 * refusal coded by why when the issuer's DID document cannot be read, and a
 * {@link DeadlineExceededError} when it is not read in time, both for the caller to code as it codes
 * any throw. Any other throw, from a proof the decoder or the signature check cannot read, is `false`.
 */
export async function verifyEddsaJcs2022Proof(
  document: Record<string, unknown>,
  didResolver: DIDResolver,
  proofPurpose: VerificationRelationship,
  timeoutMs?: number,
): Promise<boolean> {
  try {
    return await verifyEddsaJcs2022(document, didResolver, proofPurpose, timeoutMs);
  } catch (error) {
    if (error instanceof RefusalError || error instanceof DeadlineExceededError) throw error;
    return false;
  }
}

/**
 * The DID document of `did`, the proof's issuer, resolved within the limits for its key `key`. When
 * none is found it throws a {@link RefusalError} as the delegation verifier refuses the DID: `Could
 * not resolve issuer DID`, with the code of the cause the resolver reports and its detail where a
 * refusal shows it, or `did_invalid` when the limits refused it. A resolver that throws is
 * `did_unavailable`, unless its error carries a code of its own, and its words are logged, never
 * shown, the refusal saying the log has them; a deadline that passes rejects as it does.
 */
async function issuerDocument(
  didResolver: DIDResolver, did: string, key: string, timeoutMs: number | undefined,
): Promise<DIDDocument> {
  const unresolved = (why: string): string => `${unresolvedIssuer(did)}${why}`;
  let resolved: ExplainedResolution;
  try {
    resolved = await resolveExplained(didResolver, did, key, timeoutMs);
  } catch (error) {
    if (error instanceof RefusalError || error instanceof DeadlineExceededError) throw error;
    logger.warn(`[eddsa-jcs-2022] Resolving ${did} failed: ${loggedWords(error)}`);
    throw new RefusalError(refusalCodeOf(error, 'did_unavailable'), unresolved(WITHHELD_SUFFIX));
  }
  if (resolved.document === null) throw new RefusalError(resolved.code, unresolved(resolved.why));
  return resolved.document;
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
  /** The document's `@context` when it has one, which the signature covers (W3C vc-di-eddsa §3.3.1 step 2). */
  '@context'?: unknown;
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
 * verifier would reject is refused here instead. The proof states the document's `@context`, when
 * it has one, and the signature covers it there, as W3C vc-di-eddsa §3.3.1 step 2 has an issuer
 * do; the signature is the one 1.22.0 to 1.25.0 made, which did not state it. Throws when the
 * signer is not Ed25519, has no `signRaw`, or the document already carries a proof, and with a
 * `TypeError` when the document holds a value with no JSON form, such as an `undefined` member,
 * which is not dropped.
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

  const proof: Omit<EddsaJcs2022Proof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: options.created ?? new Date().toISOString(),
    verificationMethod: signer.kid,
    proofPurpose: options.proofPurpose,
    ...(document['@context'] === undefined ? {} : { '@context': copyOf(document['@context']) }),
  };
  const data = hashData(await jcsHash(proof), await jcsHash(document));
  const signature = base64urlDecodeToBytes(await signer.signRaw(data));
  if (signature.length !== ED25519_SIGNATURE_LENGTH) throw new Error('signer returned a malformed Ed25519 signature');
  return { ...document, proof: { ...proof, proofValue: `z${base58Encode(signature)}` } };
}

/** SHA-256 of `value`'s RFC 8785 form. */
async function jcsHash(value: Record<string, unknown>): Promise<Uint8Array> {
  return sha256(canonicalizeJsonBytes(value));
}

/** The cryptosuite's hash data: the proof configuration's hash, then the document's. */
function hashData(configurationHash: Uint8Array, documentHash: Uint8Array): Uint8Array {
  const data = new Uint8Array(configurationHash.length + documentHash.length);
  data.set(configurationHash, 0);
  data.set(documentHash, configurationHash.length);
  return data;
}

/**
 * The document's `@context` for its proof to state. An array is copied, so that a context appended
 * to the document in place after signing, as §3.3.2 step 4 allows, leaves the proof's as signed.
 */
function copyOf(context: unknown): unknown {
  return Array.isArray(context) ? [...context] : context;
}

function contexts(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function startsWith(whole: unknown[], prefix: unknown[]): boolean {
  return prefix.length <= whole.length && prefix.every((entry, i) => canonicalizeJson(entry) === canonicalizeJson(whole[i]));
}
