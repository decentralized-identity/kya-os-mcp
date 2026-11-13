/**
 * Verification methods by verification relationship: the key a proof may be checked with, retrieved
 * under the own-issuer profile of W3C Controlled Identifiers v1.0 (CID) §3.3 for a verification
 * relationship. Every verifier of a delegation credential, a status list or a delegation hop takes
 * its key from a DID document this way: the delegation credential's Data Integrity proof and VC-JWT
 * envelope, the status lists `CheqdStatusListResolver` reads, and the Entity Card's
 * `eddsa-jcs-2022` proofs on status lists and delegation hops. `ProofVerifier`, for a detached
 * request proof, and `didKeyedJwks` still read every key a document publishes: SPEC.md does not yet
 * say which relationship lists those keys.
 *
 * A DID document publishes keys, and its verification relationships say what each key is for:
 * `assertionMethod` for the subject's credentials and other claims, `authentication` for signing
 * in, and so on (CID §2.3). CID §3.3 step 11 requires the retrieved method to be associated with the
 * expected relationship, by reference (an absolute DID URL or a relative `#fragment`) or by value
 * (embedded), so a proof made for a purpose verifies only with a key the document lists under the
 * relationship of that name. VC Data Integrity §5.10 explains why that matters: a key its
 * controller keeps for signing in is not thereby a key that issues its credentials.
 *
 * Only a DID's own document and its own methods count: a document whose `id` is another DID, and a
 * method whose id is under another DID, are never used, and {@link selectAssertionMethod} says which
 * DID a method it would otherwise select belongs to. A method retrieved, referenced or embedded,
 * must have a non-empty string `id`, `type` and `controller` (CID §3.3 step 8,
 * ./verification-method-shape), and its `controller` must be the DID (step 10): a method refers
 * back to the document that lists it, so a document cannot claim a key another DID controls. An id
 * the document defines more than once, among `verificationMethod` and the methods the relationship
 * embeds, names no method, since which key it means is ambiguous. A proof that states a purpose must
 * state the relationship its key is retrieved for ({@link proofPurposeMismatch}).
 *
 * A DID document is the counterparty's to write, and so is the DID a lookup reads it for, so what
 * a lookup costs is bounded by what it is given. For parsed JSON, let S count its UTF-16 units
 * and entries, D the DID length and K the requested id length. Check the document and DID once
 * in O(S + D), and make the target relative once in O(K). Scan each published and relationship
 * entry once; making its id relative, comparing it with the target and checking its controller
 * each cost at most that entry's own length. No DID is prepended to an entry. Slicing copies at
 * most the id's length. Thus time is O(S + D + K), with no hash-table assumption. Keep only one
 * candidate and a duplicate flag; a duplicate still counts when malformed or controlled elsewhere.
 * With no name, {@link selectAssertionMethod} reads the first `assertionMethod` entry, then performs
 * this same lookup once.
 * ./__tests__/verification-relationship-scaling.test.ts times it in a document and in one 16 times
 * its size, and holds the ratio of the two times far below quadratic.
 */

import { isRecord } from '../utils/guards.js';
import { describeValue } from '../utils/describe-value.js';
import { hasIdTypeAndController } from './verification-method-shape.js';
import type { DIDDocument, VerificationMethod } from './vc-verifier.types.js';

/** A verification relationship a DID document can list a method under (CID §2.3). */
export type VerificationRelationship =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

/**
 * The relationship of an issuer's assertions: the key of a delegation credential, a status list or
 * a delegation hop is retrieved for it, and its proof states it as `proofPurpose`.
 */
export const ASSERTION_METHOD = 'assertionMethod' satisfies VerificationRelationship;

/**
 * The verification method `vmIdentifier` names (a DID URL such as `did:web:acme.example#key-1`, or
 * `#key-1` read against `did`), when `didDocument`, `did`'s own document, lists it under
 * `relationship` and it is a method of `did`; otherwise `undefined`.
 */
export function retrieveVerificationMethod(
  didDocument: DIDDocument,
  did: string,
  vmIdentifier: string,
  relationship: VerificationRelationship,
): VerificationMethod | undefined {
  const found = lookUp(didDocument, did, vmIdentifier, relationship);
  return found !== undefined && 'method' in found ? found.method : undefined;
}

/**
 * The key a proof of an issuer's assertion is checked with, or why there is none:
 * - `method`: the method the proof names, or with no name the first `assertionMethod` entry names;
 * - `not a name`: the proof names its key by something other than a non-empty string, which names
 *   no key and is never read as naming none;
 * - `not listed`: `assertionMethod` lists no method of `did` by that name
 *   ({@link retrieveVerificationMethod});
 * - `no usable first entry`: the proof names no key, and the first entry names no method of `did`;
 * - `another DID`: the method named, or named first, would be selected but that its `controller`, or
 *   its document's `id`, is another DID, as `reason` says.
 */
export type AssertionMethodSelection =
  | { readonly method: VerificationMethod }
  | AssertionMethodRefusal;

/** Why {@link selectAssertionMethod} selects no method. */
export type AssertionMethodRefusal =
  | { readonly refused: 'not a name' | 'not listed' | 'no usable first entry' }
  | { readonly refused: 'another DID'; readonly reason: string };

/**
 * The method a proof that `did` asserts with is checked with, by the name `named` it gives its key:
 * the method `assertionMethod` lists under that name, or, when `named` is undefined, the one its
 * first entry names, so a proof costs one signature check. Later entries are never tried: an issuer
 * that signs with another key names it. Every verifier of a delegation credential and a status list
 * selects its key here: the VC-JWT `kid`, a Data Integrity proof's `verificationMethod`, and the
 * proof of a status list `CheqdStatusListResolver` reads. The Entity Card's `eddsa-jcs-2022` proofs
 * must name their key by a DID URL of the issuer, so they retrieve it by that name alone
 * ({@link retrieveVerificationMethod}).
 */
export function selectAssertionMethod(
  didDocument: DIDDocument,
  did: string,
  named: unknown,
): AssertionMethodSelection {
  if (named !== undefined && !isName(named)) return { refused: 'not a name' };
  const name = named ?? firstEntryId(didDocument[ASSERTION_METHOD]);
  const found = name === undefined ? undefined : lookUp(didDocument, did, name, ASSERTION_METHOD);
  if (found === undefined) return { refused: named === undefined ? 'no usable first entry' : 'not listed' };
  if ('method' in found) return found;
  const method = `Verification method ${describeValue(name)} under ${ASSERTION_METHOD} of ${describeValue(did)}`;
  return { refused: 'another DID', reason: `${method} has another DID as its ${found.member}: ${describeValue(found.otherDid)}` };
}

/**
 * The reason a verifier gives for `refusal`, which {@link selectAssertionMethod} returned for a proof
 * of `did`'s that names its key by `named`. `naming` is what that verifier calls the name, such as
 * `JWT kid`, `Proof verificationMethod` or `Status list proof verificationMethod`. The reason quotes
 * `named` and `did` as {@link describeValue} quotes any value the other party chose.
 */
export function assertionMethodRefusal(refusal: AssertionMethodRefusal, naming: string, named: unknown, did: string): string {
  switch (refusal.refused) {
    case 'not a name':
      return `${naming} ${describeValue(named)} is not a DID URL`;
    case 'not listed':
      return `Verification method ${describeValue(named)} not found under ${ASSERTION_METHOD} of ${describeValue(did)}`;
    case 'no usable first entry':
      return `${naming} is absent, and ${ASSERTION_METHOD} of ${describeValue(did)} has no usable first entry`;
    case 'another DID':
      return refusal.reason;
    default: {
      const unhandled: never = refusal;
      return unhandled;
    }
  }
}

/**
 * What a lookup of one method id finds: the method; or a method the relationship lists that would be
 * the one named, but that its `controller`, or its document's `id`, names `otherDid`; or nothing.
 */
type Lookup =
  | { readonly method: VerificationMethod }
  | { readonly otherDid: string; readonly member: 'controller' | "document's id" }
  | undefined;

function lookUp(
  didDocument: DIDDocument,
  did: string,
  vmIdentifier: string,
  relationship: VerificationRelationship,
): Lookup {
  if (did.includes('#')) return undefined;
  const entries: unknown = didDocument[relationship];
  if (!Array.isArray(entries)) return undefined;
  const target = relativeId(vmIdentifier, did);
  if (target === undefined) return undefined;

  let candidate: VerificationMethod | undefined;
  let duplicate = false;
  let listed = false;
  const define = (entry: unknown): boolean => {
    if (!isMethod(entry) || relativeId(entry.id, did) !== target) return false;
    if (candidate !== undefined) duplicate = true;
    candidate = entry;
    return true;
  };
  const published: unknown = didDocument.verificationMethod;
  if (Array.isArray(published)) for (const entry of published) define(entry);
  for (const entry of entries as unknown[]) {
    if (typeof entry === 'string') {
      if (relativeId(entry, did) === target) listed = true;
    } else {
      if (define(entry)) listed = true;
    }
  }
  if (!listed || duplicate || candidate === undefined || !hasIdTypeAndController(candidate)) return undefined;
  const documentId: unknown = didDocument.id;
  if (documentId !== did) {
    return typeof documentId === 'string' ? { otherDid: documentId, member: "document's id" } : undefined;
  }
  if (candidate.controller !== did) return { otherDid: candidate.controller, member: 'controller' };
  return { method: candidate };
}

/** The id the first entry of a relationship gives: the entry itself, or the id of an embedded method. */
function firstEntryId(entries: unknown): string | undefined {
  const first: unknown = Array.isArray(entries) ? entries[0] : undefined;
  return typeof first === 'string' ? first : isMethod(first) ? first.id : undefined;
}

/** Whether a key name a proof gives is one: a non-empty string. */
function isName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Why `proof` is refused for stating a `proofPurpose` other than `relationship`, or `undefined` when
 * it states `relationship` or no purpose at all. Reading an absent purpose as `relationship` is the
 * SPEC.md §6.2 profile's rule: its construction leaves the purpose outside the signature, so it is
 * the key's listing under that relationship that holds the proof to it. The reason names the
 * stated purpose as {@link describeValue} names any value the other party chose.
 */
export function proofPurposeMismatch(proof: unknown, relationship: VerificationRelationship): string | undefined {
  const stated = isRecord(proof) ? proof.proofPurpose : undefined;
  return stated === undefined || stated === relationship
    ? undefined
    : `Proof purpose ${describeValue(stated)} is not ${relationship}`;
}

function isMethod(value: unknown): value is VerificationMethod {
  return isRecord(value) && typeof value.id === 'string';
}

/**
 * A method id of `did` relative to `did`, the form a lookup compares: a `#fragment` as
 * it is written, the `#fragment` that follows `did` in an absolute id, and `''` for `did` itself.
 * `undefined` for any other id, such as one under another DID, or under a path or query of `did`.
 * It reads `did` no further than `id` reaches, so it costs at most `id`'s own length.
 */
function relativeId(id: string, did: string): string | undefined {
  if (id.startsWith('#')) return id;
  if (!id.startsWith(did)) return undefined;
  if (id.length === did.length) return '';
  return id[did.length] === '#' ? id.slice(did.length) : undefined;
}
