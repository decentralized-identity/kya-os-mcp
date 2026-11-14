/**
 * The signed form of a delegation credential (SPEC.md §7.8): what its
 * issuer's signature covers, and that signature.
 *
 * This is the one definition of it. A credential's signature is checked over
 * {@link signingInput} of its signed form, and the chain digest hashes
 * {@link digestInput} of the same form, so what verified and what is digested
 * are one thing. Were the two derived separately, a member one reading kept
 * and the other dropped, or a signature string one decoded and the other did
 * not, would let a credential verify as its issuer signed it and be digested
 * as something else.
 *
 * Pure: no transport, no framework, no key material.
 */

import { CanonicalJsonError, canonicalizeJsonBytes, jsonMemberValue } from '../utils/canonical-json.js';
import { base64urlEncodeFromBytes } from '../utils/base64.js';
import { base64EitherBytes, jwsSegmentBytes } from '../utils/base64-reading.js';
import { isRecord } from '../utils/guards.js';
import { MAX_JSON_NESTING_DEPTH } from '../utils/json-preflight.js';
import { nestsDeeperThan } from '../utils/plain-data.js';

/**
 * A credential as a verifier holds it: the compact VC-JWT string, or the
 * credential object with its `proof`.
 */
export type ReceivedCredential = string | object;

/** A VC-JWT in its signed form: its header and payload segments as received, and the signature. */
export interface SignedJwt {
  /** `<header>.<payload>`, the JWS signing input. */
  jwt: string;
  signature: Uint8Array;
}

/** A credential object in its signed form: the object without `proof`, and the signature. */
export interface SignedCredential {
  credential: Record<string, unknown>;
  signature: Uint8Array;
}

/** A credential in its signed form. */
export type SignedForm = SignedJwt | SignedCredential;

/**
 * The deepest the arrays and objects of a credential may nest (SPEC §7.8).
 * A credential object is level 1, and an array or object inside another is
 * one level deeper. A credential object that nests deeper, in what its issuer
 * signed or in its `proof`, has no signed form. The header and the payload of
 * a VC-JWT are counted the same way, each from its own outermost object, and
 * one that nests deeper is not read as JSON.
 *
 * The number is the protocol's, the same for every implementation, so that
 * whether a credential verifies and has a digest does not turn on how deep a
 * call stack the runtime reading it has. It is the package's one bound on
 * nesting, declared in `../utils/json-preflight.ts`.
 */
export const MAX_CREDENTIAL_NESTING_DEPTH = MAX_JSON_NESTING_DEPTH;

/**
 * Thrown for a value that has no signed form (SPEC §7.8): it is neither a
 * compact VC-JWT nor a credential object with a `proof.proofValue`, its
 * signature string is not a signature, it is an object nested more than
 * {@link MAX_CREDENTIAL_NESTING_DEPTH} levels deep, or what the signature
 * covers has no canonical JSON form. Such a value is no credential, and has
 * no digest.
 *
 * A `TypeError`, since it is the value that is wrong. The class tells that
 * apart from every other failure on the way to a digest, a hash provider's
 * say, which is nothing the value did.
 */
export class NoSignedFormError extends TypeError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'NoSignedFormError';
  }
}

/**
 * A {@link NoSignedFormError} for what a credential object holds, not for
 * its signature string: it nests more than
 * {@link MAX_CREDENTIAL_NESTING_DEPTH} levels deep, or what its issuer signed
 * has no canonical JSON form. So a refusal can say which of the two was
 * wrong.
 */
export class CredentialContentError extends NoSignedFormError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CredentialContentError';
  }
}

const encoder = new TextEncoder();

/**
 * The bytes a `proofValue` carries, as {@link base64EitherBytes} reads them
 * (SPEC §7.8): base64 or base64url, padded or not, across lines or not. A
 * VC-JWT's signature is not read this way: see {@link decodeJwsSegment}.
 *
 * @throws {NoSignedFormError} for a string outside that reading: it is not a
 *   signature.
 */
export function decodeSignature(encoded: string): Uint8Array {
  return readOrRefuse(base64EitherBytes(encoded), 'A credential signature is base64url');
}

/**
 * The bytes a segment of a compact JWS carries, as {@link jwsSegmentBytes}
 * reads them (SPEC §7.8): base64url as RFC 7515 §2 has it. A VC-JWT that
 * verified before this reading existed still verifies, and one that did not
 * still does not.
 *
 * @throws {NoSignedFormError} for a string outside that reading.
 */
export function decodeJwsSegment(encoded: string): Uint8Array {
  return readOrRefuse(jwsSegmentBytes(encoded), 'A JWS segment is base64url (RFC 7515 §2)');
}

/** The bytes a reading gave, or a refusal that the string carries no signature. */
function readOrRefuse(bytes: Uint8Array | undefined, refusal: string): Uint8Array {
  if (bytes === undefined) throw new NoSignedFormError(refusal);
  return bytes;
}

/** A signature's bytes as `decode` reads them, of which there must be at least one. */
function signatureBytes(encoded: unknown, decode: (encoded: string) => Uint8Array): Uint8Array {
  const bytes = typeof encoded === 'string' ? decode(encoded) : new Uint8Array();
  if (bytes.length === 0) {
    throw new NoSignedFormError('A credential signature is base64url of at least one byte');
  }
  return bytes;
}

/**
 * A credential object without its `proof` member: what a §6.2 signature
 * covers. Every other own member is kept, with its own descriptor, for the
 * canonicalizer to read or refuse as it would the credential. A member named
 * `__proto__` therefore stays a member, where assigning it would set a
 * prototype and drop it; an accessor stays an accessor, which has no
 * canonical form, where reading it would let it answer differently the next
 * time; and a member keyed by a symbol, which has no JSON form, is not left
 * behind for the rest to pass without it.
 */
export function credentialWithoutProof(credential: object): Record<string, unknown> {
  const unsigned = {};
  for (const key of Reflect.ownKeys(credential)) {
    if (key === 'proof') continue;
    Object.defineProperty(unsigned, key, Object.getOwnPropertyDescriptor(credential, key)!);
  }
  return unsigned;
}

/**
 * A credential object in its signed form.
 *
 * The nesting bound is applied here, on the whole object, by a count that
 * takes no call stack. This is where every reading of a credential object
 * starts, the signature check and the digest alike, so nothing that recurses
 * reads one that is deeper.
 *
 * Its `proof`, and the `proofValue` in that, are read as the JSON form of
 * the object has them ({@link jsonMemberValue}): a member that is not
 * enumerable is not there, and an accessor is not called.
 *
 * @throws {NoSignedFormError} when it has none: no `proof.proofValue`, or
 *   one that is not a signature; a {@link CredentialContentError} for arrays
 *   and objects nested more than {@link MAX_CREDENTIAL_NESTING_DEPTH} levels
 *   deep.
 */
export function signedCredential(credential: object): SignedCredential {
  const proof = jsonMemberValue(credential, 'proof');
  if (!isRecord(credential) || !isRecord(proof)) {
    throw new NoSignedFormError('A credential object carries its signature in proof.proofValue');
  }
  if (nestsDeeperThan(credential, MAX_CREDENTIAL_NESTING_DEPTH)) {
    throw new CredentialContentError(
      `A credential object nests at most ${MAX_CREDENTIAL_NESTING_DEPTH} levels deep`,
    );
  }
  return {
    credential: credentialWithoutProof(credential),
    signature: signatureBytes(jsonMemberValue(proof, 'proofValue'), decodeSignature),
  };
}

/**
 * A compact VC-JWT in its signed form.
 *
 * @throws {NoSignedFormError} when it has none: it is not three segments, of
 *   which the header and the payload are not empty, or its last segment is
 *   not a signature as {@link decodeJwsSegment} reads one.
 */
export function signedJwt(jwt: string): SignedJwt {
  const segments = jwt.split('.');
  if (segments.length !== 3 || segments[0] === '' || segments[1] === '') {
    throw new NoSignedFormError('A VC-JWT is a compact JWS: header.payload.signature');
  }
  return {
    jwt: `${segments[0]}.${segments[1]}`,
    signature: signatureBytes(segments[2], decodeJwsSegment),
  };
}

/**
 * A credential in its signed form.
 *
 * @throws {NoSignedFormError} for a value that has none (see {@link signedJwt}
 *   and {@link signedCredential}), or is neither a string nor an object.
 */
export function signedForm(credential: ReceivedCredential): SignedForm {
  if (typeof credential === 'string') return signedJwt(credential);
  if (!isRecord(credential)) {
    throw new NoSignedFormError('A delegation credential is a compact VC-JWT string or a credential object');
  }
  return signedCredential(credential);
}

/**
 * The RFC 8785 bytes of `value`: the one canonicalization the signature check
 * and the digest both read a credential through.
 *
 * Only the canonicalizer's own refusal says that the value has no canonical
 * form. Anything else it throws is a fault, and is thrown on as it is: a
 * call stack that ran out is the runtime's limit, not a property of the
 * value, and is not reported as one.
 */
function canonicalBytes(value: unknown): Uint8Array {
  try {
    return canonicalizeJsonBytes(value);
  } catch (error) {
    if (!(error instanceof CanonicalJsonError)) throw error;
    throw new CredentialContentError(
      `What a credential's signature covers has no canonical JSON form: ${error.message}`,
      { cause: error },
    );
  }
}

/**
 * The bytes a credential's signature is checked over (SPEC §7.8): the
 * RFC 8785 form of a credential object without its `proof`, or the two
 * segments of a VC-JWT as received. A verifier that checks `form.signature`
 * over these bytes has verified exactly what {@link digestInput} hashes.
 *
 * @throws {CredentialContentError} when the credential object has no
 *   canonical JSON form.
 */
export function signingInput(form: SignedForm): Uint8Array {
  return 'jwt' in form ? encoder.encode(form.jwt) : canonicalBytes(form.credential);
}

/**
 * The JSON value a credential digest is taken over (SPEC §7.8): the signed
 * form with its signature written as base64url without padding, the one way
 * every string for that signature comes out.
 */
export function signedFormJson(form: SignedForm): Record<string, unknown> {
  const { signature, ...content } = form;
  return { ...content, signature: base64urlEncodeFromBytes(signature) };
}

/**
 * The bytes a credential digest is taken over (SPEC §7.8): the RFC 8785 form
 * of {@link signedFormJson}.
 *
 * @throws {CredentialContentError} when the credential object has no
 *   canonical JSON form.
 */
export function digestInput(form: SignedForm): Uint8Array {
  return canonicalBytes(signedFormJson(form));
}

/**
 * A compact VC-JWT with its signature segment written canonically. It names
 * the same JWS. A verifier handed this string reads the signature bytes
 * {@link signedJwt} gives, whatever its own decoder passes over.
 *
 * @throws {NoSignedFormError} as {@link signedJwt} does.
 */
export function canonicalVcJwt(jwt: string): string {
  const form = signedJwt(jwt);
  return `${form.jwt}.${base64urlEncodeFromBytes(form.signature)}`;
}
