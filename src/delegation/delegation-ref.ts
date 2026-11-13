/**
 * The reference a delegation credential goes by (SPEC.md §7.8).
 *
 * The audit trail names the delegation a call presented by `delegationRef`,
 * and a response proof may. It is derived from the id the credential shows,
 * and it is only a name: nothing stops two credentials from showing one id,
 * and `delegationChainDigest` is what pins a chain. What a reference has to be
 * is one string for everyone who derives it, so that a proof, an audit event
 * and a verifier holding the credential can be compared by it. This is that
 * derivation, and the only one.
 *
 * Pure: no transport, no framework, no key material.
 */

import { jsonMemberValue } from '../utils/canonical-json.js';
import { isRecord } from '../utils/guards.js';
import { hasUnprintableCharacter, isWellFormedUnicode } from '../utils/plain-text.js';
import type { Sha256 } from './chain-digest.js';
import { delegationIdMember, NO_DELEGATION_ID } from './delegation-id.js';
import { isDigest } from './digest-form.js';
import { jwsSegmentsJson } from './jws-segment.js';

/** An id longer than this, in UTF-16 code units, is referred to by its digest. */
const MAX_VERBATIM_LENGTH = 256;

const encoder = new TextEncoder();

/**
 * A member's value as the JSON form of `object` has it ({@link jsonMemberValue}):
 * an accessor is not read, and nothing inherited or not enumerable is.
 */
const member = jsonMemberValue;

/** A non-empty string, or nothing. */
const idOf = (value: unknown): string | undefined =>
  typeof value === 'string' && value.length > 0 ? value : undefined;

/**
 * The claims of a compact VC-JWT: its payload segment read `strict`
 * ({@link jwsSegmentsJson}), as a JWS segment, as UTF-8 and as JSON, each
 * strictly. A payload whose arrays and objects nest deeper than a credential
 * may (`MAX_CREDENTIAL_NESTING_DEPTH`) is not read as JSON at all.
 *
 * @throws when the string is not three segments, or its payload is not read
 *   so.
 */
function jwtClaims(jwt: string): unknown {
  const segments = jwt.split('.');
  if (segments.length !== 3) throw new TypeError('A VC-JWT is a compact JWS');
  return jwsSegmentsJson([segments[1]!], 'strict')[0];
}

/**
 * The id a delegation credential shows (SPEC §7.8), in the form it was
 * presented in: the first of these that is a non-empty string.
 *
 * - A credential object: its `id`, then `credentialSubject.delegation.id`.
 * - A compact VC-JWT, whose payload is a JSON object with an object `vc`:
 *   `vc.id`, then `jti` (where the VC-JWT mapping puts a credential's id),
 *   then `vc.credentialSubject.delegation.id`. A payload nested more than
 *   `MAX_CREDENTIAL_NESTING_DEPTH` levels deep is not read, and shows no id.
 *
 * Undefined for anything else, and for a credential that shows none. The
 * value is read as untrusted data, and as its JSON form has it: own
 * enumerable data members only, so an accessor, an inherited member and one
 * that is not enumerable are not an id. It never throws.
 */
export function delegationCredentialId(credential: unknown): string | undefined {
  try {
    if (typeof credential === 'string') {
      const claims = jwtClaims(credential);
      const vc = isRecord(claims) ? member(claims, 'vc') : undefined;
      if (!isRecord(claims) || !isRecord(vc)) return undefined;
      return idOf(member(vc, 'id')) ?? idOf(member(claims, 'jti')) ?? idOf(delegationIdMember(vc));
    }
    if (!isRecord(credential)) return undefined;
    return idOf(member(credential, 'id')) ?? idOf(delegationIdMember(credential));
  } catch {
    return undefined;
  }
}

/**
 * The reference for a credential id (SPEC §7.8): the id itself, or its
 * digest where the id is not fit to be recorded as it stands.
 *
 * An id is referred to by `hash(UTF8(id))`, which reads `sha256:<64 lowercase
 * hex>`, when it is longer than 256 UTF-16 code units, when it holds a
 * character that does not print as itself (a control or format character, a
 * line or paragraph separator, or a surrogate without its pair), when it
 * already reads as such a digest, and when it is `unknown`. The last two keep
 * the forms unambiguous: a reference that reads as a digest is always the
 * digest of an id, and `unknown`, which an audit record names a credential
 * that shows no id by, never stands for one that does.
 *
 * A surrogate without its pair has no UTF-8 encoding of its own, and is
 * encoded as the three bytes of its code point (WTF-8), so that every id has
 * one reference and two implementations agree on it. Undefined for an empty
 * id.
 */
export async function delegationReference(id: string, hash: Sha256): Promise<string | undefined> {
  if (typeof id !== 'string' || id.length === 0) return undefined;
  const verbatim =
    id.length <= MAX_VERBATIM_LENGTH && !hasUnprintableCharacter(id) && !isDigest(id) && id !== NO_DELEGATION_ID;
  return verbatim ? id : hash(wtf8(id));
}

/**
 * A string's UTF-8 bytes, a surrogate without its pair written as the three
 * bytes UTF-8 gives any other code point of its size: WTF-8, which is UTF-8
 * itself for a string that is well-formed Unicode.
 */
function wtf8(text: string): Uint8Array {
  if (isWellFormedUnicode(text)) return encoder.encode(text);
  const parts: number[] = [];
  for (const character of text) {
    const code = character.codePointAt(0)!;
    if (code >= 0xd800 && code <= 0xdfff) parts.push(0xed, 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else parts.push(...encoder.encode(character));
  }
  return Uint8Array.from(parts);
}

/**
 * The reference a credential goes by: {@link delegationReference} of
 * {@link delegationCredentialId}. A proof that names a delegation and binds
 * its chain carries this for the chain's last credential, as `delegationRef`.
 * Undefined for a credential that shows no id.
 */
export async function delegationRefOf(credential: unknown, hash: Sha256): Promise<string | undefined> {
  const id = delegationCredentialId(credential);
  return id === undefined ? undefined : delegationReference(id, hash);
}
