/**
 * KYA-OS Middleware: what the delegation gate must be able to encode of a delegation it verified.
 *
 * The gate takes a digest of the delegation, and hands values of it on: into its audit record, into
 * the authorization context a tool and a composed policy gate receive, and into the grant it binds
 * for the next call. The audit trail service encodes each event in RFC 8785 form, which refuses a
 * lone surrogate, an integer of magnitude 2^53 or more and a number beyond the double range, and a
 * tool or a policy engine may encode what it receives the same way. So the gate checks every value
 * it hands on before it runs anything, whether or not an audit store is configured, and refuses a
 * delegation that holds one it cannot encode. A grant's credential passes the same check, without
 * being encoded, each time the grant authorizes a call.
 */

import type { DelegationCredential } from "../types/protocol.js";
import { assertCanonicalJsonValue, canonicalizeJsonBytes } from "../utils/canonical-json.js";

/** Why the gate refuses a delegation holding a value it cannot encode. */
export const UNENCODABLE_DELEGATION_REASON =
  "Delegation credential holds a value that cannot be encoded as RFC 8785 text";

/**
 * The members of `credential` whose values the gate hands on, each as the credential holds it:
 * - its `id` and its delegation's `id`: the delegation reference in the audit record and in the
 *   context's `authorization` is the credential's `id`, or its delegation's when it has none; both
 *   are checked, so whether a delegation is accepted does not depend on which of them it carries;
 * - its subject's `id`: the `actor` of the context and of every audit event, the context's
 *   `principal.agentDid` and the grant's `agentDid`;
 * - its delegation's `controller`: the context's `responsibleParty` and `principal.responsibleParty`,
 *   and the grant's `userDid`;
 * - its delegation's `parentId`: the audit record's `parentRef`;
 * - its delegation's `scopes` and the `scopes` of its `constraints`: together the context's
 *   `principal.delegatedScopes`, which a tool and a composed policy gate receive, and the grant's
 *   scopes. A list whose every element encodes yields only scopes that encode.
 */
function handedOnMembers(credential: DelegationCredential): unknown[] {
  const subject = credential.credentialSubject;
  const delegation = subject.delegation;
  return [
    credential.id,
    delegation.id,
    subject.id,
    delegation.controller,
    delegation.parentId,
    delegation.scopes,
    delegation.constraints?.scopes,
  ];
}

/**
 * Whether the gate can encode as RFC 8785 text every value it hands on from a verified delegation.
 * A credential with a Data Integrity proof (`jwt` undefined) is digested in its RFC 8785 form, so
 * all of it must encode, its unsigned `proof` included. A VC-JWT is digested as the JWT it arrived
 * as, which `jose` verified as base64url text, so only the members the gate hands on must encode,
 * and any other member of its credential may hold any value the JWT's JSON can. No bytes are made.
 */
export function isEncodableDelegation(credential: DelegationCredential, jwt: string | undefined): boolean {
  try {
    for (const value of jwt === undefined ? [credential] : handedOnMembers(credential)) {
      if (value !== undefined) assertCanonicalJsonValue(value);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * The bytes the gate takes the digest of a verified delegation over, or `undefined` when
 * {@link isEncodableDelegation} says it cannot encode a value it hands on: the RFC 8785 form of a
 * credential with a Data Integrity proof, whose writing checks every value as it goes, so it is
 * written once, or the text of a VC-JWT.
 */
export function encodableDelegationBytes(
  credential: DelegationCredential,
  jwt: string | undefined,
): Uint8Array | undefined {
  if (jwt !== undefined) return isEncodableDelegation(credential, jwt) ? new TextEncoder().encode(jwt) : undefined;
  try {
    return canonicalizeJsonBytes(credential);
  } catch {
    return undefined;
  }
}
