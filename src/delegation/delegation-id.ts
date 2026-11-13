/**
 * Where a delegation credential carries the id of its delegation, and the
 * word an audit record names a delegation by when its credential shows no id
 * (SPEC.md §7.8). The readings of `./delegation-ref.ts` and the chain walk's
 * (`./resolved-chain.ts`) read the id here, so they read one member one way.
 *
 * Pure: no transport, no framework, no key material.
 */

import { jsonMemberValue } from '../utils/canonical-json.js';
import { isRecord } from '../utils/guards.js';

/**
 * What an audit record names a delegation by when its credential shows no
 * id. An id written so is referred to by its digest (SPEC.md §7.8), so the
 * word never stands for a credential that does show one.
 */
export const NO_DELEGATION_ID = 'unknown';

/**
 * How many levels of a credential object hold the ids it shows: the
 * credential, its `credentialSubject`, and that subject's `delegation`.
 */
export const DELEGATION_ID_LEVELS = 3;

/**
 * The value at `credentialSubject.delegation.id`, read as the JSON form of
 * the credential has it ({@link jsonMemberValue}): an accessor is not read,
 * and nothing inherited or not enumerable is. Undefined where there is none.
 */
export function delegationIdMember(credential: unknown): unknown {
  const subject = isRecord(credential) ? jsonMemberValue(credential, 'credentialSubject') : undefined;
  const delegation = isRecord(subject) ? jsonMemberValue(subject, 'delegation') : undefined;
  return isRecord(delegation) ? jsonMemberValue(delegation, 'id') : undefined;
}
