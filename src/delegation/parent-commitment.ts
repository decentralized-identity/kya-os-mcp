/**
 * A re-delegation's commitment to its parent: `parentCredentialDigest` (SPEC.md §6.2, §6.10).
 *
 * A credential names its parent by an id, and an id is a name: nothing stops a parent from being
 * issued again under the id of another. A re-delegation that states the SPEC §7.8 digest of its
 * parent credential commits to that one credential, signature included. The digest of a credential
 * covers what it states, so a chain whose every hop states its parent's digest is fixed by the
 * digest of its last credential alone: a holder that names the credential it presents
 * (`./stated-delegation.ts`) then fixes every ancestor too, without knowing them.
 *
 * The member is read where each profile puts it: in `credentialSubject.delegation` of a base
 * profile credential (SPEC §6.2), and in `credentialSubject` of an Entity Card hop (SPEC §6.10).
 * A credential states it when it holds the member, whatever its value.
 *
 * Pure but for the default hash: no transport, no framework, no key material.
 */

import { delegationCredentialDigest, type ReceivedCredential, type Sha256 } from './chain-digest.js';
import { NoSignedFormError } from './signed-form.js';
import { parseVCJWT } from './utils.js';
import type { Digest } from '../audit/types.js';
import { webCryptoSha256 } from '../utils/domain-digest.js';
import { isRecord } from '../utils/guards.js';

/** The member that commits a re-delegation to its parent credential. */
export const PARENT_CREDENTIAL_DIGEST = 'parentCredentialDigest';

/** What a credential says of its parent. */
export interface ParentReference {
  /** Whether it names a parent at all: a root does not. */
  readonly named: boolean;
  /** The `parentCredentialDigest` it states, whatever its value; absent when it states none. */
  readonly commitment?: { readonly stated: unknown };
}

/**
 * The `parentCredentialDigest` a child of `parent` states: the digest SPEC §7.8 gives the parent
 * credential, as it is held (an object, or a VC-JWT by its string).
 *
 * @throws {NoSignedFormError} for a parent with no signed form, which has no digest
 */
export function parentCredentialDigestOf(parent: ReceivedCredential, hash: Sha256 = webCryptoSha256): Promise<Digest> {
  return delegationCredentialDigest(parent, hash);
}

/** The credential a received value carries: the object itself, or the `vc` claim of a VC-JWT. */
function credentialOf(received: unknown): Record<string, unknown> | undefined {
  if (typeof received !== 'string') return isRecord(received) ? received : undefined;
  const vc: unknown = parseVCJWT(received)?.payload?.vc;
  return isRecord(vc) ? vc : undefined;
}

/** What `received`, a credential of either profile in either form, says of its parent. */
export function parentReferenceOf(received: unknown): ParentReference {
  const subject = credentialOf(received)?.credentialSubject;
  if (!isRecord(subject)) return { named: false };
  // A base profile credential (SPEC §6.2) carries a delegation record; an Entity Card hop (SPEC
  // §6.10) carries its capability in the subject itself, and its root names its own target.
  const base = subject.delegation;
  const [holder, named] = isRecord(base)
    ? [base, Boolean(base.parentId)]
    : [subject, subject.parentCapability !== undefined && subject.parentCapability !== subject.invocationTarget];
  return Object.hasOwn(holder, PARENT_CREDENTIAL_DIGEST)
    ? { named, commitment: { stated: holder[PARENT_CREDENTIAL_DIGEST] } }
    : { named };
}

/** Whether `stated` is the digest of `parent`. A parent with no signed form has no digest, so none is. */
export async function commitsTo(stated: unknown, parent: ReceivedCredential, hash: Sha256 = webCryptoSha256): Promise<boolean> {
  try {
    return stated === (await parentCredentialDigestOf(parent, hash));
  } catch (error) {
    if (error instanceof NoSignedFormError) return false;
    throw error;
  }
}

/**
 * Whether the last credential of `chain`, root first, fixes the whole of it:
 *
 * - `pinned`: the first credential names no parent, and every later one states the digest of the
 *   credential before it;
 * - `unpinned`: a credential states no digest, or the first names a parent that is not given, so
 *   that part of the chain is named by ids alone;
 * - `mismatch`: a credential states a digest that is not that of the credential before it, so the
 *   chain given is not the one its credentials were signed under.
 */
export async function ancestryPinning(
  chain: readonly ReceivedCredential[],
  hash: Sha256 = webCryptoSha256,
): Promise<'pinned' | 'unpinned' | 'mismatch'> {
  let pinned = chain.length > 0 && !parentReferenceOf(chain[0]).named;
  for (let hop = 1; hop < chain.length; hop += 1) {
    const { commitment } = parentReferenceOf(chain[hop]);
    if (commitment === undefined) pinned = false;
    else if (!(await commitsTo(commitment.stated, chain[hop - 1]!, hash))) return 'mismatch';
  }
  return pinned ? 'pinned' : 'unpinned';
}
