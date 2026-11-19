/**
 * A delegation hop's commitment to its parent (SPEC.md §6.10): `credentialSubject.parentCredentialDigest`.
 *
 * A hop names its parent by two names alone, the parent's delegate as its own issuer and the
 * parent's capability id as its `parentCapability`. Both are the parent issuer's to choose, so a
 * parent issued again under the id of one that was revoked would carry every hop signed under the
 * first. A hop that states the digest of its parent commits to that one credential.
 *
 * The digest is the one SPEC §7.8 gives any delegation credential ({@link delegationCredentialDigest}):
 * SHA-256, under the credential domain, over the parent's signed form, every member but `proof` and
 * the signature `proof.proofValue` carries. An `eddsa-jcs-2022` signature covers the proof's own
 * configuration too, so the digest fixes the parent and its whole proof, while a copy of the parent
 * stored or serialized another way keeps it.
 *
 * A verifier checks the digest whenever a hop states it, against the hop before it as received, and
 * refuses a mismatch; a hop that states none is accepted, as before.
 */

import { delegationCredentialDigest } from '../delegation/chain-digest.js';
import { NoSignedFormError } from '../delegation/signed-form.js';
import type { Digest } from '../audit/types.js';
import { webCryptoSha256 } from '../utils/domain-digest.js';
import { isRecord } from '../utils/guards.js';
import { coded, type Coded } from '../utils/refusal.js';
import { thrownReason } from '../utils/thrown-words.js';

/** The member of a hop's `credentialSubject` that commits it to its parent. */
export const PARENT_CREDENTIAL_DIGEST = 'parentCredentialDigest';

/**
 * The `parentCredentialDigest` a child of `parent` states: the digest SPEC §7.8 gives the parent
 * credential, as `sha256:` and 64 lowercase hex digits.
 *
 * @throws {NoSignedFormError} for a parent with no signed form (SPEC §7.8), one that carries no
 *   signature among them.
 */
export function parentCredentialDigestOf(parent: object): Promise<Digest> {
  return delegationCredentialDigest(parent, webCryptoSha256);
}

/** The `parentCredentialDigest` a received hop states, or `undefined` when it states none. */
export function statedParentDigest(credential: Record<string, unknown>): unknown {
  const subject = credential.credentialSubject;
  return isRecord(subject) && Object.hasOwn(subject, PARENT_CREDENTIAL_DIGEST) ? subject[PARENT_CREDENTIAL_DIGEST] : undefined;
}

/**
 * Check every hop's `parentCredentialDigest` against the hop before it, root to leaf, as received:
 * the first refusal, its reason naming the zero-based hop, or `undefined` when every hop that states
 * one states its parent's. A hop that states none is not checked, and the root, which has no parent
 * credential, is left to the chain rules. Nothing is resolved or fetched.
 */
export async function firstParentDigestRefusal(
  credentials: readonly Record<string, unknown>[],
): Promise<(Coded & { reason: string }) | undefined> {
  for (let hop = 1; hop < credentials.length; hop += 1) {
    const stated = statedParentDigest(credentials[hop]!);
    if (stated === undefined) continue;
    const refused = await parentDigestRefusal(stated, credentials[hop - 1]!, hop - 1);
    if (refused !== undefined) return { ...refused, reason: `hop ${hop}: ${refused.reason}` };
  }
  return undefined;
}

/** Why `stated` is not the digest of `parent`, hop `position` of the chain, or `undefined` when it is. */
async function parentDigestRefusal(
  stated: unknown,
  parent: Record<string, unknown>,
  position: number,
): Promise<(Coded & { reason: string }) | undefined> {
  const named = `hop ${position}, the parent presented with it`;
  try {
    if (stated === (await parentCredentialDigestOf(parent))) return undefined;
    return { reason: `${PARENT_CREDENTIAL_DIGEST} is not the digest of ${named}`, ...coded('chain_invalid') };
  } catch (error) {
    if (error instanceof NoSignedFormError) {
      return { reason: `${named}, has no signed form, so it has no digest`, ...coded('chain_invalid') };
    }
    const withheld = `${PARENT_CREDENTIAL_DIGEST} could not be checked`;
    return { reason: thrownReason(error, { withheld, tag: '[kya-os]' }), ...coded('runtime_error') };
  }
}
