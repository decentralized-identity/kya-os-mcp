/**
 * Delegation chain digests (SPEC.md §7.8).
 *
 * A response proof may name the delegation a call was decided under by
 * `delegationRef`, the presented credential's id. An id is a name: nothing
 * stops two credentials from sharing one. `delegationChainDigest` is the
 * value that pins the chain: one SHA-256 over the digests of every credential
 * the server evaluated, root to leaf. A server that binds the chain signs it;
 * a verifier or auditor holding the chain recomputes it. Both use the
 * functions here, so they cannot drift.
 *
 * A credential is digested in its signed form (`./signed-form.ts`): what its
 * issuer's signature covers, and that signature. Everything else about how
 * it arrived is left out, so the digest is of the credential and not of one
 * serialization of it. A copy with other `proof` metadata, which a §6.2
 * signature does not cover, or with its signature written another way, has
 * the same digest. A verifier that checks the signature over that same form
 * (`signingInput`), as the middleware does, cannot be made to sign a digest
 * that the issuer's own copy fails to reproduce.
 *
 * The chain digest is a hash of hashes on purpose. Whoever holds the
 * per-credential digests (the audit trail records them) can recompute it
 * without the credentials themselves, and can tell which hop of a chain
 * differs from the one the server saw.
 *
 * Pure: no transport, no framework, no key material.
 */

import { canonicalizeJsonBytes } from '../utils/canonical-json.js';
import { domainDigest, type Sha256 } from '../utils/domain-digest.js';
import { digestInput, signedForm, type ReceivedCredential } from './signed-form.js';
import { isDigest } from './digest-form.js';
import type { Digest } from '../audit/types.js';

export type { ReceivedCredential } from './signed-form.js';
export type { Sha256 } from '../utils/domain-digest.js';

/** The digests of a chain's credentials, and the one digest that stands for the chain. */
export interface DelegationChainDigests {
  /** One per credential, root first; the presented (leaf) credential's is last. */
  credentials: Digest[];
  /** {@link delegationChainDigest} of `credentials`: the value a proof signs. */
  chain: Digest;
}

/** Domain of a credential digest: `SHA-256(UTF8(domain) || 0x00 || JCS(signed form))`. */
export const DELEGATION_CREDENTIAL_DIGEST_DOMAIN = 'org.kya-os.delegation.credential.v1';
/** Domain of a chain digest: `SHA-256(UTF8(domain) || 0x00 || JCS(credential digests))`. */
export const DELEGATION_CHAIN_DIGEST_DOMAIN = 'org.kya-os.delegation.chain.v1';

/**
 * The digest of one credential (SPEC §7.8): SHA-256, under the credential
 * domain, over the RFC 8785 (JCS) canonicalization of its signed form.
 *
 * @throws {NoSignedFormError} for a value with no signed form: it is neither
 *   a compact JWS nor an object with a `proof.proofValue`, its signature is
 *   not base64url, or what the signature covers has no canonical JSON form.
 */
export async function delegationCredentialDigest(
  credential: ReceivedCredential,
  hash: Sha256,
): Promise<Digest> {
  return domainDigest(DELEGATION_CREDENTIAL_DIGEST_DOMAIN, digestInput(signedForm(credential)), hash);
}

/**
 * The digest of a chain, from its credentials' digests in order, root first:
 * SHA-256, under the chain domain, over the RFC 8785 (JCS) array of those
 * digest strings. A single credential is a chain of one. Order is part of the
 * value, so the same credentials in another order are another chain.
 *
 * @throws {TypeError} for an empty list, or an entry that is not a
 *   `sha256:<64 lowercase hex>` digest.
 */
export async function delegationChainDigest(
  credentialDigests: readonly string[],
  hash: Sha256,
): Promise<Digest> {
  if (credentialDigests.length === 0) {
    throw new TypeError('A delegation chain has at least one credential');
  }
  for (const digest of credentialDigests) {
    if (!isDigest(digest)) {
      throw new TypeError('A credential digest is "sha256:" followed by 64 lowercase hex characters');
    }
  }
  return domainDigest(DELEGATION_CHAIN_DIGEST_DOMAIN, canonicalizeJsonBytes([...credentialDigests]), hash);
}

/**
 * Digest a whole chain, root first: each credential, then the chain.
 *
 * @throws {NoSignedFormError} when a credential has no signed form, and
 *   {@link TypeError} for an empty chain, as {@link delegationCredentialDigest}
 *   and {@link delegationChainDigest} do.
 */
export async function digestDelegationChain(
  chain: readonly ReceivedCredential[],
  hash: Sha256,
): Promise<DelegationChainDigests> {
  const credentials: Digest[] = [];
  for (const credential of chain) {
    credentials.push(await delegationCredentialDigest(credential, hash));
  }
  return { credentials, chain: await delegationChainDigest(credentials, hash) };
}
