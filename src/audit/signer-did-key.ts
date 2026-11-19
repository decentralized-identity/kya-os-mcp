/**
 * A verifier of an audit signer's own signatures, derived from the Ed25519 did:key its reference
 * names, for a signer whose key yields no public key: a remote key service, or a `CryptoKey`
 * created non-extractable. The recorder and the checkpoint builder use it, as they use the verifier
 * a signer derives from its own key, to check the stored entries they build on when they are given
 * no `signatures`.
 *
 * Nothing proves that a signer signs with the key its reference names, so the verifier is used
 * only once a signature the signer makes over a fixed self-check payload verifies under it. A
 * reference that names another key, a DID that is no Ed25519 did:key, or an algorithm other than
 * EdDSA derives nothing, and the journal is trusted as written, as before. A did:web reference is
 * not read: the audit path has no fetch provider, and its first write would otherwise wait on the
 * network.
 */
import type { JWK } from 'jose';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../delegation/did-key-resolver.js';
import { CompactJwsAuditSignatureVerifier, type AuditSignatureVerifier, type AuditSigner } from './crypto.js';
import { ownKeyResolver } from './own-key.js';

/**
 * What a signer signs to show it holds the key its did:key names. It is no canonical JSON, so no
 * audit artifact's payload is ever these bytes, and the signature cannot stand for one.
 */
const SELF_CHECK_PAYLOAD = new TextEncoder().encode('org.kya-os.audit.signer-self-check.v1');

/**
 * The verifier of `signer`'s signatures under the Ed25519 did:key its `ref` names, or undefined
 * when its reference names none, or names one its self-check does not verify under. It asks the
 * signer for one signature; an error the signer throws is not caught.
 */
export async function didKeyVerifierOf(signer: AuditSigner): Promise<AuditSignatureVerifier | undefined> {
  const { ref } = signer;
  if (ref.alg !== 'EdDSA') return undefined;
  const publicKey = extractPublicKeyFromDidKey(ref.did);
  if (publicKey === null) return undefined;
  const verifier = new CompactJwsAuditSignatureVerifier(ownKeyResolver(ref, publicKeyToJwk(publicKey) as JWK));
  const jws = await signer.sign(SELF_CHECK_PAYLOAD);
  return (await verifier.verify(SELF_CHECK_PAYLOAD, jws, ref)) ? verifier : undefined;
}
