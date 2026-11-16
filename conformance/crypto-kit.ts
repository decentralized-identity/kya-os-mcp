/**
 * Crypto kit shared by the reference adapter and the vector generator.
 *
 * Centralizes the Ed25519 VC signing convention (`Ed25519Signature2020` over
 * RFC 8785 canonicalized VC, minus `proof`), the one the package's
 * `embeddedSignatureVerifier` checks, and the JWS conventions the generator
 * signs proofs and VC-JWTs with. Node built-ins, `jose` and the package's own
 * primitives, no test-only helpers. Status lists use the package's own
 * `statusListGzipCodec`.
 */

import { createPrivateKey, sign } from 'node:crypto';
import { canonicalize } from 'json-canonicalize';
import { CompactSign, importPKCS8 } from 'jose';
import { canonicalizeJSON } from '../src/delegation/utils.js';
import { publicKeyToJwk } from '../src/delegation/did-key-resolver.js';
import type { NodeCryptoProvider } from '../src/providers/node-crypto.js';
import { ED25519_PKCS8_DER_HEADER, ED25519_KEY_SIZE } from '../src/utils/ed25519-constants.js';
import { base64ToBytes, bytesToBase64 } from '../src/utils/base64.js';
import { buildProofJwsPayload, type DelegationCredential, type DetachedProof, type Proof } from '../src/index.js';

/** A party as the generator mints it: its DID, the key id it signs under, and its Ed25519 private key in base64. */
export interface SigningParty {
  did: string;
  kid: string;
  privateKey: string;
}

/**
 * Sign a VC-shaped object (`Ed25519Signature2020`). Strips any existing `proof`,
 * canonicalizes (RFC 8785), signs with `privateKeyBase64`, and returns the proof
 * block. This is the exact convention `embeddedSignatureVerifier` checks.
 *
 * `canonicalize` is the package's own RFC 8785 unless a vector needs a
 * credential signed as another canonicalizer writes it, one that refuses
 * nothing the package refuses, say.
 */
export async function signVC(
  crypto: NodeCryptoProvider,
  vcWithoutProof: Record<string, unknown>,
  privateKeyBase64: string,
  verificationMethod: string,
  canonicalize: (unsigned: Record<string, unknown>) => string = canonicalizeJSON,
): Promise<Proof> {
  const unsigned = { ...vcWithoutProof };
  delete unsigned['proof'];
  const canonical = canonicalize(unsigned);
  const signature = await crypto.sign(new TextEncoder().encode(canonical), privateKeyBase64);
  return {
    type: 'Ed25519Signature2020',
    created: '2026-01-01T00:00:00.000Z',
    verificationMethod,
    proofPurpose: 'assertionMethod',
    proofValue: Buffer.from(signature).toString('base64url'),
  };
}

/**
 * The `Ed25519VerificationKey2020` verification method `id` that publishes the raw Ed25519 public
 * key `publicKey` as a JWK, under `controller`: the form every DID document in the vectors uses.
 */
export function ed25519VerificationMethod(
  id: string,
  controller: string,
  publicKey: Uint8Array,
): Record<string, unknown> {
  return { id, type: 'Ed25519VerificationKey2020', controller, publicKeyJwk: publicKeyToJwk(publicKey) };
}

/**
 * Sign a proof meta into a DetachedProof using the SAME canonical payload shape
 * the package's ProofGenerator/ProofVerifier use (RFC 8785). The generator needs
 * to mint proofs at arbitrary pinned timestamps; ProofGenerator only signs at
 * Date.now(), so the generator reproduces the documented payload shape directly.
 *
 * The JWS is signed under `header`, the producer's `{ alg: 'EdDSA', kid }`
 * unless a vector needs a proof whose header names another algorithm or key.
 * It is signed by hand, as JWS libraries sign it, since they refuse to sign
 * under such a header.
 */
export async function signProofMeta(
  party: Pick<SigningParty, 'kid' | 'privateKey'>,
  meta: DetachedProof['meta'],
  header: Record<string, unknown> = { alg: 'EdDSA', kid: party.kid },
): Promise<DetachedProof> {
  // The payload SHAPE comes from the library's own buildProofJwsPayload, the
  // single source of truth shared with ProofGenerator/ProofVerifier, so a
  // covered claim (e.g. the envelope profile's `prf` discriminator) can never drift between
  // the library and the committed vectors.
  const payload = buildProofJwsPayload(meta);
  const canonical = canonicalize(payload as Parameters<typeof canonicalize>[0]);
  const base64url = (text: string | Uint8Array): string => Buffer.from(text).toString('base64url');
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(canonical)}`;
  const key = createPrivateKey(formatPrivateKeyAsPEM(party.privateKey));
  return { jws: `${signingInput}.${base64url(sign(null, Buffer.from(signingInput), key))}`, meta };
}

/**
 * A §6.2 credential as a compact VC-JWT: its issuer signs the JWS over
 * `{ iss, sub, vc }`, and the embedded proof is left out.
 */
export async function signVcJwt(issuer: SigningParty, credential: DelegationCredential): Promise<string> {
  const vc: Record<string, unknown> = { ...credential };
  delete vc['proof'];
  const payload = { iss: issuer.did, sub: credential.credentialSubject.id, vc };
  const key = await importPKCS8(formatPrivateKeyAsPEM(issuer.privateKey), 'EdDSA');
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: issuer.kid })
    .sign(key);
}

function formatPrivateKeyAsPEM(base64PrivateKey: string): string {
  const keyData = base64ToBytes(base64PrivateKey);
  const rawKey = keyData.subarray(0, ED25519_KEY_SIZE);
  const fullKey = new Uint8Array(ED25519_PKCS8_DER_HEADER.length + rawKey.length);
  fullKey.set(ED25519_PKCS8_DER_HEADER);
  fullKey.set(rawKey, ED25519_PKCS8_DER_HEADER.length);
  const b64 = bytesToBase64(fullKey);
  const formatted = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN PRIVATE KEY-----\n${formatted}\n-----END PRIVATE KEY-----`;
}
