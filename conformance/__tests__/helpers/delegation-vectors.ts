/**
 * Test helper: the `signed-proof/delegation-*` vectors (suite 1.5.0), read
 * by id, and what a test holds each to: whether its issuers signed its
 * credentials, the digest of its chain, and the reference adapter's verdict.
 */
import { compactVerify, decodeJwt, importJWK } from 'jose';
import { loadVectors } from '../../loader.js';
import { ReferenceConformanceAdapter } from '../../reference-adapter.js';
import { embeddedSignatureVerifier } from '../../../src/delegation/embedded-signature.js';
import { digestDelegationChain } from '../../../src/delegation/chain-digest.js';
import { extractPublicKeyFromDidKey, publicKeyToJwk } from '../../../src/delegation/did-key-resolver.js';
import { NodeCryptoProvider } from '../../../src/providers/node-crypto.js';
import type { DelegationCredential } from '../../../src/index.js';
import type { ConformanceVector, SignedProofInput } from '../../types.js';

export interface Proof {
  jws: string;
  meta: Record<string, unknown>;
}
export type Credential = string | (DelegationCredential & { proof: Record<string, unknown> });

export const crypto = new NodeCryptoProvider();
export const hash = (bytes: Uint8Array) => crypto.hash(bytes);
const vectors = loadVectors();
export const byId = (id: string): ConformanceVector => {
  const vector = vectors.find((v) => v.id === `signed-proof/delegation-${id}`);
  if (!vector) throw new Error(`missing vector ${id}`);
  return vector;
};
export const inputOf = (id: string) => byId(id).input as SignedProofInput;
export const proofOf = (id: string) => inputOf(id).proof as Proof;
export const chainOf = (id: string) => inputOf(id).expected!.delegationChain as Credential[];
export const digestOf = async (chain: Credential[]) => (await digestDelegationChain(chain, hash)).chain;
export const verify = (input: SignedProofInput) => new ReferenceConformanceAdapter().verifySignedProof(input);
export const keyOf = (did: string) => publicKeyToJwk(extractPublicKeyFromDidKey(did)!);

/** Whether a credential's own signature verifies under its issuer's did:key. */
export async function issuerSigned(credential: Credential): Promise<boolean> {
  if (typeof credential === 'string') {
    const claims = decodeJwt(credential);
    try {
      await compactVerify(credential, await importJWK(keyOf(claims.iss!), 'EdDSA'));
      return true;
    } catch {
      return false;
    }
  }
  const issuer = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
  return (await embeddedSignatureVerifier(crypto)(credential, keyOf(issuer))).valid;
}
