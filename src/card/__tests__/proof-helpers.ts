/**
 * Shared fixtures for the `org.kya-os/proof@1` test suites. Not a test file (no `.test.ts`),
 * so vitest does not collect it; excluded from coverage as an `__tests__` module.
 */

import { exportJWK, generateKeyPair } from 'jose';
import {
  ed25519SignerFromJwk,
  es256SignerFromJwk,
  type Ed25519PrivateJwk,
  type P256PrivateJwk,
  type ProofSigner,
  type VerifyProofDeps,
} from '../index.js';
import type { Ed25519PublicJwk, P256PublicJwk, ProofPublicJwk } from '../schema.js';
import { KYA_OS_CARD_PROOF_META_KEY } from '../proof/types.js';

export const PROOF_KEY = KYA_OS_CARD_PROOF_META_KEY;
export const DID = 'did:web:example.com:agents:acme';
export const KID = `${DID}#key-1`;
export const AUD = 'did:web:example.com:mcp:server';
export const NONCE = 'n-0123456789abcdef0123456789abcdef';
export const REQ = { method: 'tools/call', params: { name: 'search', arguments: { q: 'ledgers' } } };

/** A fixed clock (ms) so created/expires windows are deterministic across runs. */
export const T0 = Date.parse('2026-06-30T12:00:00Z');
export const clock = (): number => T0;

/** A freshly generated Ed25519 signer + its public JWK (as a `resolveKey` would return it). */
export async function keypair(
  did = DID,
  kid = KID,
): Promise<{ signer: ProofSigner; publicJwk: Ed25519PublicJwk }> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { extractable: true });
  const priv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  const privateJwk: Ed25519PrivateJwk = { kty: 'OKP', crv: 'Ed25519', x: priv.x ?? '', d: priv.d ?? '' };
  const signer = await ed25519SignerFromJwk({ did, kid, privateJwk });
  const publicJwk: Ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: pub.x ?? '', kid };
  return { signer, publicJwk };
}

/** A freshly generated ES256 (P-256) signer + its public JWK — the FIPS-eligible profile path. */
export async function es256Keypair(
  did = DID,
  kid = KID,
): Promise<{ signer: ProofSigner; publicJwk: P256PublicJwk }> {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const priv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  const privateJwk: P256PrivateJwk = { kty: 'EC', crv: 'P-256', x: priv.x ?? '', y: priv.y ?? '', d: priv.d ?? '' };
  const signer = await es256SignerFromJwk({ did, kid, privateJwk });
  const publicJwk: P256PublicJwk = { kty: 'EC', crv: 'P-256', x: pub.x ?? '', y: pub.y ?? '', kid };
  return { signer, publicJwk };
}

/** Build the injected verify seams over a resolved key, with per-test overrides. */
export function deps(publicJwk: ProofPublicJwk, over: Partial<VerifyProofDeps> = {}): VerifyProofDeps {
  return {
    resolveKey: () => publicJwk,
    // The stub resolveKey above IS authoritative for this test key, so per-binding tests opt into the
    // dev escape hatch; tests that exercise DID-membership itself override with `resolveDidKeys`.
    trustResolveKeyAuthority: true,
    expectedAudience: AUD,
    consumeNonceIfFresh: () => true,
    now: clock,
    ...over,
  };
}
