/**
 * ES256 (P-256) proof profile + algorithm-confusion resistance.
 *
 * Crypto agility is only safe if the second algorithm cannot be abused to confuse the first. These
 * tests prove the allow-list (`EdDSA`|`ES256` only), the alg↔key binding (an ES256 claim MUST carry
 * a P-256 key and vice versa), and that `alg` is a signed covered claim — so neither the schema, the
 * key type, nor the signature can be talked out of the declared algorithm.
 */
import { describe, it, expect } from 'vitest';
import { buildCardProof, verifyCardProof, verifyHttpSignature, type CardProofMeta, type ProofSigner } from '../index.js';
import { es256Keypair, keypair, deps, REQ, AUD, NONCE, clock, PROOF_KEY } from './proof-helpers.js';

async function mint(signer: ProofSigner, over: Record<string, unknown> = {}): Promise<CardProofMeta> {
  const env = await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock, ...over });
  return env[PROOF_KEY];
}

describe('ES256 (P-256) proof profile', () => {
  it('mints + verifies an ES256 proof end-to-end (detached JWS + RFC 9421 sibling), L3-minus', async () => {
    const { signer, publicJwk } = await es256Keypair();
    expect(signer.alg).toBe('ES256');
    const proof = await mint(signer);
    expect(proof.alg).toBe('ES256');

    const res = await verifyCardProof(proof, REQ, deps(publicJwk, { resolveDidKeys: () => [publicJwk] }));
    expect(res.ok).toBe(true);
    expect(res.level).toBe('L3-minus');
    // the dual-carrier RFC 9421 (ecdsa-p256-sha256) sibling verifies against the same P-256 key
    expect(await verifyHttpSignature(proof, publicJwk)).toBe(true);
  });

  it('rejects an ES256 proof signed by a DIFFERENT P-256 key (invalid_signature)', async () => {
    const { signer } = await es256Keypair();
    const { publicJwk: stranger } = await es256Keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(stranger)); // dev trust: skip membership
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('invalid_signature');
  });

  it('ES256 reaches L3 when the token cnf.jkt fuses to the P-256 key thumbprint', async () => {
    const { signer, publicJwk } = await es256Keypair();
    const proof = await mint(signer, { cnfJkt: signer.jkt });
    const res = await verifyCardProof(
      proof,
      REQ,
      deps(publicJwk, { resolveDidKeys: () => [publicJwk], tokenCnfJkt: signer.jkt }),
    );
    expect(res.ok).toBe(true);
    expect(res.level).toBe('L3');
  });
});

describe('algorithm-confusion resistance', () => {
  it('an ES256 proof resolved to an Ed25519 key → alg_key_mismatch (never verified)', async () => {
    const { signer } = await es256Keypair();
    const { publicJwk: edKey } = await keypair(); // Ed25519 key at the same kid
    const res = await verifyCardProof(await mint(signer), REQ, deps(edKey));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('alg_key_mismatch');
  });

  it('an EdDSA proof resolved to a P-256 key → alg_key_mismatch (never verified)', async () => {
    const { signer } = await keypair();
    const { publicJwk: p256Key } = await es256Keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(p256Key));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('alg_key_mismatch');
  });

  it('flipping meta.alg on a signed proof cannot get it accepted', async () => {
    const { signer, publicJwk } = await keypair(); // an authentic EdDSA proof + its Ed25519 key
    const proof = await mint(signer);
    // Claim ES256 while the key stays Ed25519 → alg_key_mismatch; and the JWS header still says EdDSA
    // (≠ the flipped meta.alg) while `alg` is a covered claim, so the signature can't be made to fit.
    const res = await verifyCardProof({ ...proof, alg: 'ES256' }, REQ, deps(publicJwk));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('alg_key_mismatch');
  });

  it('the schema rejects any non-allow-list alg (RS256 / none / HS256) → malformed_proof', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    for (const badAlg of ['RS256', 'none', 'HS256', 'ES384']) {
      const res = await verifyCardProof({ ...proof, alg: badAlg }, REQ, deps(publicJwk));
      expect(res.reasons).toContain('malformed_proof');
    }
  });
});
