import { describe, it, expect } from 'vitest';
import {
  buildCardProof,
  verifyCardProof,
  InMemoryNonceCache,
  consumeFromNonceCacheProvider,
  PROOF_PROFILE_V1,
  type CardProofMeta,
  type ProofPublicJwk,
  type ProofSigner,
  type VerifyProofDeps,
} from '../index.js';
import { MemoryNonceCacheProvider } from '../../providers/memory.js';
import { canonicalPayloadBytes } from '../proof/canonical.js';
import { AUD, DID, KID, NONCE, PROOF_KEY, REQ, T0, clock, deps, keypair } from './proof-helpers.js';

/** Mint a proof with the shared clock; returns the flat CardProofMeta. */
async function mint(
  signer: ProofSigner,
  over: Partial<Parameters<typeof buildCardProof>[2]> = {},
): Promise<CardProofMeta> {
  const env = await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock, ...over });
  return env[PROOF_KEY];
}

/** ADVERSARIAL mint: sign an arbitrary claims set into a jws-only proof, bypassing buildCardProof's
 *  input validation — the only way to exercise VERIFIER defenses against windows an honest minter
 *  (which now fails closed at mint) would never emit. */
async function signAdversarial(
  signer: ProofSigner,
  claims: Omit<CardProofMeta, 'jws' | 'httpSig'>,
): Promise<CardProofMeta> {
  const unsigned: CardProofMeta = { ...claims, jws: '' };
  return { ...unsigned, jws: await signer.sign(canonicalPayloadBytes(unsigned)) };
}

describe('buildCardProof', () => {
  it('mints an org.kya-os/proof.v1 under the shipped _meta key, binding did/kid/audience/cnf', async () => {
    const { signer } = await keypair();
    const env = await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock });
    const proof = env[PROOF_KEY];
    expect(proof.prf).toBe(PROOF_PROFILE_V1);
    expect(proof.alg).toBe('EdDSA');
    expect(proof.did).toBe(DID);
    expect(proof.kid).toBe(KID);
    expect(proof.audience).toBe(AUD);
    expect(proof.cnf?.jkt).toBe(signer.jkt);
    expect(proof.jws.split('.')[1]).toBe(''); // detached JWS: header..signature
    expect(proof.expires - proof.created).toBe(60);
  });

  it('omits cnf when neither the signer nor the context supplies a jkt (L3-minus proof)', async () => {
    const { signer } = await keypair();
    const noCnf: ProofSigner = { did: signer.did, kid: signer.kid, sign: signer.sign };
    const proof = await mint(noCnf);
    expect(proof.cnf).toBeUndefined();
  });
});

describe('verifyCardProof — happy path', () => {
  it('verifies a valid proof and derives L3-minus without a token cnf', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk));
    // The proof carries a cnf but no token cnf was wired to fuse it against, so it degrades to a
    // valid L3-minus proof AND surfaces a NON-FATAL warning (TM-1) so the downgrade is observable.
    // ok / reasons / level are unaffected — the warning does not fail the proof closed.
    expect(res).toEqual({
      ok: true,
      reasons: [],
      level: 'L3-minus',
      did: DID,
      warnings: ['cnf_present_but_token_unfused'],
    });
  });

  it('accepts the proof when resolveDidKeys confirms the signing key is published by the DID', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { resolveDidKeys: () => [publicJwk] }));
    expect(res.ok).toBe(true);
  });
});

describe('verifyCardProof — cnf.jkt fusion (RFC 7638 / 9449)', () => {
  it('achieves L3 when token.cnf.jkt === proof.cnf.jkt === thumbprint(resolve(kid))', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { tokenCnfJkt: signer.jkt }));
    expect(res.ok).toBe(true);
    expect(res.level).toBe('L3');
    // When the cnf actually fuses to L3 there is nothing unfused to warn about.
    expect(res.warnings).toBeUndefined();
  });

  it('emits NO unfused-cnf warning when the proof itself carried no cnf', async () => {
    const { signer, publicJwk } = await keypair();
    const noCnf: ProofSigner = { did: signer.did, kid: signer.kid, sign: signer.sign };
    const res = await verifyCardProof(await mint(noCnf), REQ, deps(publicJwk));
    // No cnf presented → the L3-minus degradation is expected, not a misconfiguration, so no warning.
    expect(res.ok).toBe(true);
    expect(res.level).toBe('L3-minus');
    expect(res.warnings).toBeUndefined();
  });

  it('rejects a token cnf.jkt that does not fuse with the proof', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { tokenCnfJkt: 'not-the-thumbprint' }));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('cnf_token_mismatch');
  });

  it('rejects a token-constrained request whose proof carries NO cnf (downgrade defense)', async () => {
    const { signer, publicJwk } = await keypair();
    const noCnf: ProofSigner = { did: signer.did, kid: signer.kid, sign: signer.sign };
    const res = await verifyCardProof(await mint(noCnf), REQ, deps(publicJwk, { tokenCnfJkt: signer.jkt }));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('cnf_required_by_token');
  });

  it('rejects a proof whose signed cnf.jkt does not match the actual signing key', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer, { cnfJkt: 'bogus-but-signed-jkt' }), REQ, deps(publicJwk));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('cnf_key_mismatch');
  });
});

describe('verifyCardProof — kid ⇄ did binding (the forgeable-principal blocker)', () => {
  it('REJECTS a proof whose kid points at a DIFFERENT DID than proof.did', async () => {
    // did = the victim principal; kid = an attacker DID key. The signature is valid, but the
    // accountable principal is forged: kid.split("#")[0] !== proof.did.
    const { signer, publicJwk } = await keypair(DID, 'did:web:evil.example#key-1');
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('kid_did_mismatch');
  });

  it('REJECTS a proof whose signing key is not a verificationMethod of proof.did', async () => {
    // kid prefix matches proof.did, but the DID document publishes a DIFFERENT key — so the key
    // that signed is not actually bound to the accountable principal.
    const { signer, publicJwk } = await keypair();
    const { publicJwk: strangerKey } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { resolveDidKeys: () => [strangerKey] }));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('kid_not_in_did_document');
  });
});

describe('verifyCardProof — DID-membership posture (fail-closed, explicit)', () => {
  it('DEFAULT (no resolver): binding rests on the authoritative resolveKey contract → accepts', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk));
    expect(res.ok).toBe(true);
  });

  it('the secure DEFAULT (no resolveDidKeys, no opt-out) FAILS CLOSED (did_membership_unverifiable)', async () => {
    const { signer, publicJwk } = await keypair();
    // Override the helper's dev opt-out back to undefined = the real production default.
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { trustResolveKeyAuthority: undefined }));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('did_membership_unverifiable');
  });

  it('resolveDidKeys publishing the signing key → accepts (RFC 7638 membership proven)', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { resolveDidKeys: () => [publicJwk] }));
    expect(res.ok).toBe(true);
  });

  it('resolveDidKeys publishing a DIFFERENT key → kid_not_in_did_document (even if trust opt-out is set)', async () => {
    const { signer, publicJwk } = await keypair();
    const { publicJwk: stranger } = await keypair();
    // The seam, when present, is authoritative — it overrides the dev opt-out the helper sets.
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { resolveDidKeys: () => [stranger] }));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('kid_not_in_did_document');
  });

  it('trustResolveKeyAuthority opts out (dev / authoritative resolveKey) → accepts without a seam', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { trustResolveKeyAuthority: true }));
    expect(res.ok).toBe(true);
  });
});

describe('verifyCardProof — per-request bindings', () => {
  it('rejects an audience bound to a different recipient (anti-relay / confused deputy)', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { expectedAudience: 'did:web:someone.else' }));
    expect(res.reasons).toContain('audience_mismatch');
  });

  it('rejects a proof verified against a DIFFERENT request (tampered params)', async () => {
    const { signer, publicJwk } = await keypair();
    const other = { method: 'tools/call', params: { name: 'delete', arguments: { id: 42 } } };
    const res = await verifyCardProof(await mint(signer), other, deps(publicJwk));
    expect(res.reasons).toContain('request_hash_mismatch');
  });

  it('rejects a replayed nonce (consumeNonceIfFresh === false)', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { consumeNonceIfFresh: () => false }));
    expect(res.reasons).toContain('nonce_replayed');
  });

  it('rejects an expired proof (now past expires + skew)', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { now: () => T0 + 120_000 }));
    expect(res.reasons).toContain('expired');
  });

  it('rejects a not-yet-valid proof (created beyond now + skew)', async () => {
    const { signer, publicJwk } = await keypair();
    const future = await mint(signer, { now: () => T0 + 120_000 });
    const res = await verifyCardProof(future, REQ, deps(publicJwk, { now: clock }));
    expect(res.reasons).toContain('created_in_future');
  });

  it('rejects an over-long lifetime (expires - created > MAX_TTL_SEC)', async () => {
    const { signer, publicJwk } = await keypair();
    // The honest minter now fails closed on an over-long ttl, so craft the over-long proof
    // adversarially to exercise the verifier's own ttl_too_long defense.
    const { jws: _j, httpSig: _h, ...claims } = await mint(signer);
    const overLong = await signAdversarial(signer, { ...claims, expires: claims.created + 3600 });
    const res = await verifyCardProof(overLong, REQ, deps(publicJwk));
    expect(res.reasons).toContain('ttl_too_long');
  });

  it('buildCardProof fails FAST on an over-long ttlSec (never emits a doomed proof)', async () => {
    const { signer } = await keypair();
    await expect(mint(signer, { ttlSec: 3600 })).rejects.toThrow(/exceeds the profile cap/);
  });

  it('rejects an inverted window where expires <= created (invalid_window)', async () => {
    // Guards the `expires > created` invariant — signed, so a zero-length window is minted (not tampered).
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer, { ttlSec: 0 }), REQ, deps(publicJwk));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('invalid_window');
  });
});

describe('verifyCardProof — JWS protected-header binding', () => {
  it('rejects a proof whose JWS header alg differs from the signed meta.alg (anti-downgrade)', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    const [h, , s] = proof.jws.split('.');
    const header = JSON.parse(Buffer.from(h!, 'base64url').toString('utf8')) as { alg: string; kid: string };
    header.alg = header.alg === 'EdDSA' ? 'ES256' : 'EdDSA'; // flip to another allow-listed alg
    const jws = `${Buffer.from(JSON.stringify(header)).toString('base64url')}..${s}`;
    const res = await verifyCardProof({ ...proof, jws }, REQ, deps(publicJwk));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('invalid_signature');
  });
});

describe('verifyCardProof — thumbprint failure fails CLOSED (never throws)', () => {
  // A structurally-typed but INVALID JWK (EC key missing `y`) passes keyMatchesAlg (kty/crv only) but
  // makes jose's calculateJwkThumbprint throw. The verifier must return { ok:false, reasons }, never
  // reject out of verifyCardProof — the documented fail-closed contract.
  const brokenKey = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU' } as unknown as ProofPublicJwk;

  it('a resolveKey seam returning an invalid JWK → thumbprint_computation_failed (checkCnfFusion)', async () => {
    const { signer } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(brokenKey));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('thumbprint_computation_failed');
  });

  it('a resolveDidKeys seam publishing an invalid JWK → thumbprint_computation_failed (assertDidMembership)', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { resolveDidKeys: () => [brokenKey] }));
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('thumbprint_computation_failed');
  });
});

describe('verifyCardProof — replay defense (atomic consume seam, SPEC §12.2)', () => {
  it('REJECTS a replayed nonce wired to the batteries-included InMemoryNonceCache (test-AND-set)', async () => {
    // Regression for the fail-open where the seam was a pure read: the FIRST verify must consume the
    // nonce so the SECOND (same nonce, same request) is rejected as a replay — no window reliance.
    const { signer, publicJwk } = await keypair();
    const cache = new InMemoryNonceCache({ now: clock });
    const proof = await mint(signer);
    const d = deps(publicJwk, { consumeNonceIfFresh: cache.consume });
    const first = await verifyCardProof(proof, REQ, d);
    expect(first.ok).toBe(true);
    const replay = await verifyCardProof(proof, REQ, d);
    expect(replay.ok).toBe(false);
    expect(replay.reasons).toContain('nonce_replayed');
  });

  it('the NonceCacheProvider adapter composes has()+add() into an atomic consume (replay rejected)', async () => {
    const { signer, publicJwk } = await keypair();
    const consumeNonceIfFresh = consumeFromNonceCacheProvider(new MemoryNonceCacheProvider());
    const proof = await mint(signer);
    const d = deps(publicJwk, { consumeNonceIfFresh });
    expect((await verifyCardProof(proof, REQ, d)).ok).toBe(true);
    expect((await verifyCardProof(proof, REQ, d)).reasons).toContain('nonce_replayed');
  });

  it('FAILS CLOSED when NO replay seam is supplied — never fail-open (nonce_seam_missing)', async () => {
    const { signer, publicJwk } = await keypair();
    const bare: VerifyProofDeps = { resolveKey: () => publicJwk, expectedAudience: AUD, now: clock };
    const res = await verifyCardProof(await mint(signer), REQ, bare);
    expect(res.ok).toBe(false);
    expect(res.reasons).toContain('nonce_seam_missing');
  });

  it('scopes the recorded nonce by DID — the same nonce for a DIFFERENT did is still fresh', async () => {
    const { signer, publicJwk } = await keypair();
    const cache = new InMemoryNonceCache({ now: clock });
    // Consume NONCE under a different DID first; the real proof (its own DID) must remain fresh.
    expect(await cache.consume(NONCE, 'did:web:other.example')).toBe(true);
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, { consumeNonceIfFresh: cache.consume }));
    expect(res.ok).toBe(true);
  });
});

describe('verifyCardProof — signature + structure (fail-closed)', () => {
  it('rejects a proof with any tampered covered claim (signature no longer verifies)', async () => {
    const { signer, publicJwk } = await keypair();
    const tampered = { ...(await mint(signer)), nonce: 'swapped-nonce-not-signed' };
    const res = await verifyCardProof(tampered, REQ, deps(publicJwk));
    expect(res.reasons).toContain('invalid_signature');
  });

  it('rejects a non-detached JWS (a payload segment is present)', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    const [h, , s] = proof.jws.split('.');
    const res = await verifyCardProof({ ...proof, jws: `${h}.cGF5bG9hZA.${s}` }, REQ, deps(publicJwk));
    expect(res.reasons).toContain('invalid_signature');
  });

  it('rejects a structurally malformed / wrong-profile proof', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = await mint(signer);
    expect((await verifyCardProof({}, REQ, deps(publicJwk))).reasons).toEqual(['malformed_proof']);
    expect((await verifyCardProof(null, REQ, deps(publicJwk))).reasons).toEqual(['malformed_proof']);
    const wrongPrf = { ...proof, prf: 'org.kya-os/proof@2' };
    expect((await verifyCardProof(wrongPrf, REQ, deps(publicJwk))).reasons).toEqual(['malformed_proof']);
  });

  it('fails closed when the signing key cannot be resolved', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, {
      resolveKey: () => { throw new Error('resolver down'); },
    }));
    expect(res.reasons).toContain('key_unresolvable');
  });

  it('fails closed when the DID document keys cannot be resolved', async () => {
    const { signer, publicJwk } = await keypair();
    const res = await verifyCardProof(await mint(signer), REQ, deps(publicJwk, {
      resolveDidKeys: () => { throw new Error('did doc down'); },
    }));
    expect(res.reasons).toContain('did_keys_unresolvable');
  });
});
