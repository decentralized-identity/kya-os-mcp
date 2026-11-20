/**
 * `verifyCardProof` reads no key for a proof its own claims already refuse.
 *
 * A proof names its key before anything has verified it, and resolving that key may be a network
 * read of a document the caller chose. So what needs no key is decided first: that the key is the
 * holder's, the audience, the request hash and the window.
 */
import { describe, expect, it, vi } from 'vitest';
import { buildCardProof, verifyCardProof, type CardProofMeta, type ProofSigner, type VerifyProofDeps } from '../index.js';
import type { ProofPublicJwk } from '../schema.js';
import { AUD, DID, NONCE, PROOF_KEY, REQ, T0, clock, deps, keypair } from './proof-helpers.js';

const OTHER_REQ = { method: 'tools/call', params: { name: 'delete', arguments: { id: 42 } } };

async function mint(
  signer: ProofSigner,
  over: Partial<Parameters<typeof buildCardProof>[2]> = {},
): Promise<CardProofMeta> {
  const env = await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock, ...over });
  return env[PROOF_KEY];
}

/** Verify seams that count what they are asked. */
function watched(publicJwk: ProofPublicJwk, over: Partial<VerifyProofDeps> = {}) {
  const resolveKey = vi.fn(() => publicJwk);
  const resolveDidKeys = vi.fn(() => [publicJwk]);
  const consumeNonceIfFresh = vi.fn(() => true);
  return {
    seams: deps(publicJwk, { resolveKey, resolveDidKeys, consumeNonceIfFresh, ...over }),
    resolveKey,
    resolveDidKeys,
    consumeNonceIfFresh,
  };
}

describe('verifyCardProof reads no key for a proof its own claims refuse', () => {
  it.each([
    ['addressed to another verifier', { expectedAudience: 'did:web:someone.else' }, REQ, 'audience_mismatch'],
    ['signed over another request', {}, OTHER_REQ, 'request_hash_mismatch'],
    ['past its window', { now: () => T0 + 120_000 }, REQ, 'expired'],
    ['made in the future', { now: () => T0 - 120_000 }, REQ, 'created_in_future'],
  ])('a proof %s', async (_name, over, req, reason) => {
    const { signer, publicJwk } = await keypair();
    const { seams, resolveKey, resolveDidKeys, consumeNonceIfFresh } = watched(publicJwk, over);

    const res = await verifyCardProof(await mint(signer), req, seams);

    expect(res).toEqual({ ok: false, reasons: [reason] });
    expect(resolveKey).not.toHaveBeenCalled();
    expect(resolveDidKeys).not.toHaveBeenCalled();
    expect(consumeNonceIfFresh).not.toHaveBeenCalled();
  });

  it("a proof whose key is another DID's", async () => {
    const { signer, publicJwk } = await keypair(DID, 'did:web:attacker.example#key-1');
    const { seams, resolveKey } = watched(publicJwk);

    const res = await verifyCardProof(await mint(signer), REQ, seams);

    expect(res).toEqual({ ok: false, reasons: ['kid_did_mismatch'] });
    expect(resolveKey).not.toHaveBeenCalled();
  });

  it('names every claim the proof fails', async () => {
    const { signer, publicJwk } = await keypair();
    const { seams, resolveKey } = watched(publicJwk, { expectedAudience: 'did:web:someone.else' });

    const res = await verifyCardProof(await mint(signer), OTHER_REQ, seams);

    expect(res).toEqual({ ok: false, reasons: ['audience_mismatch', 'request_hash_mismatch'] });
    expect(resolveKey).not.toHaveBeenCalled();
  });

  it('reads the key once for a proof its claims pass', async () => {
    const { signer, publicJwk } = await keypair();
    const { seams, resolveKey, resolveDidKeys, consumeNonceIfFresh } = watched(publicJwk);

    const res = await verifyCardProof(await mint(signer), REQ, seams);

    expect(res).toMatchObject({ ok: true, did: DID });
    expect(resolveKey).toHaveBeenCalledTimes(1);
    expect(resolveDidKeys).toHaveBeenCalledTimes(1);
    expect(consumeNonceIfFresh).toHaveBeenCalledTimes(1);
  });
});
