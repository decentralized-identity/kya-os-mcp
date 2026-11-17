/**
 * A live proof lifts a Card to L3 only when the Card's own DID signed it (SPEC-ENTITY-CARD §9.3,
 * §11.1). A valid proof by another DID shows possession of that DID's key, not the Card's, so the
 * Card stays at L2 however valid the proof. The DIDs are compared as `resolveCard` compares a
 * fetched Card's `id` with the DID it was resolved for. The proofs here are real: minted with
 * `buildCardProof` and checked by `verifyCardProof` against each signer's published key.
 */

import { describe, expect, it, vi } from 'vitest';
import { buildCardProof, verifyCard, verifyCardProof, type CardProofVerifier, type EntityCard } from '../index.js';
import { AUD, clock, keypair, PROOF_KEY, REQ } from './proof-helpers.js';
import type { ProofPublicJwk } from '../schema.js';

const CARD_DID = 'did:web:example.com:agents:acme';
const OTHER_DID = 'did:web:other.example';
const card: EntityCard = {
  id: CARD_DID,
  entityType: 'agent',
  name: 'Acme',
  capabilities: [{ name: 'search', attestations: [{ vc: 'jwt' }] }],
};
const allAttested = async () => ({ verified: ['search'], unverified: [] });

/** A real proof of `REQ` that `did` signs, and a verifier that checks it against `did`'s published key. */
async function signedBy(did: string) {
  const kid = `${did}#key-1`;
  const { signer, publicJwk } = await keypair(did, kid);
  const published = new Map<string, ProofPublicJwk>([[kid, publicJwk]]);
  const meta = await buildCardProof(REQ, signer, { audience: AUD, nonce: `n-${did.length}-0123456789abcdef0123456789`, now: clock });
  const proofVerifier: CardProofVerifier = (proof, request) => verifyCardProof(proof, request, {
    resolveKey: (keyId) => published.get(keyId)!,
    resolveDidKeys: (owner) => (owner === did ? [publicJwk] : []),
    expectedAudience: AUD,
    consumeNonceIfFresh: () => true,
    now: clock,
  });
  return { proof: meta[PROOF_KEY], proofVerifier };
}

/** A proof verifier that answers a valid proof by `did`, as a host's own may. */
const answering = (did: string): CardProofVerifier => async () => ({ ok: true, did, level: 'L3', reasons: [] });

describe('verifyCard and the DID that signed its live proof', () => {
  it("lifts the Card to L3 on a valid proof the Card's own DID signed", async () => {
    const result = await verifyCard(card, { capabilityVerifier: allAttested, request: REQ, ...await signedBy(CARD_DID) });
    expect(result.proof).toMatchObject({ verified: true, did: CARD_DID });
    expect(result.conformanceLevel).toBe('L3');
  });

  it('keeps the Card at L2 on a valid proof another DID signed, and reports that proof as it is', async () => {
    const result = await verifyCard(card, { capabilityVerifier: allAttested, request: REQ, ...await signedBy(OTHER_DID) });
    expect(result.proof).toMatchObject({ verified: true, did: OTHER_DID });
    expect(result.ok).toBe(true);
    expect(result.conformanceLevel).toBe('L2');
  });

  it("still hands the accountability verifier the DID that signed the proof, for the leaf join", async () => {
    const accountabilityVerifier = vi.fn(async () => ({ verified: true, fresh: true }));
    const responsible = { ...card, responsibleParty: 'did:web:example.com:org:acme' };
    await verifyCard(responsible, { capabilityVerifier: allAttested, accountabilityVerifier, proof: {}, request: REQ, proofVerifier: answering(OTHER_DID) });
    expect(accountabilityVerifier).toHaveBeenCalledWith(responsible, expect.objectContaining({ proofDid: OTHER_DID }));
  });

  it.each([
    ['a did:web host in another case', 'did:web:Example.COM:agents:acme'],
    ['a percent-encoded letter', 'did:web:example.com:agents:%61cme'],
  ])("lifts the Card to L3 on a proof whose DID is the Card's, written with %s", async (_how, did) => {
    const result = await verifyCard(card, { capabilityVerifier: allAttested, proof: {}, request: REQ, proofVerifier: answering(did) });
    expect(result.conformanceLevel).toBe('L3');
  });

  it.each([
    ['a did:key', 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'],
    ['another path under the same host', 'did:web:example.com:agents:acme:sub'],
    ['a percent-encoded colon, which is another DID', 'did:web:example.com:agents%3Aacme'],
    ['malformed percent-encoding', 'did:web:example.com:agents:%E0acme'],
  ])('keeps the Card at L2 on a proof whose DID is %s, and never throws', async (_how, did) => {
    const result = await verifyCard(card, { capabilityVerifier: allAttested, proof: {}, request: REQ, proofVerifier: answering(did) });
    expect(result.conformanceLevel).toBe('L2');
  });
});
