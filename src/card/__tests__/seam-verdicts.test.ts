/**
 * The seams `verifyCard` asks are code the host supplies, and one written in JavaScript, or one with
 * a fault, can answer anything. Each verdict counts only as the literal its type promises: an
 * attestation verifies on `true`, a proof on an object whose `ok` is `true` and whose `did` is a
 * string, a capability on a name in an array of strings, and a capability check is fresh on `true`.
 * Any other answer leaves the claim unverified, and `verifyCard` does not throw for it.
 */

import { describe, expect, it } from 'vitest';
import { verifyCard, type EntityCard, type VerifyCardDeps } from '../index.js';

const CARD: EntityCard = {
  id: 'did:web:example.com:agents:acme',
  entityType: 'agent',
  name: 'Acme',
  capabilities: ['handshake'],
  responsibleParty: 'did:web:acme.example',
  attestations: [{ type: 'IdentityVerification', vc: 'jwt', issuer: 'did:web:kyb.example' }],
};

/** Seams that verify every claim of {@link CARD} at L3, so each test changes one answer alone. */
const ANSWERING: VerifyCardDeps = {
  capabilityVerifier: async () => ({ verified: ['handshake'], unverified: [], fresh: true }),
  accountabilityVerifier: async () => ({ verified: true, fresh: true }),
  attestationVerifier: async () => true,
  proof: {},
  request: { method: 'tools/call', params: {} },
  proofVerifier: async () => ({ ok: true, did: CARD.id, level: 'L3', reasons: [] }),
};

/** `verifyCard` on {@link CARD} when the seam `name` answers `answer`. */
const withAnswer = (name: keyof VerifyCardDeps, answer: unknown) =>
  verifyCard(CARD, { ...ANSWERING, [name]: async () => answer });

/** An object whose `member` throws when read. */
const throwingOn = (member: string, rest: Record<string, unknown> = {}): object =>
  Object.defineProperty({ ...rest }, member, {
    enumerable: true,
    get() {
      throw new Error('getter boom');
    },
  });

describe('verifyCard, with every seam answering as its type promises', () => {
  it('verifies the Card at L3', async () => {
    expect(await verifyCard(CARD, ANSWERING)).toMatchObject({
      ok: true,
      conformanceLevel: 'L3',
      verifiedCapabilities: ['handshake'],
      attestations: [{ verified: true }],
      proof: { verified: true, did: CARD.id, level: 'L3', reasons: [] },
    });
  });
});

describe('an attestation verifier whose answer is not a boolean', () => {
  it.each([['"false"', 'false'], ['1', 1], ['{}', {}], ['undefined', undefined], ['null', null]])(
    'leaves the attestation unverified on %s',
    async (_label, answer) => {
      const result = await withAnswer('attestationVerifier', answer);
      expect(result.ok).toBe(false);
      expect(result.attestations).toEqual([{ type: 'IdentityVerification', subject: undefined, verified: false }]);
    },
  );
});

describe('a proof verifier whose answer is not a proof verdict', () => {
  const unreadable = { verified: false, did: undefined, level: undefined, reasons: ['proof_verdict_unreadable'] };

  it.each([
    ['{ ok: "false" }', { ok: 'false', did: CARD.id, level: 'L3', reasons: [] }],
    ['{ ok: 1 }', { ok: 1, did: CARD.id, level: 'L3', reasons: [] }],
    ['{}', {}],
    ['undefined', undefined],
    ['null', null],
    ['true', true],
    ['a string', 'ok'],
    ['an ok verdict with no did', { ok: true, level: 'L3', reasons: [] }],
    ['an ok verdict whose did is not a string', { ok: true, did: { toString: () => CARD.id }, level: 'L3', reasons: [] }],
    ['an answer whose ok throws', throwingOn('ok', { did: CARD.id })],
    ['an answer whose did throws', throwingOn('did', { ok: true })],
    ['an answer whose level throws', throwingOn('level', { ok: true, did: CARD.id })],
    ['an answer whose reasons throws', throwingOn('reasons', { ok: false })],
  ])('leaves the proof unverified, and the Card at L2, on %s', async (_label, answer) => {
    const result = await withAnswer('proofVerifier', answer);
    expect(result.conformanceLevel).toBe('L2');
    expect(result.proof).toEqual(unreadable);
  });

  it('passes no proof DID to the accountability verifier on such an answer', async () => {
    const seen: (string | undefined)[] = [];
    await verifyCard(CARD, {
      ...ANSWERING,
      proofVerifier: (async () => ({ ok: 'yes', did: CARD.id })) as never,
      accountabilityVerifier: async (_card, ctx) => {
        seen.push(ctx.proofDid);
        return true;
      },
    });
    expect(seen).toEqual([undefined]);
  });

  it('keeps a refusal and the reasons it gave that are strings', async () => {
    const result = await withAnswer('proofVerifier', { ok: false, did: CARD.id, level: 'L3', reasons: ['expired', 7, 'audience_mismatch'] });
    expect(result.conformanceLevel).toBe('L2');
    expect(result.proof).toEqual({ verified: false, did: undefined, level: undefined, reasons: ['expired', 'audience_mismatch'] });
    expect((await withAnswer('proofVerifier', { ok: false, reasons: 'expired' })).proof).toMatchObject({ verified: false, reasons: [] });
  });

  it('reports a level only when it is one a proof can have', async () => {
    expect((await withAnswer('proofVerifier', { ok: true, did: CARD.id, level: 'L3-minus', reasons: [] })).proof).toMatchObject({
      verified: true,
      level: 'L3-minus',
    });
    expect((await withAnswer('proofVerifier', { ok: true, did: CARD.id, level: 'L9', reasons: [] })).proof).toEqual({
      verified: true,
      did: CARD.id,
      level: undefined,
      reasons: [],
    });
  });
});

describe('a capability verifier whose answer is not a capability check', () => {
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', 'handshake'],
    ['{}', {}],
    ['a verified that is a string', { verified: 'handshake', unverified: [] }],
    ['a verified that holds a value that is not a string', { verified: ['handshake', 7], unverified: [] }],
    ['an unverified that is not an array', { verified: ['handshake'], unverified: 0 }],
    ['an unverified that holds a value that is not a string', { verified: ['handshake'], unverified: [null] }],
    ['an answer whose verified throws', throwingOn('verified', { unverified: [] })],
    ['an answer whose unverified throws', throwingOn('unverified', { verified: ['handshake'] })],
    ['an answer whose fresh throws', throwingOn('fresh', { verified: ['handshake'], unverified: [] })],
  ])('counts no capability verified, and does not throw, on %s', async (_label, answer) => {
    const result = await withAnswer('capabilityVerifier', answer);
    expect(result).toMatchObject({ ok: true, conformanceLevel: 'L1', verifiedCapabilities: [] });
  });

  it.each([['"false"', 'false'], ['"true"', 'true'], ['1', 1], ['0', 0], ['null', null], ['false', false]])(
    'reads a fresh of %s as not fresh, which keeps the Card at L2',
    async (_label, fresh) => {
      const result = await withAnswer('capabilityVerifier', { verified: ['handshake'], unverified: [], fresh });
      expect(result).toMatchObject({ conformanceLevel: 'L2', verifiedCapabilities: ['handshake'] });
    },
  );

  it('reads a fresh that is left out, or undefined, as unknown, which does not demote', async () => {
    expect(await withAnswer('capabilityVerifier', { verified: ['handshake'], unverified: [] })).toMatchObject({ conformanceLevel: 'L3' });
    expect(await withAnswer('capabilityVerifier', { verified: ['handshake'], unverified: [], fresh: undefined })).toMatchObject({
      conformanceLevel: 'L3',
    });
  });

  it('keeps the floor at L1 while a capability is unverified', async () => {
    expect(await withAnswer('capabilityVerifier', { verified: ['handshake'], unverified: ['payments'] })).toMatchObject({
      conformanceLevel: 'L1',
      verifiedCapabilities: ['handshake'],
    });
  });
});
