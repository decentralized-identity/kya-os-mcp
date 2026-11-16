/**
 * Every dependency the host supplies that the Entity Card verifiers wait on has the time a DID
 * resolver has: 5 seconds, or the `dependencyTimeoutMs` the host gives that verifier. One that has
 * not answered by then is refused as each verifier refuses a dependency that fails:
 * `verifyRequestDelegation` with the code for a chain it could not resolve, a hop whose proof did
 * not verify or a status it could not prove; `evaluateDelegationChain` and `evaluateRevocationChain`
 * with a chain that is not ok; `verifyCard` with the claim unverified, or the Card revoked;
 * `verifyCardProof` with the reason it gives a seam that throws. None waits on, and none throws.
 * Each dependency here hangs on a promise that never settles; the clock is faked, the chain and
 * its proofs are real. Every case runs under the default and under a raised deadline.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEADLINES, REFUSED_TIMEOUTS, settledAt, timeoutTypeError, type Hang } from '../../__tests__/utils/deadlines.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { evaluateDelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import {
  requireDelegation,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RequestDelegationInput,
  type VerifyRequestDelegationDeps,
} from '../request-delegation.js';
import { createRevocationChecker, evaluateRevocationChain } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { buildCardProof, requireProof, verifyCard, verifyCardProof, type EntityCard, type VerifyCardDeps } from '../index.js';
import { AUD, NONCE, PROOF_KEY, REQ, clock, deps as proofDeps, keypair } from './proof-helpers.js';
import { issuerOf } from '../../utils/guards.js';
import { NOW_MS, RESOURCE, STATUS_URL, parties, serve, statusList, twoHopChain, type ChainParties } from './signed-chain-helpers.js';

/** A status entry a checker is asked about. */
const ENTRY = { statusListIndex: '7', statusListCredential: STATUS_URL };
const clear = async () => ({ revoked: false, fresh: true });

afterEach(() => {
  vi.useRealTimers();
});

describe.each(DEADLINES)('%s', (_label, option, ms, stated) => {
  describe('verifyRequestDelegation', () => {
    const deps = (p: ChainParties, overrides: Partial<VerifyRequestDelegationDeps>): VerifyRequestDelegationDeps => ({
      resource: RESOURCE,
      trustedRootIssuers: [p.acme.did],
      verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
      checkRevocation: clear,
      now: () => NOW_MS,
      ...option,
      ...overrides,
    });
    const carried = (p: ChainParties): RequestDelegationInput => ({
      meta: { ...toDelegationChainMeta(twoHopChain(p)) }, proofDid: p.subAgent.did, action: 'orders.place',
    });

    it('accepts the chain when every dependency answers, and leaves no timer behind', async () => {
      const p = parties();
      vi.useFakeTimers();
      expect(await verifyRequestDelegation(carried(p), deps(p, {}))).toMatchObject({ ok: true, source: 'carried' });
      expect(vi.getTimerCount()).toBe(0);
    });

    it('refuses a chain its resolver has not returned by the deadline as delegation_unresolvable', async () => {
      const p = parties();
      const input: RequestDelegationInput = { meta: {}, proofDid: p.subAgent.did, action: 'orders.place' };
      expect(await settledAt(ms, (never) => verifyRequestDelegation(input, deps(p, { resolveDelegationChain: never })))).toEqual({
        ok: false,
        code: 'delegation_unresolvable',
        reasons: [`delegation chain could not be resolved: the chain resolver did not answer within ${stated}`],
        source: 'resolved',
      });
    });

    it('refuses a hop whose proof verifier has not answered by the deadline as delegation_invalid', async () => {
      const p = parties();
      expect(await settledAt(ms, (never) => verifyRequestDelegation(carried(p), deps(p, { verifyHopProof: never })))).toEqual({
        ok: false,
        code: 'delegation_invalid',
        reasons: [`hop 0: the hop proof verifier did not answer within ${stated}`],
        source: 'carried',
      });
    });

    it('refuses a chain whose revocation checker has not answered by the deadline as delegation_revoked', async () => {
      const p = parties();
      const result = await settledAt(ms, (never) => verifyRequestDelegation(carried(p), deps(p, { checkRevocation: never })));
      expect(result).toMatchObject({ ok: false, code: 'delegation_revoked', source: 'carried' });
      if (result.ok) throw new Error('unreachable');
      expect(result.reasons).toHaveLength(1);
      expect(result.reasons[0]).toMatch(new RegExp(`^revocation: hop 0 \\(list ".*", index ".*"\\) is unresolvable: the revocation checker did not answer within ${stated}$`));
    });

    it('still refuses a revocation checker that throws as it did', async () => {
      const p = parties();
      const checkRevocation = async (): Promise<never> => {
        throw new Error('list offline');
      };
      expect(await verifyRequestDelegation(carried(p), deps(p, { checkRevocation }))).toMatchObject({
        ok: false, code: 'delegation_revoked', reasons: ['revocation checker threw: status unprovable, fail-closed'],
      });
    });
  });

  describe('evaluateDelegationChain', () => {
    it('finds a chain whose revocation checker has not answered by the deadline not ok and not fresh', async () => {
      const chain = twoHopChain(parties());
      const result = await settledAt(ms, (never) => evaluateDelegationChain(chain, never, { resource: RESOURCE, now: () => NOW_MS, ...option }));
      expect(result).toMatchObject({ ok: false, fresh: false });
      expect(result.reasons.at(-1)).toMatch(new RegExp(`is unresolvable: the revocation checker did not answer within ${stated}$`));
    });
  });

  describe('verifyCard', () => {
    const card: EntityCard = {
      id: 'did:web:example.com:agents:acme',
      entityType: 'agent',
      name: 'Acme',
      capabilities: ['handshake'],
      responsibleParty: 'did:web:acme.example',
      attestations: [{ type: 'IdentityVerification', vc: 'jwt', issuer: 'did:web:kyb.example' }],
      revocation: { statusListIndex: '7', statusListCredential: 'https://acme.example/status/cards' },
    };
    /** Seams that verify every claim of {@link card}, so each test hangs one of them alone. */
    const answering: VerifyCardDeps = {
      capabilityVerifier: async (capabilities) => ({ verified: capabilities.map((c) => (typeof c === 'string' ? c : c.name)), unverified: [] }),
      accountabilityVerifier: async () => ({ verified: true, fresh: true }),
      attestationVerifier: async () => true,
      proof: {},
      request: { method: 'tools/call', params: {} },
      proofVerifier: async () => ({ ok: true, did: 'did:web:example.com:agents:acme', level: 'L3', reasons: [] }),
      statusListChecker: clear,
      ...option,
    };

    it('verifies the Card at L3 when every seam answers, and leaves no timer behind', async () => {
      vi.useFakeTimers();
      expect(await verifyCard(card, answering)).toMatchObject({ ok: true, conformanceLevel: 'L3' });
      expect(vi.getTimerCount()).toBe(0);
    });

    it('counts no capability verified when the capability verifier has not answered by the deadline', async () => {
      const result = await settledAt(ms, (never) => verifyCard(card, { ...answering, capabilityVerifier: never }));
      expect(result).toMatchObject({ ok: true, conformanceLevel: 'L1', verifiedCapabilities: [] });
    });

    it('finds the Card not accountable when the accountability verifier has not answered by the deadline', async () => {
      const result = await settledAt(ms, (never) => verifyCard(card, { ...answering, accountabilityVerifier: never }));
      expect(result).toMatchObject({ ok: false, accountability: { verified: false } });
    });

    it('finds an attestation unverified when the attestation verifier has not answered by the deadline', async () => {
      const result = await settledAt(ms, (never) => verifyCard(card, { ...answering, attestationVerifier: never }));
      expect(result).toMatchObject({ ok: false, attestations: [{ type: 'IdentityVerification', verified: false }] });
    });

    it('finds the proof unverified, saying who did not answer, when the proof verifier has not answered by the deadline', async () => {
      const result = await settledAt(ms, (never) => verifyCard(card, { ...answering, proofVerifier: never }));
      expect(result).toMatchObject({
        ok: true,
        conformanceLevel: 'L2',
        proof: { verified: false, reasons: [`the proof verifier did not answer within ${stated}`] },
      });
    });

    it('finds the Card revoked when the status list checker has not answered by the deadline', async () => {
      const result = await settledAt(ms, (never) => verifyCard(card, { ...answering, statusListChecker: never }));
      expect(result).toMatchObject({ ok: false, conformanceLevel: 'L1' });
      expect(result.revocation).toEqual({ revoked: true, fresh: false, reason: `the revocation checker did not answer within ${stated}` });
    });

    it.each(['capabilityVerifier', 'accountabilityVerifier', 'attestationVerifier'] as const)(
      'still throws what the %s throws, as it did',
      async (seam) => {
        const thrown = new Error(`${seam} offline`);
        const throwing = async (): Promise<never> => {
          throw thrown;
        };
        await expect(verifyCard(card, { ...answering, [seam]: throwing })).rejects.toBe(thrown);
      },
    );

    it('reads an answer that is the text of a missed deadline as an answer it cannot read, not as a missed deadline', async () => {
      const text = `the revocation checker did not answer within ${stated}`;
      const result = await verifyCard(card, { ...answering, statusListChecker: (async () => text) as never });
      expect(result.revocation).toEqual({
        revoked: true,
        fresh: false,
        reason: `the Card's revocation status could not be read: the revocation checker's answer ("${text}") is not an object`,
      });
    });
  });

  describe('verifyCardProof', () => {
    const minted = async () => {
      const { signer, publicJwk } = await keypair();
      const proof = (await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock }))[PROOF_KEY];
      return { proof, publicJwk };
    };

    it('verifies the proof when every seam answers, and leaves no timer behind', async () => {
      const { proof, publicJwk } = await minted();
      vi.useFakeTimers();
      const seams = proofDeps(publicJwk, { ...option, trustResolveKeyAuthority: false, resolveDidKeys: async () => [publicJwk] });
      expect(await verifyCardProof(proof, REQ, seams)).toMatchObject({ ok: true });
      expect(vi.getTimerCount()).toBe(0);
    });

    it('finds the key unresolvable when resolveKey has not answered by the deadline', async () => {
      const { proof, publicJwk } = await minted();
      const result = await settledAt(ms, (never) => verifyCardProof(proof, REQ, proofDeps(publicJwk, { ...option, resolveKey: never })));
      expect(result).toMatchObject({ ok: false, reasons: ['key_unresolvable'] });
    });

    it("finds the DID's keys unresolvable when resolveDidKeys has not answered by the deadline", async () => {
      const { proof, publicJwk } = await minted();
      const seams = (never: Hang) => proofDeps(publicJwk, { ...option, trustResolveKeyAuthority: false, resolveDidKeys: never });
      const result = await settledAt(ms, (never) => verifyCardProof(proof, REQ, seams(never)));
      expect(result).toMatchObject({ ok: false, reasons: ['did_keys_unresolvable'] });
    });

    it('finds the nonce cache unavailable when consumeNonceIfFresh has not answered by the deadline', async () => {
      const { proof, publicJwk } = await minted();
      const result = await settledAt(ms, (never) => verifyCardProof(proof, REQ, proofDeps(publicJwk, { ...option, consumeNonceIfFresh: never })));
      expect(result).toMatchObject({ ok: false, reasons: ['nonce_cache_unavailable'] });
    });
  });

  describe('evaluateRevocationChain', () => {
    it('finds a chain whose checker has not answered by the deadline not ok and not fresh', async () => {
      const result = await settledAt(ms, (never) => evaluateRevocationChain([ENTRY], never, option));
      expect(result).toEqual({
        ok: false,
        fresh: false,
        reasons: [`revocation: hop 0 (list "${STATUS_URL}", index "7") is unresolvable: the revocation checker did not answer within ${stated}`],
      });
    });

    it('reads an answer that is the text of a missed deadline as an answer it cannot read, not as a missed deadline', async () => {
      const text = `the revocation checker did not answer within ${stated}`;
      const result = await evaluateRevocationChain([ENTRY], (async () => text) as never, option);
      expect(result.reasons).toEqual([
        `revocation: hop 0 (list "${STATUS_URL}", index "7") has a status that could not be read: the revocation checker's answer ("${text}") is not an object`,
      ]);
    });
  });

  describe('a checker built with createRevocationChecker, called directly', () => {
    it('fails closed when its list read has not answered by the deadline', async () => {
      const result = await settledAt(ms, (never) => createRevocationChecker({ fetch: never, ...option })(ENTRY));
      expect(result).toEqual({ revoked: true, fresh: false });
    });

    it('fails closed when its verifyStatusList has not answered by the deadline', async () => {
      const list = statusList(parties().acme, []);
      const result = await settledAt(ms, (never) =>
        createRevocationChecker({ fetch: serve(list), verifyStatusList: never, now: () => NOW_MS, ...option })(
          ENTRY, { credentialIssuer: issuerOf(list.issuer)! },
        ));
      expect(result).toEqual({ revoked: true, fresh: false });
    });
  });

  describe('the proof verifiers built for a hop and for a status list', () => {
    it('find a proof unverified when the DID resolver has not answered by the deadline', async () => {
      const [root] = twoHopChain(parties());
      for (const build of [createDelegationProofVerifier, createStatusListProofVerifier]) {
        const verified = await settledAt(ms, async (never) => build({ didResolver: { resolve: never }, ...option })(root));
        expect(verified).toBe(false);
        vi.useRealTimers();
      }
    });
  });
});

describe('a dependencyTimeoutMs that is not a number of milliseconds a timer can hold', () => {
  const p = parties();
  const delegationDeps = (dependencyTimeoutMs: unknown) => ({
    resource: RESOURCE, verifyHopProof: async () => true, checkRevocation: clear, dependencyTimeoutMs,
  } as VerifyRequestDelegationDeps);
  const input: RequestDelegationInput = { meta: {}, proofDid: p.subAgent.did, action: 'orders.place' };
  const card: EntityCard = { id: 'did:web:example.com:agents:acme', entityType: 'agent', name: 'Acme' };
  const set = <T>(dependencyTimeoutMs: unknown, rest: object = {}): T => ({ ...rest, dependencyTimeoutMs }) as T;

  it.each(REFUSED_TIMEOUTS)('throws a TypeError where a guard, a checker or a proof verifier is built, for %s', (_label, value, got) => {
    const error = timeoutTypeError(got);
    expect(() => requireDelegation(delegationDeps(value))).toThrow(error);
    expect(() => requireProof(set(value, proofDeps({ kty: 'OKP', crv: 'Ed25519', x: '' })))).toThrow(error);
    expect(() => createRevocationChecker(set(value, { fetch: serve(undefined) }))).toThrow(error);
    expect(() => createDelegationProofVerifier(set(value, { didResolver: createDidKeyResolver() }))).toThrow(error);
    expect(() => createStatusListProofVerifier(set(value, { didResolver: createDidKeyResolver() }))).toThrow(error);
  });

  it.each(REFUSED_TIMEOUTS)('rejects with a TypeError, before any dependency is asked, for %s', async (_label, value, got) => {
    const error = timeoutTypeError(got);
    const asked = vi.fn(async () => true);
    await expect(verifyRequestDelegation({ ...input, meta: toDelegationChainMeta(twoHopChain(p)) }, { ...delegationDeps(value), verifyHopProof: asked })).rejects.toThrow(error);
    await expect(evaluateRevocationChain([ENTRY], asked as never, set(value))).rejects.toThrow(error);
    await expect(evaluateDelegationChain(twoHopChain(p), asked as never, set(value, { resource: RESOURCE, now: () => NOW_MS }))).rejects.toThrow(error);
    await expect(verifyCard({ ...card, attestations: [{ type: 'IdentityVerification', vc: 'jwt' }] }, set(value, { attestationVerifier: asked }))).rejects.toThrow(error);
    await expect(verifyCardProof({}, REQ, set(value, proofDeps({ kty: 'OKP', crv: 'Ed25519', x: '' }, { resolveKey: asked as never })))).rejects.toThrow(error);
    expect(asked).not.toHaveBeenCalled();
  });
});
