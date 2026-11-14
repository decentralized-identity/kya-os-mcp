/**
 * Every dependency the host supplies that the Entity Card verifiers wait on has the 5 seconds a DID
 * resolver has. One that has not answered by then is refused as each verifier refuses a dependency
 * that fails: `verifyRequestDelegation` with the code for a chain it could not resolve, a hop whose
 * proof did not verify or a status it could not prove; `evaluateDelegationChain` with a chain that
 * is not ok; `verifyCard` with the claim unverified, or the Card revoked; `verifyCardProof` with the
 * reason it gives a seam that throws. None waits on, and none throws. Each dependency here hangs on a promise that never settles; the clock is faked, the chain
 * and its proofs are real.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { OUTBOUND_READ_TIMEOUT_MS } from '../../utils/outbound-read-limits.js';
import { evaluateDelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import {
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RequestDelegationInput,
  type VerifyRequestDelegationDeps,
} from '../request-delegation.js';
import { buildCardProof, verifyCard, verifyCardProof, type EntityCard, type VerifyCardDeps } from '../index.js';
import { AUD, NONCE, PROOF_KEY, REQ, clock, deps as proofDeps, keypair } from './proof-helpers.js';
import { NOW_MS, RESOURCE, parties, twoHopChain, type ChainParties } from './signed-chain-helpers.js';

const clear = async () => ({ revoked: false, fresh: true });

afterEach(() => {
  vi.useRealTimers();
});

/**
 * What `work` settles to when the dependency it is handed, one that never answers, has been waited
 * on for 5,000 ms: it must still be pending 1 ms before, settle at the deadline, and leave no timer
 * behind. The clock moves only once the dependency has been asked, so the real signature checks
 * before it have finished.
 */
async function atTheDeadline<T>(work: (never: <A>() => Promise<A>) => Promise<T>): Promise<T> {
  vi.useFakeTimers();
  let asked!: () => void;
  const reached = new Promise<void>((resolve) => {
    asked = resolve;
  });
  let settled: { value: T } | undefined;
  const done = work(() => {
    asked();
    return new Promise<never>(() => undefined);
  }).then((value) => {
    settled = { value };
  });
  await reached;
  await vi.advanceTimersByTimeAsync(OUTBOUND_READ_TIMEOUT_MS - 1);
  expect(settled).toBeUndefined();
  await vi.advanceTimersByTimeAsync(1);
  await done;
  expect(vi.getTimerCount()).toBe(0);
  return settled!.value;
}

describe('verifyRequestDelegation', () => {
  const deps = (p: ChainParties, overrides: Partial<VerifyRequestDelegationDeps>): VerifyRequestDelegationDeps => ({
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
    checkRevocation: clear,
    now: () => NOW_MS,
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

  it('refuses a chain its resolver has not returned in 5,000 ms as delegation_unresolvable', async () => {
    const p = parties();
    const input: RequestDelegationInput = { meta: {}, proofDid: p.subAgent.did, action: 'orders.place' };
    expect(await atTheDeadline((never) => verifyRequestDelegation(input, deps(p, { resolveDelegationChain: never })))).toEqual({
      ok: false,
      code: 'delegation_unresolvable',
      reasons: ['delegation chain could not be resolved: the chain resolver did not answer within 5 seconds'],
      source: 'resolved',
    });
  });

  it('refuses a hop whose proof verifier has not answered in 5,000 ms as delegation_invalid', async () => {
    const p = parties();
    expect(await atTheDeadline((never) => verifyRequestDelegation(carried(p), deps(p, { verifyHopProof: never })))).toEqual({
      ok: false,
      code: 'delegation_invalid',
      reasons: ['hop 0: the hop proof verifier did not answer within 5 seconds'],
      source: 'carried',
    });
  });

  it('refuses a chain whose revocation checker has not answered in 5,000 ms as delegation_revoked', async () => {
    const p = parties();
    const result = await atTheDeadline((never) => verifyRequestDelegation(carried(p), deps(p, { checkRevocation: never })));
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked', source: 'carried' });
    if (result.ok) throw new Error('unreachable');
    expect(result.reasons).toHaveLength(1);
    expect(result.reasons[0]).toMatch(/^revocation: hop 0 \(list ".*", index ".*"\) is unresolvable: the revocation checker did not answer within 5 seconds$/);
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
  it('finds a chain whose revocation checker has not answered in 5,000 ms not ok and not fresh', async () => {
    const chain = twoHopChain(parties());
    const result = await atTheDeadline((never) => evaluateDelegationChain(chain, never, { resource: RESOURCE, now: () => NOW_MS }));
    expect(result).toMatchObject({ ok: false, fresh: false });
    expect(result.reasons.at(-1)).toMatch(/is unresolvable: the revocation checker did not answer within 5 seconds$/);
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
  };

  it('verifies the Card at L3 when every seam answers, and leaves no timer behind', async () => {
    vi.useFakeTimers();
    expect(await verifyCard(card, answering)).toMatchObject({ ok: true, conformanceLevel: 'L3' });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('counts no capability verified when the capability verifier has not answered in 5,000 ms', async () => {
    const result = await atTheDeadline((never) => verifyCard(card, { ...answering, capabilityVerifier: never }));
    expect(result).toMatchObject({ ok: true, conformanceLevel: 'L1', verifiedCapabilities: [] });
  });

  it('finds the Card not accountable when the accountability verifier has not answered in 5,000 ms', async () => {
    const result = await atTheDeadline((never) => verifyCard(card, { ...answering, accountabilityVerifier: never }));
    expect(result).toMatchObject({ ok: false, accountability: { verified: false } });
  });

  it('finds an attestation unverified when the attestation verifier has not answered in 5,000 ms', async () => {
    const result = await atTheDeadline((never) => verifyCard(card, { ...answering, attestationVerifier: never }));
    expect(result).toMatchObject({ ok: false, attestations: [{ type: 'IdentityVerification', verified: false }] });
  });

  it('finds the proof unverified, saying who did not answer, when the proof verifier has not answered in 5,000 ms', async () => {
    const result = await atTheDeadline((never) => verifyCard(card, { ...answering, proofVerifier: never }));
    expect(result).toMatchObject({
      ok: true,
      conformanceLevel: 'L2',
      proof: { verified: false, reasons: ['the proof verifier did not answer within 5 seconds'] },
    });
  });

  it('finds the Card revoked when the status list checker has not answered in 5,000 ms', async () => {
    const result = await atTheDeadline((never) => verifyCard(card, { ...answering, statusListChecker: never }));
    expect(result).toMatchObject({ ok: false, conformanceLevel: 'L1', revocation: { revoked: true, fresh: false } });
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
    const seams = proofDeps(publicJwk, { trustResolveKeyAuthority: false, resolveDidKeys: async () => [publicJwk] });
    expect(await verifyCardProof(proof, REQ, seams)).toMatchObject({ ok: true });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('finds the key unresolvable when resolveKey has not answered in 5,000 ms', async () => {
    const { proof, publicJwk } = await minted();
    const result = await atTheDeadline((never) => verifyCardProof(proof, REQ, proofDeps(publicJwk, { resolveKey: never })));
    expect(result).toMatchObject({ ok: false, reasons: ['key_unresolvable'] });
  });

  it("finds the DID's keys unresolvable when resolveDidKeys has not answered in 5,000 ms", async () => {
    const { proof, publicJwk } = await minted();
    const seams = (never: <A>() => Promise<A>) => proofDeps(publicJwk, { trustResolveKeyAuthority: false, resolveDidKeys: never });
    const result = await atTheDeadline((never) => verifyCardProof(proof, REQ, seams(never)));
    expect(result).toMatchObject({ ok: false, reasons: ['did_keys_unresolvable'] });
  });

  it('finds the nonce cache unavailable when consumeNonceIfFresh has not answered in 5,000 ms', async () => {
    const { proof, publicJwk } = await minted();
    const result = await atTheDeadline((never) => verifyCardProof(proof, REQ, proofDeps(publicJwk, { consumeNonceIfFresh: never })));
    expect(result).toMatchObject({ ok: false, reasons: ['nonce_cache_unavailable'] });
  });
});
