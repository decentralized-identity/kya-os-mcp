/**
 * Each refusal of the Entity Card verifiers carries a stable code and whether it is transient,
 * beside its reasons: the card profile's chain rules, its chain walk with revocation, the
 * delegation a request carries and the guard over it, and an Entity Card's own claims. Every case
 * goes through `@kya-os/mcp/card` as an adopter calls it, over real signed hops and lists.
 */

import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateDelegationChain,
  isTransientRefusal,
  RefusalError,
  requireDelegation,
  toDelegationChainMeta,
  validateDelegationChain,
  verifyCard,
  verifyRequestDelegation,
  type DelegationChain,
  type DelegationChainContext,
  type EntityCard,
  type RefusalCode,
  type RequestDelegationInput,
  type VerifyCardDeps,
  type VerifyRequestDelegationDeps,
} from '../index.js';
import { NOW_MS, RESOURCE, hop, now, parties, serve, statusList, twoHopChain, type ChainParties } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const p = parties();
const chain = twoHopChain(p);
const [root, leaf] = chain;

/** A dependency that never answers. */
const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

/** The code and transient flag of `code`. */
const coded = (code: RefusalCode) => ({ code, transient: isTransientRefusal(code) });

/** A checker over the root's list with `revoked` bits set. */
const checkerOf = (revoked: number[] = []) =>
  createRevocationChecker({ fetch: serve(statusList(p.acme, revoked)), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });

describe("the card profile's validateDelegationChain", () => {
  const rootUntil = (validUntil: string) =>
    hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:acme-root', parentCapability: RESOURCE, allowedAction: ['orders.place'], validUntil });
  const expired = rootUntil('2026-01-01T00:00:00Z');

  it.each<[string, DelegationChain, DelegationChainContext, RefusalCode]>([
    ['an empty chain', [], {}, 'chain_invalid'],
    ['under a maxChainLength that is not a positive integer', chain, { maxChainLength: 0, now }, 'configuration_error'],
    ['longer than maxChainLength', chain, { maxChainLength: 1, now }, 'chain_invalid'],
    ['whose root does not name this resource', chain, { resource: 'did:web:else.example', now }, 'chain_invalid'],
    ['whose root is not issued by the resourceOwner', chain, { resourceOwner: p.agent.did, now }, 'untrusted_root'],
    ['whose re-delegation is wider than its parent', [root, hop({ ...hopOf(p), allowedAction: ['orders.refund'] })], { now }, 'chain_invalid'],
    ['with a credential past its validUntil', [expired], { now }, 'delegation_expired'],
    ['with a credential whose validUntil is not a date', [rootUntil('not a date')], { now }, 'delegation_malformed'],
    ['with a credential not yet valid', [{ ...root, validFrom: '2027-01-01T00:00:00Z' }, leaf], { now }, 'delegation_not_yet_valid'],
  ])('codes %s', (_name, refused, ctx, code) => {
    const result = validateDelegationChain(refused, ctx);
    expect({ ok: result.ok, ...pick(result) }, result.reasons.join()).toEqual({ ok: false, ...coded(code) });
  });

  it('codes the first rule a chain breaks, and a chain that passes not at all', () => {
    const result = validateDelegationChain([expired, leaf], { resourceOwner: p.agent.did, now });
    expect(pick(result)).toEqual(coded('untrusted_root'));
    const passed = validateDelegationChain(chain, { now });
    expect(passed.ok).toBe(true);
    expect(passed).not.toHaveProperty('code');
    expect(passed).not.toHaveProperty('transient');
  });
});

describe("the card profile's evaluateDelegationChain", () => {
  it.each<[string, () => ReturnType<typeof evaluateDelegationChain>, RefusalCode]>([
    ['a chain whose structure is refused', () => evaluateDelegationChain(chain, checkerOf(), { maxChainLength: 1, now }), 'chain_invalid'],
    ['a chain with a revoked credential', () => evaluateDelegationChain(chain, checkerOf([7]), { resourceOwner: p.acme.did, now }), 'delegation_revoked'],
    ['a chain whose checker never answers', () => evaluateDelegationChain(chain, never, { now, dependencyTimeoutMs: 20 }), 'deadline_exceeded'],
  ])('codes %s', async (_name, evaluate, code) => {
    const result = await evaluate();
    expect({ ok: result.ok, ...pick(result) }, result.reasons.join()).toEqual({ ok: false, ...coded(code) });
  });

  it('codes a chain that passes not at all', async () => {
    const result = await evaluateDelegationChain(chain, checkerOf(), { resourceOwner: p.acme.did, now });
    expect(result.ok).toBe(true);
    expect(result).not.toHaveProperty('code');
  });
});

describe('verifyRequestDelegation and requireDelegation', () => {
  const deps = (overrides: Partial<VerifyRequestDelegationDeps> = {}): VerifyRequestDelegationDeps => ({
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: checkerOf(),
    now: () => NOW_MS,
    ...overrides,
  });
  const carrying = (meta: unknown, action = 'orders.place'): RequestDelegationInput => ({ meta, proofDid: p.subAgent.did, action });
  const carried = carrying(toDelegationChainMeta(chain));

  it.each<[string, RequestDelegationInput, Partial<VerifyRequestDelegationDeps>, string, RefusalCode]>([
    ['a request that carries no chain, with no resolver', carrying({}), {}, 'delegation_missing', 'needs_authorization'],
    ['a request whose resolver finds no chain', carrying({}), { resolveDelegationChain: async () => undefined }, 'delegation_missing', 'needs_authorization'],
    ['a request whose resolver throws', carrying({}), { resolveDelegationChain: async () => { throw new Error('registry down'); } }, 'delegation_unresolvable', 'runtime_error'],
    ['a request whose resolver never answers', carrying({}), { resolveDelegationChain: never, dependencyTimeoutMs: 20 }, 'delegation_unresolvable', 'deadline_exceeded'],
    ['a resolved chain with a value that is not a credential', carrying({}), { resolveDelegationChain: async () => [5] as never }, 'delegation_invalid', 'delegation_malformed'],
    ['a carried member that is not an array', carrying({ 'org.kya-os/delegation-chain': 'chain' }), {}, 'delegation_invalid', 'delegation_malformed'],
    ['a carried chain that is empty', carrying({ 'org.kya-os/delegation-chain': [] }), {}, 'delegation_invalid', 'chain_invalid'],
    ['a carried chain under a maxChainLength it cannot use', carried, { maxChainLength: 0 }, 'delegation_invalid', 'configuration_error'],
    ['a carried chain longer than maxChainLength', carried, { maxChainLength: 1 }, 'delegation_invalid', 'chain_invalid'],
    ['a carried hop that is not a DelegationCredential', carrying({ 'org.kya-os/delegation-chain': [{ type: 'x' }] }), {}, 'delegation_invalid', 'delegation_malformed'],
    ['a chain whose root does not name this resource', carried, { resource: 'did:web:else.example' }, 'delegation_invalid', 'chain_invalid'],
    ['a chain past its validUntil', carried, { now: () => Date.parse('2028-01-01T00:00:00Z') }, 'delegation_invalid', 'delegation_expired'],
    ['a chain whose leaf delegate is not the proof DID', { ...carried, proofDid: p.agent.did }, {}, 'delegation_invalid', 'holder_binding_failed'],
    ['a chain whose root trustedRootIssuers does not list', carried, { trustedRootIssuers: [p.agent.did] }, 'delegation_invalid', 'untrusted_root'],
    ['a chain whose hop proof does not verify', carried, { verifyHopProof: () => false }, 'delegation_invalid', 'invalid_proof'],
    ['a chain whose hop proof verifier throws', carried, { verifyHopProof: () => { throw new Error('boom'); } }, 'delegation_invalid', 'runtime_error'],
    ['a chain whose hop proof verifier throws a RefusalError', carried, { verifyHopProof: () => { throw new RefusalError('did_unavailable', 'try later'); } }, 'delegation_invalid', 'did_unavailable'],
    [
      'a chain whose hop proof verifier throws a RefusalError of a code outside the catalog',
      carried,
      { verifyHopProof: () => { throw new RefusalError('REVOKED' as RefusalCode, 'revoked by the host'); } },
      'delegation_invalid',
      'invalid_proof',
    ],
    [
      "a chain whose hop issuer's DID resolver throws a RefusalError of a code outside the catalog",
      carried,
      { verifyHopProof: createDelegationProofVerifier({ didResolver: { resolve: async () => { throw new RefusalError('REVOKED' as RefusalCode, 'revoked by the host'); } } }) },
      'delegation_invalid',
      'invalid_proof',
    ],
    ['a chain whose hop proof verifier never answers', carried, { verifyHopProof: never, dependencyTimeoutMs: 20 }, 'delegation_invalid', 'deadline_exceeded'],
    ['a chain that does not grant the action', carrying(toDelegationChainMeta(chain), 'orders.refund'), {}, 'action_not_delegated', 'insufficient_scope'],
    ['a chain with a revoked credential', carried, { checkRevocation: checkerOf([7]) }, 'delegation_revoked', 'delegation_revoked'],
    ['a chain whose status list is not served', carried, { checkRevocation: createRevocationChecker({ fetch: serve(undefined) }) }, 'delegation_revoked', 'status_unavailable'],
    // Its hop proofs pass at once, so only the checker can run out the short deadline.
    ['a chain whose revocation checker never answers', carried, { verifyHopProof: () => true, checkRevocation: never, dependencyTimeoutMs: 20 }, 'delegation_revoked', 'deadline_exceeded'],
    ['a chain whose revocation checker throws', carried, { checkRevocation: async () => { throw new Error('boom'); } }, 'delegation_revoked', 'status_unavailable'],
  ])('codes %s', async (_name, input, overrides, gateCode, code) => {
    const result = await verifyRequestDelegation(input, deps(overrides));
    expect(result.ok ? result : { ok: result.ok, code: result.code, refusalCode: result.refusalCode, transient: result.transient }, JSON.stringify(result)).toEqual({
      ok: false,
      code: gateCode,
      refusalCode: code,
      transient: isTransientRefusal(code),
    });
    const guarded = await requireDelegation(deps(overrides))(input);
    expect(guarded).toMatchObject({ ok: false, error: { code: gateCode }, refusalCode: code, transient: isTransientRefusal(code) });
    if (!guarded.ok) expect(Object.keys(guarded.error).sort()).toEqual(['code', 'message', 'reasons']);
  });

  it('codes a request it accepts not at all', async () => {
    const result = await verifyRequestDelegation(carried, deps());
    expect(result.ok).toBe(true);
    expect(result).not.toHaveProperty('refusalCode');
    expect(result).not.toHaveProperty('transient');
  });
});

describe('verifyCard', () => {
  const card: EntityCard = {
    id: p.acme.did,
    entityType: 'agent',
    name: 'Acme',
    responsibleParty: p.agent.did,
    attestations: [{ type: 'IdentityVerification', vc: 'jwt' }],
    revocation: { statusListCredential: 'https://acme.example/status/delegations', statusListIndex: '7' },
  };
  const passing: VerifyCardDeps = {
    accountabilityVerifier: async () => ({ verified: true, fresh: true }),
    attestationVerifier: async () => true,
    statusListChecker: checkerOf(),
  };

  it.each<[string, Partial<VerifyCardDeps>, RefusalCode]>([
    ['a Card whose accountability no verifier checks', { accountabilityVerifier: undefined }, 'configuration_error'],
    ['a Card whose accountability verifier answers no', { accountabilityVerifier: async () => ({ verified: false }) }, 'claim_unverified'],
    ['a Card whose accountability verifier answers false', { accountabilityVerifier: async () => false }, 'claim_unverified'],
    ['a Card whose accountability verifier answers what is not a verdict', { accountabilityVerifier: async () => 'yes' as never }, 'runtime_error'],
    ['a Card whose accountability verifier never answers', { accountabilityVerifier: never, dependencyTimeoutMs: 20 }, 'deadline_exceeded'],
    ['a Card whose attestations no verifier checks', { attestationVerifier: undefined }, 'configuration_error'],
    ['a Card whose attestation verifier answers no', { attestationVerifier: async () => false }, 'claim_unverified'],
    ['a Card whose attestation verifier never answers', { attestationVerifier: never, dependencyTimeoutMs: 20 }, 'deadline_exceeded'],
    ['a revoked Card', { statusListChecker: checkerOf([7]) }, 'delegation_revoked'],
    ['a Card whose status list is not served', { statusListChecker: createRevocationChecker({ fetch: serve(undefined) }) }, 'status_unavailable'],
    ['a Card whose checker never answers', { statusListChecker: never, dependencyTimeoutMs: 20 }, 'deadline_exceeded'],
    ['a Card whose checker answers what is not a status', { statusListChecker: async () => 'clear' as never }, 'status_unavailable'],
    ['a Card whose checker throws', { statusListChecker: async () => { throw new Error('boom'); } }, 'status_unavailable'],
  ])('codes %s', async (_name, overrides, code) => {
    const result = await verifyCard(card, { ...passing, ...overrides });
    expect({ ok: result.ok, ...pick(result) }).toEqual({ ok: false, ...coded(code) });
  });

  it('codes the revocation it reports as the checker coded it', async () => {
    expect((await verifyCard(card, { ...passing, statusListChecker: checkerOf([7]) })).revocation).toEqual({
      revoked: true,
      fresh: true,
      ...coded('delegation_revoked'),
    });
    expect((await verifyCard(card, { ...passing, statusListChecker: never, dependencyTimeoutMs: 20 })).revocation).toMatchObject(
      coded('deadline_exceeded'),
    );
  });

  it('codes a Card refused for several claims by the first that is not transient, else by the first', async () => {
    const late = await verifyCard(card, { ...passing, accountabilityVerifier: never, attestationVerifier: async () => false, dependencyTimeoutMs: 20 });
    expect(pick(late)).toEqual(coded('claim_unverified'));
    const both = await verifyCard(card, { ...passing, accountabilityVerifier: never, statusListChecker: never, dependencyTimeoutMs: 20 });
    expect(pick(both)).toEqual(coded('deadline_exceeded'));
    const first = await verifyCard(card, { ...passing, accountabilityVerifier: async () => false, statusListChecker: checkerOf([7]) });
    expect(pick(first)).toEqual(coded('claim_unverified'));
  });

  it('codes a Card it accepts not at all', async () => {
    const result = await verifyCard(card, passing);
    expect(result.ok).toBe(true);
    expect(result).not.toHaveProperty('code');
    expect(result).not.toHaveProperty('transient');
    expect(result.revocation).toEqual({ revoked: false, fresh: true });
  });
});

/** The leaf hop's options, for a variant of it. */
function hopOf(c: ChainParties) {
  return {
    issuer: c.agent,
    invoker: c.subAgent.did,
    id: 'urn:zcap:agent-leaf',
    parentCapability: 'urn:zcap:acme-root',
    allowedAction: ['orders.place'],
    caveats: [{ type: 'MaxAmount', limit: '100.00', currency: 'USD' }],
    statusIndex: 7,
  };
}

/** The code and transient flag of `result`, as it carries them. */
function pick(result: { code?: unknown; transient?: unknown }) {
  return { code: result.code, transient: result.transient };
}
