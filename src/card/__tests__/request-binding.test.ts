/**
 * The delegation a card request proof states, and the chain held to it (SPEC.md §7.8,
 * SPEC-ENTITY-CARD §8, §11.4). A sub-agent holds two chains for one action, from two root issuers the
 * merchant trusts. Its request proof covers `{ method, params }` without `_meta`, and the chain rides
 * in `_meta`, so a party on the path that has seen both chains, and holds no key, can put one in
 * place of the other. Every case runs the shipped path: `buildCardProof`, `requireProof`, and
 * `requireDelegation` with real hop proofs and a real status list; only the network is faked.
 */

import { decodeProtectedHeader } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { delegationCredentialDigest } from '../../delegation/chain-digest.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { NoSignedFormError } from '../../delegation/signed-form.js';
import { DELEGATION_HEADER_PARAMETER, type StatedDelegation } from '../../delegation/stated-delegation.js';
import { logger } from '../../logging/index.js';
import { webCryptoSha256 } from '../../utils/domain-digest.js';
import type { DelegationChain, DelegationCredential } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { requireProof } from '../middleware.js';
import {
  KYA_OS_CARD_PROOF_META_KEY,
  InMemoryNonceCache,
  buildCardProof,
  ed25519SignerFromJwk,
  es256SignerFromJwk,
  verifyCardProof,
  type BuildProofContext,
  type CardProofMeta,
  type P256PrivateJwk,
  type ProofSigner,
} from '../proof/index.js';
import { requestBindingRefusal } from '../request-binding.js';
import { requireDelegation, toDelegationChainMeta, type VerifyRequestDelegationDeps } from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { NOW_MS, RESOURCE, hop, identity, parties, serveAt, statusList, twoHopChain, type ChainParties, type TestIdentity } from './signed-chain-helpers.js';

const REQUEST = { method: 'tools/call', params: { name: 'orders.place', arguments: { sku: 'A-100', qty: 1 } } };
const ACTION = REQUEST.params.name;
const didResolver = createDidKeyResolver();
const digestOf = (credential: object): Promise<string> => delegationCredentialDigest(credential, webCryptoSha256);
const WARNED = ['request-proof-names-no-delegation', 'request-proof-states-none-beside-delegation', 'request-proof-statement-unknown', 'card-proof-signer-wrote-no-delegation'];

let nonces = 0;
const context = (more: Partial<BuildProofContext> = {}): BuildProofContext => ({ audience: RESOURCE, nonce: `n-${(nonces += 1)}`, ...more });
const signerOf = (id: TestIdentity): Promise<ProofSigner> => ed25519SignerFromJwk({ did: id.did, kid: id.method, privateJwk: id.privateJwk });
const statedIn = (proof: CardProofMeta): unknown => decodeProtectedHeader(proof.jws.replace('..', '.e30.'))[DELEGATION_HEADER_PARAMETER];

/** A second root issuer, and the chain it grants the same sub-agent for the same action, under ids of its own. */
function otherChain(p: ChainParties, other: TestIdentity): DelegationChain {
  const root = hop({ issuer: other, invoker: p.agent.did, id: 'urn:zcap:other-root', parentCapability: RESOURCE, allowedAction: ['orders.place'] });
  const leaf = hop({ issuer: p.agent, invoker: p.subAgent.did, id: 'urn:zcap:other-leaf', parentCapability: 'urn:zcap:other-root', allowedAction: ['orders.place'] });
  return [root, leaf];
}

/** The merchant: both guards, trusting Acme and the other root issuer. */
function merchant(p: ChainParties, other: TestIdentity, more: Partial<VerifyRequestDelegationDeps> = {}) {
  const proofGuard = requireProof({
    resolveKey: () => ({ ...p.subAgent.publicJwk, kid: p.subAgent.method }),
    resolveDidKeys: (did) => (did === p.subAgent.did ? [p.subAgent.publicJwk] : []),
    expectedAudience: RESOURCE,
    consumeNonceIfFresh: new InMemoryNonceCache().consume,
  });
  const delegationGuard = requireDelegation({
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did, other.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: createRevocationChecker({
      fetch: serveAt({ 'https://acme.example/status/delegations': statusList(p.acme) }),
      now: () => NOW_MS,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    }),
    now: () => NOW_MS,
    ...more,
  });
  /** One call as it arrives: `meta` is what a party on the path left of the `_meta` the caller sent. */
  const arrive = async (meta: Record<string, unknown>, handOver: 'meta' | 'statement' = 'meta') => {
    const proof = await proofGuard(REQUEST, meta);
    if (!proof.ok) return { ok: false as const, refusalCode: 'invalid_proof', reasons: proof.error.reasons };
    const verdict = await delegationGuard(
      handOver === 'meta'
        ? { meta, proofDid: proof.did, action: ACTION }
        : { meta: toDelegationChainMetaOf(meta), proofDid: proof.did, action: ACTION, statedDelegation: proof.statedDelegation! },
    );
    return verdict.ok ? verdict : { ok: false as const, refusalCode: verdict.refusalCode, reasons: verdict.error.reasons };
  };
  return { arrive, delegationGuard };
}

/** `meta` without the request proof: what a host hands the delegation guard when it verified the proof elsewhere. */
const toDelegationChainMetaOf = ({ [KYA_OS_CARD_PROOF_META_KEY]: _proof, ...rest }: Record<string, unknown>) => rest;

/** A scene: the parties, the two chains, the sub-agent's signer and the merchant. */
async function scene(more: Partial<VerifyRequestDelegationDeps> = {}) {
  const p = parties();
  const other = identity();
  const chosen = twoHopChain(p);
  const signer = await signerOf(p.subAgent);
  /** The `_meta` of a call the sub-agent makes under `chain`, its proof made from the request that carries it. */
  const sends = async (chain: DelegationChain | undefined, ctx: Partial<BuildProofContext> = {}) => {
    const carried = chain === undefined ? {} : toDelegationChainMeta(chain);
    const request = { ...REQUEST, params: { ...REQUEST.params, _meta: carried } };
    return { ...(await buildCardProof(request, signer, context(ctx))), ...carried } as Record<string, unknown>;
  };
  return { p, other, chosen, another: otherChain(p, other), signer, sends, ...merchant(p, other, more) };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const name of WARNED) delete (globalThis as { [key: symbol]: unknown })[Symbol.for(`kya-os.warned.${name}`)];
});

describe('the delegation buildCardProof states', () => {
  it('is the digest of the leaf of the chain the request carries, with no other input', async () => {
    const { chosen, sends } = await scene();
    const proof = (await sends(chosen))[KYA_OS_CARD_PROOF_META_KEY] as CardProofMeta;
    expect(statedIn(proof)).toBe(await digestOf(chosen[1]));
    expect(Object.keys(proof)).not.toContain(DELEGATION_HEADER_PARAMETER);
  });

  it('is "none" for a request that carries no chain', async () => {
    const { signer } = await scene();
    const proof = (await buildCardProof(REQUEST, signer, context()))[KYA_OS_CARD_PROOF_META_KEY];
    expect(statedIn(proof)).toBe('none');
    expect(decodeProtectedHeader(proof.jws.replace('..', '.e30.'))).toEqual({ alg: 'EdDSA', kid: signer.kid, [DELEGATION_HEADER_PARAMETER]: 'none' });
  });

  it('is the credential passed as `delegation`, whatever the request carries', async () => {
    const { chosen, another, signer, sends } = await scene();
    const digest = await digestOf(chosen[1]);
    const bare = (await buildCardProof(REQUEST, signer, context({ delegation: chosen[1] })))[KYA_OS_CARD_PROOF_META_KEY];
    expect(statedIn(bare)).toBe(digest);
    expect(statedIn((await sends(another, { delegation: chosen[1] }))[KYA_OS_CARD_PROOF_META_KEY] as CardProofMeta)).toBe(digest);
    expect(statedIn((await sends(another, { delegation: 'none' }))[KYA_OS_CARD_PROOF_META_KEY] as CardProofMeta)).toBe('none');
  });

  it('throws for a `delegation` with no signed form, and is left out for a carried chain that has none', async () => {
    const { signer, sends } = await scene();
    await expect(buildCardProof(REQUEST, signer, context({ delegation: { not: 'a credential' } }))).rejects.toThrow(NoSignedFormError);
    for (const chain of [[{ not: 'a credential' }], [], 'chain'] as unknown as DelegationChain[]) {
      const proof = (await sends(chain))[KYA_OS_CARD_PROOF_META_KEY] as CardProofMeta;
      expect(statedIn(proof)).toBeUndefined();
    }
  });

  it('is written by an ES256 signer too, and never in place of the signer\'s own alg and kid', async () => {
    const { chosen } = await scene();
    const { privateKey } = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const privateJwk = (await crypto.subtle.exportKey('jwk', privateKey)) as unknown as P256PrivateJwk;
    const es256 = await es256SignerFromJwk({ did: 'did:web:agent.example', kid: 'did:web:agent.example#key-1', privateJwk });
    const proof = (await buildCardProof(REQUEST, es256, context({ delegation: chosen[1] })))[KYA_OS_CARD_PROOF_META_KEY];
    expect(statedIn(proof)).toBe(await digestOf(chosen[1]));

    const jws = await es256.sign(new Uint8Array([1]), { alg: 'none', kid: 'did:web:other.example#key-9', extra: 'kept' });
    expect(decodeProtectedHeader(jws.replace('..', '.e30.'))).toEqual({ alg: 'ES256', kid: 'did:web:agent.example#key-1', extra: 'kept' });
  });

  it('warns once when a signer of the caller\'s own writes no header parameter, and throws when the statement was asked for', async () => {
    const { chosen, signer } = await scene();
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const older: ProofSigner = { did: signer.did, kid: signer.kid, sign: (payload) => signer.sign(payload) };

    const first = (await buildCardProof(REQUEST, older, context()))[KYA_OS_CARD_PROOF_META_KEY];
    await buildCardProof(REQUEST, older, context());
    expect(statedIn(first)).toBeUndefined();
    expect(warn.mock.calls.filter(([line]) => String(line).includes('did not write the protected header parameters'))).toHaveLength(1);
    await expect(buildCardProof(REQUEST, older, context({ delegation: chosen[1] }))).rejects.toThrow(/does not state its delegation/);
    // A signer whose JWS has no header to read wrote no statement either.
    const headless: ProofSigner = { did: signer.did, kid: signer.kid, sign: async () => '!..c2ln' };
    await expect(buildCardProof(REQUEST, headless, context({ delegation: chosen[1] }))).rejects.toThrow(/does not state its delegation/);
  });
});

describe('the statement verifyCardProof reads', () => {
  const verifyDeps = (p: ChainParties) => ({
    resolveKey: () => ({ ...p.subAgent.publicJwk, kid: p.subAgent.method }),
    resolveDidKeys: () => [p.subAgent.publicJwk],
    expectedAudience: RESOURCE,
    consumeNonceIfFresh: new InMemoryNonceCache().consume,
  });
  /** A proof of the sub-agent's whose protected header states `value` as given, or nothing for `undefined`. */
  const stating = async (p: ChainParties, value: string | undefined): Promise<CardProofMeta> => {
    const signer = await signerOf(p.subAgent);
    const writing: ProofSigner = { ...signer, sign: (payload) => signer.sign(payload, value === undefined ? {} : { [DELEGATION_HEADER_PARAMETER]: value }) };
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    return (await buildCardProof(REQUEST, writing, context()))[KYA_OS_CARD_PROOF_META_KEY];
  };
  const withHeader = (proof: CardProofMeta, changes: Record<string, unknown>): CardProofMeta => {
    const [header, , signature] = proof.jws.split('.') as [string, string, string];
    const read = JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<string, unknown>;
    return { ...proof, jws: `${Buffer.from(JSON.stringify({ ...read, ...changes })).toString('base64url')}..${signature}` };
  };

  it('is the digest, "none", or nothing, from the header the signature verified over', async () => {
    const p = parties();
    const digest = `sha256:${'ab'.repeat(32)}`;
    const cases: [string | undefined, StatedDelegation][] = [
      [digest, { kind: 'credential', digest }],
      ['none', { kind: 'none' }],
      [undefined, { kind: 'absent' }],
    ];
    for (const [value, statedDelegation] of cases) {
      expect(await verifyCardProof(await stating(p, value), REQUEST, verifyDeps(p))).toMatchObject({ ok: true, statedDelegation });
    }
  });

  it('refuses a proof whose statement is neither a digest nor "none"', async () => {
    const p = parties();
    for (const value of ['sha256:abc', 'NONE', '']) {
      const result = await verifyCardProof(await stating(p, value), REQUEST, verifyDeps(p));
      expect(result).toMatchObject({ ok: false, reasons: ['delegation_statement_malformed'] });
      expect(result.statedDelegation).toBeUndefined();
    }
  });

  it('refuses a proof whose statement was changed or removed without the key', async () => {
    const p = parties();
    const proof = await stating(p, `sha256:${'ab'.repeat(32)}`);
    for (const changes of [{ [DELEGATION_HEADER_PARAMETER]: `sha256:${'cd'.repeat(32)}` }, { [DELEGATION_HEADER_PARAMETER]: undefined }]) {
      const result = await verifyCardProof(withHeader(proof, changes), REQUEST, verifyDeps(p));
      expect(result).toMatchObject({ ok: false, reasons: ['invalid_signature'] });
      expect(result.statedDelegation).toBeUndefined();
    }
  });
});

describe('requireProof and requireDelegation, for the delegation a proof states', () => {
  it('authorize a call under the chain its proof names, and say the proof named it', async () => {
    const { chosen, sends, arrive, p } = await scene({ requestBinding: 'require' });
    for (const handOver of ['meta', 'statement'] as const) {
      expect(await arrive(await sends(chosen), handOver)).toMatchObject({
        ok: true,
        source: 'carried',
        responsibleParty: p.acme.did,
        delegationNamed: true,
        ancestorsPinned: false,
      });
    }
  });

  it('refuse another chain put in place of the one the proof names, under either mode', async () => {
    for (const requestBinding of ['prefer', 'require'] as const) {
      const { chosen, another, sends, arrive, other } = await scene({ requestBinding });
      const sent = await sends(chosen);
      // The other chain is good on its own: only the proof says the caller did not choose it.
      expect(await arrive(await sends(another))).toMatchObject({ ok: true, responsibleParty: other.did });
      for (const handOver of ['meta', 'statement'] as const) {
        const swapped = { ...(await sends(chosen)), ...toDelegationChainMeta(another) };
        expect(await arrive(swapped, handOver)).toEqual({
          ok: false,
          refusalCode: 'holder_binding_failed',
          reasons: ['Request proof names another delegation than the one presented'],
        });
      }
      expect(await arrive(sent)).toMatchObject({ ok: true });
    }
  });

  it('refuse a leaf issued again under the same id', async () => {
    const { chosen, sends, arrive, p } = await scene();
    const again = hop({
      issuer: p.agent,
      invoker: p.subAgent.did,
      id: 'urn:zcap:agent-leaf',
      parentCapability: 'urn:zcap:acme-root',
      allowedAction: ['orders.place'],
      caveats: [{ type: 'MaxAmount', limit: '400.00', currency: 'USD' }],
      statusIndex: 7,
    });
    expect(again.credentialSubject.id).toBe(chosen[1].credentialSubject.id);
    // The chain it ends is good on its own, by a proof made for it.
    expect(await arrive(await sends([chosen[0], again]))).toMatchObject({ ok: true });
    const reissued = { ...(await sends(chosen)), ...toDelegationChainMeta([chosen[0], again]) };
    expect(await arrive(reissued)).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
  });

  it('authorize the same leaf serialized another way', async () => {
    const { chosen, sends, arrive } = await scene({ requestBinding: 'require' });
    const reversed = (value: unknown): unknown =>
      Array.isArray(value)
        ? value.map(reversed)
        : value !== null && typeof value === 'object'
          ? Object.fromEntries(Object.entries(value).reverse().map(([key, member]) => [key, reversed(member)]))
          : value;
    const copy = reversed(JSON.parse(JSON.stringify(chosen[1]))) as DelegationCredential;
    expect(Object.keys(copy)).not.toEqual(Object.keys(chosen[1]));
    expect(await arrive({ ...(await sends(chosen)), ...toDelegationChainMeta([chosen[0], copy]) })).toMatchObject({ ok: true, delegationNamed: true });
  });

  it('take a proof that states "none" beside a carried chain under prefer, with one warning, and refuse it under require', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const lenient = await scene();
    // A caller that made its proof from the bare request and added the chain afterwards arrives the
    // same way as a chain a party on the path inserted beside a proof that states "none".
    const inserted = async (s: Awaited<ReturnType<typeof scene>>) => ({ ...(await s.sends(undefined)), ...toDelegationChainMeta(s.another) });
    expect(await lenient.arrive(await inserted(lenient))).toMatchObject({ ok: true, delegationNamed: false });
    expect(await lenient.arrive(await inserted(lenient))).toMatchObject({ ok: true, delegationNamed: false });
    expect(warn.mock.calls.filter(([line]) => String(line).includes('states its call presents no delegation'))).toHaveLength(1);

    const strict = await scene({ requestBinding: 'require' });
    expect(await strict.arrive(await inserted(strict))).toEqual({
      ok: false,
      refusalCode: 'holder_binding_failed',
      reasons: ['Request proof states that the call presents no delegation, but one was presented'],
    });
  });

  it('take a proof that states nothing under prefer, with one warning, and refuse it under require', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const unnamed = async (s: Awaited<ReturnType<typeof scene>>) => {
      const older: ProofSigner = { ...s.signer, sign: (payload) => s.signer.sign(payload) };
      return { ...(await buildCardProof(REQUEST, older, context())), ...toDelegationChainMeta(s.chosen) };
    };
    const lenient = await scene();
    expect(await lenient.arrive(await unnamed(lenient))).toMatchObject({ ok: true, delegationNamed: false });
    expect(warn.mock.calls.filter(([line]) => String(line).includes('does not state the delegation its call is made under'))).toHaveLength(1);

    const strict = await scene({ requestBinding: 'require' });
    expect(await strict.arrive(await unnamed(strict))).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
  });

  it('take a call whose proof they were handed nothing of under prefer, with a warning that says so, and refuse it under require', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { chosen, delegationGuard, p } = await scene();
    const bare = { meta: toDelegationChainMeta(chosen), proofDid: p.subAgent.did, action: ACTION };
    expect(await delegationGuard(bare)).toMatchObject({ ok: true, delegationNamed: false });
    expect(warn.mock.calls.filter(([line]) => String(line).includes('without knowing which delegation its request proof states'))).toHaveLength(1);

    const strict = await scene({ requestBinding: 'require' });
    expect(await strict.delegationGuard({ ...bare, meta: toDelegationChainMeta(strict.chosen), proofDid: strict.p.subAgent.did })).toMatchObject({
      ok: false,
      refusalCode: 'holder_binding_failed',
    });
  });

  it('read the statement of no proof but the caller\'s own card proof', async () => {
    const { chosen, another, sends, delegationGuard, p } = await scene({ requestBinding: 'require' });
    const sent = await sends(chosen);
    const proof = sent[KYA_OS_CARD_PROOF_META_KEY] as CardProofMeta;
    const input = (meta: Record<string, unknown>) => ({ meta, proofDid: p.subAgent.did, action: ACTION });
    // A proof of another DID, or the same statement under the session proof's key, is not the proof that verified.
    const ofAnother = { ...toDelegationChainMeta(chosen), [KYA_OS_CARD_PROOF_META_KEY]: { ...proof, did: p.agent.did } };
    const elsewhere = { ...toDelegationChainMeta(chosen), 'org.kya-os/proof': proof, [DELEGATION_HEADER_PARAMETER]: await digestOf(chosen[1]) };
    // Nor is a proof whose JWS has no header to read.
    const headless = { ...toDelegationChainMeta(chosen), [KYA_OS_CARD_PROOF_META_KEY]: { ...proof, jws: '!..c2ln' } };
    for (const meta of [ofAnother, elsewhere, headless]) {
      expect(await delegationGuard(input(meta))).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
    }
    // The statement handed over is the one held, whatever the bag carries.
    const stated: StatedDelegation = { kind: 'credential', digest: await digestOf(another[1]) };
    expect(await delegationGuard({ ...input(sent), statedDelegation: stated })).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
    expect(await delegationGuard({ ...input(sent), statedDelegation: { kind: 'malformed' } })).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
  });

  it('take a leaf with no signed form as no credential a proof names, and report a hash that fails as that failure', async () => {
    const { chosen } = await scene();
    const stated: StatedDelegation = { kind: 'credential', digest: await digestOf(chosen[1]) };
    expect(await requestBindingRefusal(stated, chosen[1], true, 'prefer')).toBeUndefined();
    expect(await requestBindingRefusal(stated, { not: 'a credential' }, true, 'prefer')).toMatchObject({ cause: 'delegation_mismatch' });
    vi.spyOn(globalThis.crypto.subtle, 'digest').mockRejectedValue(new Error('no hash'));
    await expect(requestBindingRefusal(stated, chosen[1], true, 'prefer')).rejects.toThrow('no hash');
  });

  describe('for a chain the merchant resolves by reference', () => {
    const resolving = (chain: () => DelegationChain) => ({ resolveDelegationChain: async () => chain(), requestBinding: 'require' as const });

    it('authorize a call whose proof names the chain resolved, or states "none"', async () => {
      const held: { chain?: DelegationChain } = {};
      const { chosen, sends, arrive } = await scene(resolving(() => held.chain!));
      held.chain = chosen;
      expect(await arrive(await sends(undefined, { delegation: chosen[1] }))).toMatchObject({ ok: true, source: 'resolved', delegationNamed: true });
      expect(await arrive(await sends(undefined))).toMatchObject({ ok: true, source: 'resolved', delegationNamed: false });
    });

    it('refuse a call whose proof names another chain than the one resolved, or states nothing', async () => {
      const held: { chain?: DelegationChain } = {};
      const s = await scene(resolving(() => held.chain!));
      held.chain = s.another;
      expect(await s.arrive(await s.sends(undefined, { delegation: s.chosen[1] }))).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
      vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
      const older: ProofSigner = { ...s.signer, sign: (payload) => s.signer.sign(payload) };
      expect(await s.arrive(await buildCardProof(REQUEST, older, context()))).toMatchObject({ ok: false, refusalCode: 'holder_binding_failed' });
    });
  });

  describe('and the ancestors of the leaf it names', () => {
    /** Acme's root, issued again under the same id with a wider grant, and the leaf under each, stating its parent or not. */
    const reissuedRoot = (p: ChainParties) =>
      hop({
        issuer: p.acme,
        invoker: p.agent.did,
        id: 'urn:zcap:acme-root',
        parentCapability: RESOURCE,
        allowedAction: ['orders.place', 'orders.read', 'orders.refund'],
        caveats: [{ type: 'MaxAmount', limit: '900.00', currency: 'USD' }],
        statusIndex: 3,
      });
    const leafUnder = (p: ChainParties, parentCredentialDigest?: string) =>
      hop({
        issuer: p.agent,
        invoker: p.subAgent.did,
        id: 'urn:zcap:agent-leaf',
        parentCapability: 'urn:zcap:acme-root',
        allowedAction: ['orders.place'],
        caveats: [{ type: 'MaxAmount', limit: '100.00', currency: 'USD' }],
        statusIndex: 7,
        parentCredentialDigest,
      });

    it('refuse an ancestor issued again under the same id, where the leaf states its parent digest', async () => {
      const { chosen, sends, arrive, p } = await scene({ requestBinding: 'require' });
      const pinned: DelegationChain = [chosen[0], leafUnder(p, await digestOf(chosen[0]))];
      expect(await arrive(await sends(pinned))).toMatchObject({ ok: true, delegationNamed: true, ancestorsPinned: true });

      const swapped = { ...(await sends(pinned)), ...toDelegationChainMeta([reissuedRoot(p), pinned[1]!]) };
      expect(await arrive(swapped)).toMatchObject({ ok: false, refusalCode: 'chain_invalid' });
    });

    it('say the ancestors are not pinned where the leaf states no parent digest, and the swap is then not seen', async () => {
      const { chosen, sends, arrive, p } = await scene({ requestBinding: 'require' });
      const swapped = { ...(await sends(chosen)), ...toDelegationChainMeta([reissuedRoot(p), chosen[1]]) };
      expect(await arrive(swapped)).toMatchObject({ ok: true, delegationNamed: true, ancestorsPinned: false });
    });
  });

  it('throw a TypeError for a requestBinding that is neither prefer nor require, when the guard is built', async () => {
    await expect(scene({ requestBinding: 'required' as 'require' })).rejects.toThrow(TypeError);
    await expect(scene({ requestBinding: 'required' as 'require' })).rejects.toThrow(/requestBinding must be "prefer" or "require"/);
  });
});
