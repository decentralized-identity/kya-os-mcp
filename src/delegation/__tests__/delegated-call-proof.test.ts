/**
 * `verifyDelegatedCallProof`: a holder's request proof, held to the delegation its call presents.
 * An agent holds two delegations for one scope, from two Responsible Parties. A party on the path
 * that has seen both holds no key: it can only move what it has seen. Each case here is one such
 * move, or one way a holder's own proof reaches a verifier.
 */
import { decodeProtectedHeader } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { delegationCredentialDigest, digestDelegationChain } from '../chain-digest.js';
import { verifyDelegatedCallProof, type VerifyDelegatedCallProofInput } from '../delegated-call-proof.js';
import { delegationRefOf } from '../delegation-ref.js';
import { generateRequestProof, toHolderBindingRequest } from '../holder-binding.js';
import { DELEGATION_HEADER_PARAMETER } from '../stated-delegation.js';
import type { ReceivedCredential } from '../chain-digest.js';
import type { DelegationCredential, DetachedProof } from '../../types/protocol.js';
import { nodeCrypto as crypto } from '../../__tests__/utils/node-crypto-provider.js';
import { delegate, party, reissued, type Party } from '../../middleware/__tests__/helpers/delegating-party.js';
import { jwtParty } from '../../middleware/__tests__/helpers/delegation-chains.js';
import { AUDIENCE, ARGS, TOOL, hash, proofStating, proofVerifier, withHeader } from './helpers/request-proofs.js';

describe('verifyDelegatedCallProof', () => {
  let agent: Party;
  let issuer: Party;
  let chosen: DelegationCredential;
  let other: DelegationCredential;

  beforeAll(async () => {
    const two = await party();
    [issuer, agent] = await Promise.all([party(), party()]);
    chosen = await delegate(issuer, agent.did, { scopes: ['payments:send'] });
    other = await delegate(two, agent.did, { scopes: ['payments:send'] });
  });

  /** The proof the default generator makes for a call that sends `delegation` in its arguments. */
  const proofBeside = (delegation?: unknown) =>
    generateRequestProof({
      identity: agent,
      crypto,
      toolName: TOOL,
      args: delegation === undefined ? ARGS : { ...ARGS, _kyaos_delegation: delegation },
      audience: AUDIENCE,
    });

  const verify = (
    proof: DetachedProof,
    presented: ReceivedCredential | null,
    more: Partial<VerifyDelegatedCallProofInput> = {},
  ) =>
    verifyDelegatedCallProof({
      proof,
      subjectDid: agent.did,
      request: toHolderBindingRequest(TOOL, ARGS),
      expectedAudience: AUDIENCE,
      proofVerifier: proofVerifier(),
      presented,
      hash,
      ...more,
    });

  describe('beside the credential the call presents', () => {
    it('binds a proof that names it, under either mode', async () => {
      const digest = await delegationCredentialDigest(chosen, hash);
      for (const mode of ['prefer', 'require'] as const) {
        expect(await verify(await proofBeside(chosen), chosen, { mode })).toEqual({
          status: 'bound',
          named: true,
          ancestorsPinned: true,
          claims: { statement: { kind: 'credential', digest } },
        });
      }
    });

    it('does not bind a proof made for another delegation of the same subject: a swap', async () => {
      for (const mode of ['prefer', 'require'] as const) {
        expect(await verify(await proofBeside(chosen), other, { mode })).toEqual({
          status: 'unbound',
          errorCode: 'holder_binding_failed',
          reason: 'Request proof names another delegation than the one presented',
          cause: 'delegation_mismatch',
        });
      }
    });

    it('does not bind beside a credential issued again under the same ids', async () => {
      const again = await reissued(issuer, chosen, { scopes: ['payments:send', 'payments:refund'] });
      expect([again.id, again.credentialSubject.delegation.id]).toEqual([chosen.id, chosen.credentialSubject.delegation.id]);
      expect(await delegationRefOf(again, hash)).toBe(await delegationRefOf(chosen, hash));
      expect(await verify(await proofBeside(chosen), again)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
    });

    it('binds beside the same credential serialized another way', async () => {
      const reversed = (value: unknown): unknown =>
        Array.isArray(value)
          ? value.map(reversed)
          : value !== null && typeof value === 'object'
            ? Object.fromEntries(Object.entries(value).reverse().map(([key, member]) => [key, reversed(member)]))
            : value;
      const copy = reversed(JSON.parse(JSON.stringify(chosen))) as DelegationCredential;
      expect(Object.keys(copy)).not.toEqual(Object.keys(chosen));
      expect(await verify(await proofBeside(chosen), copy, { mode: 'require' })).toMatchObject({ status: 'bound', named: true });
    });

    it('does not bind a proof of a VC-JWT beside that credential decoded to an object', async () => {
      const jwt = await (await jwtParty()).issue({ delegationId: 'del-jwt', subject: agent.did });
      const proof = () => proofBeside(jwt);
      expect(await verify(await proof(), jwt, { mode: 'require' })).toMatchObject({ status: 'bound', named: true });

      const [, payload, signature] = jwt.split('.') as [string, string, string];
      const vc = (JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { vc: object }).vc;
      // The object alone has no signature, so no signed form; with the envelope's signature for a
      // proof it has one, of another credential than the string.
      expect(await verify(await proof(), vc)).toMatchObject({ status: 'unbound', cause: 'delegation_unchecked' });
      const dressed = { ...vc, proof: { type: 'Ed25519Signature2020', proofValue: signature } };
      expect(await verify(await proof(), dressed)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
    });

    it('takes a proof that states "none" under prefer, unnamed, and refuses it under require', async () => {
      // What a client states that signed its business arguments and attached the delegation afterwards,
      // and what a party on the path leaves it with when it inserts a delegation of its own choosing.
      const proof = () => proofBeside();
      expect(decodeProtectedHeader((await proof()).jws)[DELEGATION_HEADER_PARAMETER]).toBe('none');
      expect(await verify(await proof(), chosen)).toMatchObject({ status: 'bound', named: false, claims: { statement: { kind: 'none' } } });
      expect(await verify(await proof(), chosen, { mode: 'require' })).toEqual({
        status: 'unbound',
        errorCode: 'holder_binding_failed',
        reason: 'Request proof states that the call presents no delegation, but one was presented',
        cause: 'delegation_stated_none',
      });
    });

    it('takes a proof that states nothing under prefer, unnamed, and refuses it under require', async () => {
      const unnamed = () => proofStating(agent, undefined);
      expect(decodeProtectedHeader((await unnamed()).jws)).toEqual({ alg: 'EdDSA', kid: agent.kid });
      expect(await verify(await unnamed(), chosen)).toEqual({
        status: 'bound',
        named: false,
        ancestorsPinned: true,
        claims: { statement: { kind: 'absent' } },
      });
      expect(await verify(await unnamed(), chosen, { mode: 'prefer' })).toMatchObject({ status: 'bound', named: false });
      expect(await verify(await unnamed(), chosen, { mode: 'require' })).toMatchObject({ status: 'unbound', cause: 'delegation_unnamed' });
    });

    it('refuses a statement that is neither a digest nor "none", under either mode', async () => {
      for (const value of ['sha256:abc', 'NONE', '']) {
        for (const mode of ['prefer', 'require'] as const) {
          expect(await verify(await proofStating(agent, value), chosen, { mode })).toMatchObject({
            status: 'unbound',
            cause: 'delegation_statement_malformed',
          });
        }
      }
    });
  });

  describe('and what a party without the key can do to the statement', () => {
    it('cannot change it: the header is part of what the holder signed', async () => {
      const proof = await proofBeside(chosen);
      const swapped = withHeader(proof, { [DELEGATION_HEADER_PARAMETER]: await delegationCredentialDigest(other, hash) });
      expect(await verify(swapped, other)).toMatchObject({ status: 'unbound', cause: 'INVALID_JWS_SIGNATURE' });
    });

    it('cannot remove it, to pass the proof off as one that names nothing', async () => {
      const stripped = withHeader(await proofBeside(chosen), { [DELEGATION_HEADER_PARAMETER]: undefined });
      expect(decodeProtectedHeader(stripped.jws)).toEqual({ alg: 'EdDSA', kid: agent.kid });
      expect(await verify(stripped, other)).toMatchObject({ status: 'unbound', cause: 'INVALID_JWS_SIGNATURE' });
    });

    it('cannot state it anywhere else: only the protected header that verified is read', async () => {
      const digest = await delegationCredentialDigest(other, hash);
      const unnamed = await proofStating(agent, undefined);
      const elsewhere = {
        ...unnamed,
        [DELEGATION_HEADER_PARAMETER]: digest,
        header: { [DELEGATION_HEADER_PARAMETER]: digest },
        meta: { ...unnamed.meta, [DELEGATION_HEADER_PARAMETER]: digest },
      } as DetachedProof;
      expect(await verify(elsewhere, other, { mode: 'require' })).toMatchObject({ status: 'unbound', cause: 'delegation_unnamed' });
    });

    it('cannot have one JWS verified and another read: the proof is read once', async () => {
      const [forChosen, forOther] = await Promise.all([proofBeside(chosen), proofBeside(other)]);
      let reads = 0;
      const shifting = {
        meta: forOther.meta,
        // The first reading is the proof made for `other`; every later one names `chosen`.
        get jws() {
          reads += 1;
          return reads === 1 ? forOther.jws : forChosen.jws;
        },
      } as DetachedProof;
      expect(await verify(shifting, chosen)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
      expect(reads).toBe(1);
    });
  });

  describe('and the ancestors of a re-delegation', () => {
    let subAgent: Party;
    let root: DelegationCredential;

    beforeAll(async () => {
      subAgent = await party();
      root = await delegate(issuer, agent.did, { scopes: ['payments:send'] });
    });

    const leafProof = (leaf: DelegationCredential) =>
      generateRequestProof({
        identity: subAgent,
        crypto,
        toolName: TOOL,
        args: { ...ARGS, _kyaos_delegation: leaf },
        audience: AUDIENCE,
      });
    const verifyLeaf = (proof: DetachedProof, leaf: DelegationCredential, ancestors: DelegationCredential[]) =>
      verify(proof, leaf, { subjectDid: subAgent.did, ancestors, mode: 'require' });

    it('binds a proof whose holder never saw them, and says they are named by id alone', async () => {
      const leaf = await delegate(agent, subAgent.did, { parent: root, scopes: ['payments:send'] });
      expect(await verifyLeaf(await leafProof(leaf), leaf, [root])).toMatchObject({
        status: 'bound',
        named: true,
        ancestorsPinned: false,
      });
    });

    it('says they are pinned when each hop states its parent digest', async () => {
      const leaf = await delegate(agent, subAgent.did, { parent: root, commits: true, scopes: ['payments:send'] });
      expect(leaf.credentialSubject.delegation.parentCredentialDigest).toBe(await delegationCredentialDigest(root, hash));
      expect(await verifyLeaf(await leafProof(leaf), leaf, [root])).toMatchObject({
        status: 'bound',
        named: true,
        ancestorsPinned: true,
      });
    });

    it('says they are not pinned when a parent is named and none is given', async () => {
      const leaf = await delegate(agent, subAgent.did, { parent: root, commits: true, scopes: ['payments:send'] });
      expect(await verifyLeaf(await leafProof(leaf), leaf, [])).toMatchObject({ status: 'bound', ancestorsPinned: false });
    });

    it('does not bind beside an ancestor swapped under a stated parent digest', async () => {
      const leaf = await delegate(agent, subAgent.did, { parent: root, commits: true, scopes: ['payments:send'] });
      const again = await reissued(issuer, root, { scopes: ['payments:send', 'payments:refund'] });
      expect(await verifyLeaf(await leafProof(leaf), leaf, [again])).toEqual({
        status: 'unbound',
        errorCode: 'holder_binding_failed',
        reason: "A credential of the delegation chain states a parent digest that is not its parent's",
        cause: 'ancestor_mismatch',
      });
    });
  });

  describe('and the payload members a proof may also state (SPEC §7.8)', () => {
    it('holds a proof to the delegationRef and delegationChainDigest it signs', async () => {
      const named = async (credential: DelegationCredential) => ({
        delegationRef: await delegationRefOf(credential, hash),
        delegationChainDigest: (await digestDelegationChain([credential], hash)).chain,
      });
      const stating = async (payload: Record<string, string | undefined>) =>
        proofStating(agent, await delegationCredentialDigest(chosen, hash), payload);

      expect(await verify(await stating(await named(chosen)), chosen)).toMatchObject({ status: 'bound', named: true });
      for (const member of ['delegationRef', 'delegationChainDigest'] as const) {
        const proof = await stating({ [member]: (await named(other))[member] });
        expect(await verify(proof, chosen)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
      }
    });
  });

  describe('beside no credential', () => {
    it('binds a proof that names one, and gives the name back to select retained authority by', async () => {
      const digest = await delegationCredentialDigest(chosen, hash);
      expect(await verify(await proofStating(agent, digest), null, { mode: 'require' })).toEqual({
        status: 'bound',
        named: true,
        claims: { statement: { kind: 'credential', digest } },
      });
    });

    it('binds a proof that states "none"', async () => {
      expect(await verify(await proofBeside(), null, { mode: 'require' })).toEqual({
        status: 'bound',
        named: true,
        claims: { statement: { kind: 'none' } },
      });
    });

    it('takes a proof that states nothing under prefer, and refuses it under require', async () => {
      expect(await verify(await proofStating(agent, undefined), null)).toMatchObject({ status: 'bound', named: false });
      expect(await verify(await proofStating(agent, undefined), null, { mode: 'require' })).toMatchObject({
        status: 'unbound',
        cause: 'delegation_unnamed',
      });
    });
  });

  it('throws a TypeError for a mode that is neither prefer nor require', async () => {
    const proof = await proofBeside(chosen);
    await expect(verify(proof, chosen, { mode: 'required' as 'require' })).rejects.toThrow(TypeError);
  });

  it('verifies nothing of a subject that is not a did:key, and so reads nothing its proof states', async () => {
    const result = await verify(await proofBeside(chosen), other, { subjectDid: 'did:web:agent.example.com', mode: 'require' });
    expect(result.status).toBe('not_applicable');
    expect(result.claims).toBeUndefined();
  });
});
