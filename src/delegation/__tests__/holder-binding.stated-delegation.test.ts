/**
 * What `generateRequestProof` states of the delegation a call presents (SPEC §7.8). The proof covers
 * the tool name and the business arguments, and the delegation rides beside it in
 * `_kyaos_delegation`, outside the request hash. So the proof states, in its JWS protected header,
 * the digest of the credential the call presents, or `none`: with no input beyond the arguments the
 * call sends, since a client that had to ask for the protection would mostly go without it.
 */
import { decodeProtectedHeader } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { delegationCredentialDigest } from '../chain-digest.js';
import { assertHolderBinding, generateRequestProof, toHolderBindingRequest, type GenerateRequestProofInput } from '../holder-binding.js';
import { NoSignedFormError } from '../signed-form.js';
import { DELEGATION_HEADER_PARAMETER } from '../stated-delegation.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { DelegationCredential, DetachedProof } from '../../types/protocol.js';
import { nodeCrypto as crypto } from '../../__tests__/utils/node-crypto-provider.js';
import { MemoryNonceCacheProvider, RealClockProvider, RealFetchProvider } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegate, party, type Party } from '../../middleware/__tests__/helpers/delegating-party.js';
import { jwtParty } from '../../middleware/__tests__/helpers/delegation-chains.js';

const AUDIENCE = 'did:web:server.example.com';
const TOOL = 'payments.send';
const ARGS = { amount: 100, to: 'acct-7' };
const hash = (bytes: Uint8Array): Promise<string> => crypto.hash(bytes);

/** What the proof's protected header states of its delegation; `undefined` when it states nothing. */
const stated = (proof: DetachedProof): unknown => decodeProtectedHeader(proof.jws)[DELEGATION_HEADER_PARAMETER];

describe('the delegation generateRequestProof states', () => {
  let agent: Party;
  let credential: DelegationCredential;
  let another: DelegationCredential;

  beforeAll(async () => {
    const [one, two] = await Promise.all([party(), party()]);
    agent = await party();
    credential = await delegate(one, agent.did, { scopes: ['payments:send'] });
    another = await delegate(two, agent.did, { scopes: ['payments:send'] });
  });

  const proofFor = (args: Record<string, unknown>, more: Partial<GenerateRequestProofInput> = {}) =>
    generateRequestProof({ identity: agent, crypto, toolName: TOOL, args, audience: AUDIENCE, ...more });

  it('is the digest of the credential in the arguments, with no other input', async () => {
    const proof = await proofFor({ ...ARGS, _kyaos_delegation: credential });
    expect(stated(proof)).toBe(await delegationCredentialDigest(credential, hash));
  });

  it('is the digest of a VC-JWT in the arguments, as the string that is sent', async () => {
    const jwt = await (await jwtParty()).issue({ delegationId: 'del-jwt', subject: agent.did });
    const proof = await proofFor({ ...ARGS, _kyaos_delegation: jwt });
    expect(stated(proof)).toBe(await delegationCredentialDigest(jwt, hash));
  });

  it('is "none" when the arguments hold no delegation, or hold it as null', async () => {
    expect(stated(await proofFor(ARGS))).toBe('none');
    expect(stated(await proofFor({ ...ARGS, _kyaos_delegation: null }))).toBe('none');
  });

  it('is the credential passed as `delegation`, whatever the arguments hold', async () => {
    const digest = await delegationCredentialDigest(credential, hash);
    expect(stated(await proofFor(ARGS, { delegation: credential }))).toBe(digest);
    expect(stated(await proofFor({ ...ARGS, _kyaos_delegation: another }, { delegation: credential }))).toBe(digest);
    expect(stated(await proofFor({ ...ARGS, _kyaos_delegation: another }, { delegation: 'none' }))).toBe('none');
  });

  it('is left out for a delegation in the arguments that has no signed form, which the server refuses', async () => {
    for (const unsigned of [{ not: 'a credential' }, 'not-a-jwt', 7]) {
      const proof = await proofFor({ ...ARGS, _kyaos_delegation: unsigned });
      expect(Object.hasOwn(decodeProtectedHeader(proof.jws), DELEGATION_HEADER_PARAMETER)).toBe(false);
    }
  });

  it('throws for a `delegation` that has no signed form', async () => {
    await expect(proofFor(ARGS, { delegation: { not: 'a credential' } })).rejects.toThrow(NoSignedFormError);
  });

  it('is stated in the protected header alone: the meta and the signed payload are as before', async () => {
    const proof = await proofFor({ ...ARGS, _kyaos_delegation: credential });
    expect(Object.keys(proof.meta).sort()).toEqual(['audience', 'did', 'kid', 'nonce', 'requestHash', 'sessionId', 'ts']);
    expect(decodeProtectedHeader(proof.jws)).toMatchObject({ alg: 'EdDSA', kid: agent.kid });
    expect(Object.keys(decodeProtectedHeader(proof.jws))).toEqual(['alg', 'kid', DELEGATION_HEADER_PARAMETER]);
  });

  it('leaves the proof one that assertHolderBinding, which reads no statement, still binds', async () => {
    const proof = await proofFor({ ...ARGS, _kyaos_delegation: credential });
    const bound = await assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request: toHolderBindingRequest(TOOL, ARGS),
      expectedAudience: AUDIENCE,
      proofVerifier: new ProofVerifier({
        cryptoProvider: crypto,
        clockProvider: new RealClockProvider(),
        nonceCacheProvider: new MemoryNonceCacheProvider(),
        fetchProvider: new RealFetchProvider(),
        timestampSkewSeconds: 300,
      }),
    });
    expect(bound).toEqual({ status: 'bound' });
  });

  it('takes no chain: a `delegationChain` passed by plain JavaScript names nothing', async () => {
    const proof = await proofFor(ARGS, { delegationChain: [credential] } as Partial<GenerateRequestProofInput>);
    expect([proof.meta.delegationRef, proof.meta.delegationChainDigest]).toEqual([undefined, undefined]);
    expect(stated(proof)).toBe('none');
  });
});
