/**
 * A request proof that names the delegation it was made for. The proof covers the tool name and the
 * business arguments, and the delegation rides beside it in `_kyaos_delegation`, outside the request
 * hash. So an agent's proof names its delegation by the two members of SPEC §7.8, the presented
 * credential's `delegationRef` and the chain's `delegationChainDigest`, which its signature covers,
 * and holder binding refuses the proof beside any other delegation: a party on the path that holds
 * another delegation of the same subject cannot put it in place of the one the agent chose.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { assertHolderBinding, generateRequestProof, toHolderBindingRequest } from '../holder-binding.js';
import { digestDelegationChain } from '../chain-digest.js';
import { delegationRefOf } from '../delegation-ref.js';
import { ProofVerifier } from '../../proof/verifier.js';
import type { DelegationCredential } from '../../types/protocol.js';
import { nodeCrypto as crypto } from '../../__tests__/utils/node-crypto-provider.js';
import { MemoryNonceCacheProvider, RealClockProvider, RealFetchProvider } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegate, party, type Party } from '../../middleware/__tests__/helpers/delegating-party.js';

const AUDIENCE = 'did:web:server.example.com';
const TOOL = 'payments.send';
const ARGS = { amount: 100, to: 'acct-7' };
const hash = (bytes: Uint8Array): Promise<string> => crypto.hash(bytes);

const verifier = () =>
  new ProofVerifier({
    cryptoProvider: crypto,
    clockProvider: new RealClockProvider(),
    nonceCacheProvider: new MemoryNonceCacheProvider(),
    fetchProvider: new RealFetchProvider(),
    timestampSkewSeconds: 300,
  });

/** The members of SPEC §7.8 that name `chain`, root first, as a proof made for it carries them. */
async function namesOf(chain: DelegationCredential[]) {
  return {
    delegationRef: await delegationRefOf(chain.at(-1), hash),
    delegationChainDigest: (await digestDelegationChain(chain, hash)).chain,
  };
}

/** The delegation a gate read, as holder binding is handed it. */
async function presented(chain: DelegationCredential[]) {
  const named = await namesOf(chain);
  return { delegationRef: named.delegationRef, chainDigest: vi.fn(async () => named.delegationChainDigest) };
}

describe('a request proof that names its delegation', () => {
  let agent: Party;
  let partyOne: DelegationCredential;
  let partyTwo: DelegationCredential;

  beforeAll(async () => {
    const [one, two] = await Promise.all([party(), party()]);
    agent = await party();
    partyOne = await delegate(one, agent.did, { scopes: ['payments:send'] });
    partyTwo = await delegate(two, agent.did, { scopes: ['payments:send'] });
  });

  const proofFor = (delegationChain?: DelegationCredential[]) =>
    generateRequestProof({
      identity: agent,
      crypto,
      toolName: TOOL,
      args: ARGS,
      audience: AUDIENCE,
      ...(delegationChain === undefined ? {} : { delegationChain }),
    });

  const bind = async (proof: Awaited<ReturnType<typeof proofFor>>, delegation?: Awaited<ReturnType<typeof presented>>) =>
    assertHolderBinding({
      proof,
      subjectDid: agent.did,
      request: toHolderBindingRequest(TOOL, ARGS),
      expectedAudience: AUDIENCE,
      proofVerifier: verifier(),
      ...(delegation === undefined ? {} : { delegation }),
    });

  it('is made by generateRequestProof from the chain it is given, and names none without one', async () => {
    expect((await proofFor([partyOne])).meta).toMatchObject(await namesOf([partyOne]));
    const unnamed = (await proofFor()).meta;
    expect([unnamed.delegationRef, unnamed.delegationChainDigest]).toEqual([undefined, undefined]);
    await expect(proofFor([])).rejects.toThrow(TypeError);
  });

  it('names a credential that shows no id by the chain alone', async () => {
    // Neither the credential's `id` nor its delegation's, the two members a credential shows an id by.
    const { id: _id, ...shown } = structuredClone(partyOne);
    delete (shown.credentialSubject.delegation as { id?: string }).id;
    const unnamed = shown as DelegationCredential;
    const meta = (await proofFor([unnamed])).meta;
    expect(meta.delegationRef).toBeUndefined();
    expect(meta.delegationChainDigest).toBe((await digestDelegationChain([unnamed], hash)).chain);
  });

  it('binds beside the delegation it names', async () => {
    const delegation = await presented([partyOne]);
    expect(await bind(await proofFor([partyOne]), delegation)).toEqual({ status: 'bound' });
  });

  it('does not bind beside another delegation of the same subject', async () => {
    const result = await bind(await proofFor([partyOne]), await presented([partyTwo]));
    expect(result).toEqual({
      status: 'unbound',
      errorCode: 'holder_binding_failed',
      reason: 'Request proof names another delegation than the one presented',
      cause: 'delegation_mismatch',
    });
  });

  it('does not bind beside the delegation it names by reference, evaluated as another chain', async () => {
    // The same credential, digested as the last of a chain the gate resolved for it.
    const delegation = await presented([partyOne]);
    delegation.chainDigest.mockResolvedValue((await digestDelegationChain([partyTwo, partyOne], hash)).chain);
    expect(await bind(await proofFor([partyOne]), delegation)).toMatchObject({ status: 'unbound', cause: 'delegation_mismatch' });
  });

  it('that names no delegation binds beside any, and the chain is not digested for it', async () => {
    const delegation = await presented([partyTwo]);
    expect(await bind(await proofFor(), delegation)).toEqual({ status: 'bound' });
    expect(delegation.chainDigest).not.toHaveBeenCalled();
  });

  it('does not bind when the chain it names cannot be digested to compare', async () => {
    const delegation = await presented([partyOne]);
    delegation.chainDigest.mockRejectedValue(new Error('hash provider down'));
    expect(await bind(await proofFor([partyOne]), delegation)).toEqual({
      status: 'unbound',
      errorCode: 'holder_binding_failed',
      reason: 'The delegation the request proof names could not be compared with the one presented',
      cause: 'delegation_unchecked',
    });
  });
});
