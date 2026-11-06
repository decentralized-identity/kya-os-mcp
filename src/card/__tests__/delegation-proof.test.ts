import { describe, it, expect } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { DIDResolver } from '../../delegation/vc-verifier.types.js';
import { createDelegationProofVerifier, signDelegationCredential } from '../delegation-proof.js';
import { ed25519SignerFromJwk } from '../proof/signer.js';
import type { ProofSigner } from '../proof/types.js';
import {
  hop,
  identity,
  parties,
  RESOURCE,
  signEddsaJcs2022,
  twoHopChain,
  type TestIdentity,
} from './signed-chain-helpers.js';

const verify = (credential: unknown, didResolver: DIDResolver = createDidKeyResolver()) =>
  createDelegationProofVerifier({ didResolver })(credential as Record<string, unknown>);

describe('createDelegationProofVerifier (eddsa-jcs-2022 hops)', () => {
  it('accepts every hop of a chain signed by each hop issuer', async () => {
    const [root, leaf] = twoHopChain(parties());
    expect(await verify(root)).toBe(true);
    expect(await verify(leaf)).toBe(true);
  });

  it('rejects a hop whose capability was changed after signing', async () => {
    const [root] = twoHopChain(parties());
    const subject = root.credentialSubject;
    const widened = { ...root, credentialSubject: { ...subject, allowedAction: ['orders.place', 'orders.refund'] } };
    expect(await verify(widened)).toBe(false);
  });

  it('rejects a hop signed by a key that is not its issuer', async () => {
    const p = parties();
    const forged = hop({
      issuer: p.agent,
      signer: identity(),
      invoker: p.subAgent.did,
      id: 'urn:zcap:forged',
      parentCapability: RESOURCE,
      allowedAction: ['orders.place'],
    });
    expect(await verify(forged)).toBe(false);
  });

  it('rejects a hop without a proof', async () => {
    const [root] = twoHopChain(parties());
    const unsigned: Record<string, unknown> = { ...root };
    delete unsigned.proof;
    expect(await verify(unsigned)).toBe(false);
  });

  it('reads the proof under assertionMethod, the purpose the profile uses today', async () => {
    const p = parties();
    const { proof: _proof, ...unsigned } = twoHopChain(p)[0];
    const otherPurpose = signEddsaJcs2022(unsigned, p.acme, { proofPurpose: 'capabilityDelegation' });
    expect(await verify(otherPurpose)).toBe(false);
  });

  it('returns false, not a throw, when the issuer DID cannot be resolved', async () => {
    const [root] = twoHopChain(parties());
    const throwing: DIDResolver = {
      resolve: async () => {
        throw new Error('resolver down');
      },
    };
    expect(await verify(root, throwing)).toBe(false);
  });
});

describe('signDelegationCredential', () => {
  const signerFor = (id: TestIdentity, kid = id.method): Promise<ProofSigner> =>
    ed25519SignerFromJwk({ did: id.did, kid, privateJwk: id.privateJwk });
  const unsigned = (signed: Record<string, unknown>) => {
    const copy = { ...signed };
    delete copy.proof;
    return copy as Parameters<typeof signDelegationCredential>[0];
  };
  const created = '2026-11-01T00:00:00Z';

  it('writes the proof the independent signer writes, and the verifier accepts it', async () => {
    const p = parties();
    const [root, leaf] = twoHopChain(p);
    const signedRoot = await signDelegationCredential(unsigned(root), await signerFor(p.acme), { created });
    const signedLeaf = await signDelegationCredential(unsigned(leaf), await signerFor(p.agent), { created });
    expect(signedRoot).toEqual(root);
    expect(signedLeaf).toEqual(leaf);
    expect(await verify(signedRoot)).toBe(true);
    expect(await verify(signedLeaf)).toBe(true);
  });

  it('stamps created with the current time by default', async () => {
    const p = parties();
    const signed = await signDelegationCredential(unsigned(twoHopChain(p)[0]), await signerFor(p.acme));
    expect(Date.parse(String(signed.proof?.created))).toBeGreaterThan(Date.parse(created));
    expect(await verify(signed)).toBe(true);
  });

  it("refuses to sign as someone other than the hop's issuer", async () => {
    const p = parties();
    await expect(signDelegationCredential(unsigned(twoHopChain(p)[0]), await signerFor(p.agent))).rejects.toThrow(
      /is not a verification method of the issuer/,
    );
  });

  it('refuses a signer that cannot produce a raw Ed25519 signature', async () => {
    const p = parties();
    const base = await signerFor(p.acme);
    const credential = unsigned(twoHopChain(p)[0]);
    await expect(signDelegationCredential(credential, { ...base, alg: 'ES256' })).rejects.toThrow(/Ed25519 signer, got ES256/);
    await expect(signDelegationCredential(credential, { ...base, signRaw: undefined })).rejects.toThrow(/signRaw/);
  });

  it('refuses a credential that is not a DelegationCredential, or one already signed', async () => {
    const p = parties();
    const [root] = twoHopChain(p);
    const notAHop = { ...unsigned(root), type: ['VerifiableCredential'] };
    await expect(signDelegationCredential(notAHop, await signerFor(p.acme))).rejects.toThrow(/^not a DelegationCredential at type/);
    await expect(signDelegationCredential(root, await signerFor(p.acme))).rejects.toThrow(/already carries a proof/);
  });
});
