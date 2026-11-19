/**
 * A hop's commitment to its parent (SPEC.md §6.10): `credentialSubject.parentCredentialDigest`, the
 * digest §7.8 gives the parent credential. A hop is otherwise tied to its parent by two names alone,
 * the parent's delegate and the parent's capability id, so a parent issued again under the id of one
 * that was revoked would carry every hop signed under the first. The issuing helper writes the
 * digest when it is handed the parent; the verifiers check it whenever a hop states it, refuse a
 * mismatch, and accept a hop that states none, as before.
 */

import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { delegationCredentialDigest } from '../../delegation/chain-digest.js';
import { createDelegationProofVerifier, signDelegationCredential, type DelegationProofVerifier } from '../delegation-proof.js';
import { evaluateDelegationChain, validateDelegationChain, type DelegationChain, type DelegationCredential } from '../delegation.js';
import { verifyRequestDelegation, toDelegationChainMeta } from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { ed25519SignerFromJwk } from '../proof/signer.js';
import { withWarnings } from '../../__tests__/utils/logged-lines.js';
import {
  NOW_MS,
  RESOURCE,
  hop,
  parties,
  serve,
  signEddsaJcs2022,
  statusList,
  type ChainParties,
  type HopOptions,
  type TestIdentity,
} from './signed-chain-helpers.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

const didResolver = createDidKeyResolver();
const verifyHopProof = createDelegationProofVerifier({ didResolver });

/** SHA-256 by node's own hash, apart from the one the library binds. */
const sha256 = async (bytes: Uint8Array): Promise<string> => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digestOf = (credential: object): Promise<string> => delegationCredentialDigest(credential, sha256);

const GRANT_ID = 'urn:zcap:acme:orders:agent';
const ONWARD_ID = 'urn:zcap:acme:orders:agent:sub';

const grant = (p: ChainParties, statusIndex: number, extra: Partial<HopOptions> = {}): DelegationCredential =>
  hop({ issuer: p.acme, invoker: p.agent.did, id: GRANT_ID, parentCapability: RESOURCE, allowedAction: ['orders.place'], statusIndex, ...extra });
const onward = (p: ChainParties, parentCredentialDigest?: unknown): DelegationCredential =>
  hop({ issuer: p.agent, invoker: p.subAgent.did, id: ONWARD_ID, parentCapability: GRANT_ID, allowedAction: ['orders.place'], parentCredentialDigest });

/** A credential without its proof, as an issuer holds it before signing. */
function unsigned(credential: Record<string, unknown>): Parameters<typeof signDelegationCredential>[0] {
  const copy = { ...credential };
  delete copy.proof;
  return copy as Parameters<typeof signDelegationCredential>[0];
}

const signerFor = (id: TestIdentity) => ed25519SignerFromJwk({ did: id.did, kid: id.method, privateJwk: id.privateJwk });

/** What each verifier says of a chain: whether it accepts it, the code it refuses with, and why. */
interface Said {
  ok: boolean;
  code?: string;
  reasons: string[];
}

type Path = (p: ChainParties, chain: DelegationChain, proofs?: DelegationProofVerifier) => Promise<Said>;

const checker = (p: ChainParties) =>
  createRevocationChecker({ fetch: serve(statusList(p.acme, [3])), now: () => NOW_MS, verifyStatusList: createStatusListProofVerifier({ didResolver }) });

const PATHS: [string, Path][] = [
  [
    'verifyRequestDelegation',
    async (p, chain, proofs = verifyHopProof) => {
      const verdict = await verifyRequestDelegation(
        { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
        { resource: RESOURCE, trustedRootIssuers: [p.acme.did], verifyHopProof: proofs, checkRevocation: checker(p), now: () => NOW_MS },
      );
      return verdict.ok ? { ok: true, reasons: [] } : { ok: false, code: verdict.refusalCode, reasons: verdict.reasons };
    },
  ],
  [
    'evaluateDelegationChain',
    async (p, chain, proofs = verifyHopProof) => {
      const verdict = await evaluateDelegationChain(chain, checker(p), {
        resource: RESOURCE,
        resourceOwner: p.acme.did,
        verifyHopProof: proofs,
        now: () => NOW_MS,
      });
      return { ok: verdict.ok, ...(verdict.code === undefined ? {} : { code: verdict.code }), reasons: verdict.reasons };
    },
  ],
];

describe('signDelegationCredential, with the parent in hand', () => {
  it('writes the digest SPEC §7.8 gives the parent credential, and the hop verifies', async () => {
    const p = parties();
    const parent = grant(p, 4);
    const child = await signDelegationCredential(unsigned(onward(p)), await signerFor(p.agent), { parent });
    expect(child.credentialSubject.parentCredentialDigest).toBe(await digestOf(parent));
    expect(await verifyHopProof(child)).toBe(true);
  });

  it('writes none without the parent, as before', async () => {
    const p = parties();
    const child = await signDelegationCredential(unsigned(onward(p)), await signerFor(p.agent));
    expect(child.credentialSubject).not.toHaveProperty('parentCredentialDigest');
  });

  it('keeps a digest the hop already states when it is the parent\'s', async () => {
    const p = parties();
    const parent = grant(p, 4);
    const stated = unsigned(onward(p, await digestOf(parent)));
    const child = await signDelegationCredential(stated, await signerFor(p.agent), { parent });
    expect(child.credentialSubject.parentCredentialDigest).toBe(await digestOf(parent));
  });

  it('refuses a parent whose capability the hop does not name, whose digest every verifier would refuse', async () => {
    const p = parties();
    const stranger = hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:acme:other', parentCapability: RESOURCE, allowedAction: ['orders.place'] });
    await expect(signDelegationCredential(unsigned(onward(p)), await signerFor(p.agent), { parent: stranger })).rejects.toThrow(
      TypeError,
    );
  });

  it('refuses a hop that already states the digest of another parent', async () => {
    const p = parties();
    const stated = unsigned(onward(p, await digestOf(grant(p, 3))));
    await expect(signDelegationCredential(stated, await signerFor(p.agent), { parent: grant(p, 4) })).rejects.toThrow(
      /parentCredentialDigest/,
    );
  });

  it.each([
    ['a digest in upper case', `SHA256:${'A'.repeat(64)}`],
    ['a number', 7],
    ['null', null],
  ])('refuses, with or without the parent, a hop that states as its digest %s', async (_form, stated) => {
    const p = parties();
    const hopStating = unsigned(onward(p, stated));
    const signer = await signerFor(p.agent);
    await expect(signDelegationCredential(hopStating, signer)).rejects.toThrow(/parentCredentialDigest/);
    await expect(signDelegationCredential(hopStating, signer, { parent: grant(p, 4) })).rejects.toThrow(/parentCredentialDigest/);
  });

  it('refuses a parent that carries no signature, which has no digest', async () => {
    const p = parties();
    const parent = unsigned(grant(p, 4)) as unknown as DelegationCredential;
    await expect(signDelegationCredential(unsigned(onward(p)), await signerFor(p.agent), { parent })).rejects.toThrow(TypeError);
  });
});

describe.each(PATHS)('%s reads a hop\'s parentCredentialDigest', (_name, verify) => {
  it('accepts a hop that states its parent\'s digest', async () => {
    const p = parties();
    const parent = grant(p, 4);
    expect(await verify(p, [parent, onward(p, await digestOf(parent))])).toEqual({ ok: true, reasons: [] });
  });

  it('refuses a hop presented under a parent issued again under the id of the revoked one it names', async () => {
    const p = parties();
    const revoked = grant(p, 3);
    const reissued = grant(p, 4);
    const child = onward(p, await digestOf(revoked));
    expect((await verify(p, [revoked, child])).ok).toBe(false);
    const said = await verify(p, [reissued, child]);
    expect(said).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(said.reasons).toEqual(['hop 1: parentCredentialDigest is not the digest of hop 0, the parent presented with it']);
  });

  it('accepts a hop that states no digest, as before: its parent is then named by its id alone', async () => {
    const p = parties();
    expect(await verify(p, [grant(p, 4), onward(p)])).toEqual({ ok: true, reasons: [] });
  });

  it('refuses a root that states a parent digest, since it has no parent credential', async () => {
    const p = parties();
    const root = grant(p, 4, { parentCredentialDigest: await digestOf(grant(p, 5)) });
    const said = await verify(p, [root, onward(p, await digestOf(root))]);
    expect(said).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(said.reasons).toContain('root delegation: it has no parent credential, so it states no parentCredentialDigest');
  });

  // A digest stated in any other form is not the parent's digest, as SPEC §6.10 refuses it.
  it.each([
    ['a digest in upper case', (digest: string) => digest.toUpperCase().replace('SHA256', 'sha256')],
    ['no digest at all', () => 'sha256:'],
    ['a number', () => 7],
    ['null', () => null],
  ])('refuses a hop whose parentCredentialDigest is %s as chain_invalid', async (_form, write) => {
    const p = parties();
    const parent = grant(p, 4);
    const said = await verify(p, [parent, onward(p, write(await digestOf(parent)))]);
    expect(said).toEqual({
      ok: false,
      code: 'chain_invalid',
      reasons: ['hop 1: parentCredentialDigest is not the digest of hop 0, the parent presented with it'],
    });
  });

  it('refuses a root whose parentCredentialDigest is not a digest as chain_invalid', async () => {
    const p = parties();
    const root = grant(p, 4, { parentCredentialDigest: 7 });
    const said = await verify(p, [root, onward(p)]);
    expect(said).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(said.reasons).toContain('root delegation: it has no parent credential, so it states no parentCredentialDigest');
  });

  it('refuses a mismatch before it verifies any hop proof or reads any status', async () => {
    const p = parties();
    const proofs = vi.fn(verifyHopProof);
    const said = await verify(p, [grant(p, 4), onward(p, await digestOf(grant(p, 5)))], proofs);
    expect(said).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(proofs).not.toHaveBeenCalled();
  });
});

describe('the parent a verifier digests', () => {
  it('is the credential as received, with members no schema names, as its signature covers them', async () => {
    const p = parties();
    const signed = grant(p, 4);
    const status = { ...(signed.credentialStatus as Record<string, unknown>), statusMessage: [{ status: '0x1', message: 'revoked' }] };
    const parent = signEddsaJcs2022({ ...unsigned(signed), credentialStatus: status }, p.acme) as unknown as DelegationCredential;
    const [, verify] = PATHS[0]!;
    expect(await verify(p, [parent, onward(p, await digestOf(parent))])).toEqual({ ok: true, reasons: [] });
  });

  it('refuses a hop whose parent carries no signature, which has no digest, when no hop proof is checked', async () => {
    const p = parties();
    const parent = unsigned(grant(p, 4)) as unknown as DelegationCredential;
    const child = onward(p, await digestOf(grant(p, 4)));
    const verdict = await evaluateDelegationChain([parent, child], checker(p), { resource: RESOURCE, resourceOwner: p.acme.did, now: () => NOW_MS });
    expect(verdict).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(verdict.reasons).toEqual(['hop 1: hop 0, the parent presented with it, has no signed form, so it has no digest']);
  });

  it('refuses as runtime_error when the digest cannot be computed, and tells the operator\'s log why', async () => {
    const p = parties();
    const parent = grant(p, 4);
    const child = onward(p, await digestOf(parent));
    const digest = vi.spyOn(crypto.subtle, 'digest').mockRejectedValueOnce(new Error('the hash provider is away'));
    try {
      const { result, logged } = await withWarnings(() =>
        evaluateDelegationChain([parent, child], checker(p), { resource: RESOURCE, resourceOwner: p.acme.did, verifyHopProof, now: () => NOW_MS }),
      );
      expect(result).toMatchObject({ ok: false, code: 'runtime_error', reasons: [`hop 1: parentCredentialDigest could not be checked${WITHHELD_SUFFIX}`] });
      expect(logged).toContain('the hash provider is away');
    } finally {
      digest.mockRestore();
    }
  });
});

describe('validateDelegationChain, the synchronous rules alone', () => {
  it("reads no hop's parentCredentialDigest, which evaluateDelegationChain checks", async () => {
    const p = parties();
    const chain = [grant(p, 4), onward(p, await digestOf(grant(p, 5)))];
    expect(validateDelegationChain(chain, { resource: RESOURCE, resourceOwner: p.acme.did, now: () => NOW_MS }))
      .toMatchObject({ ok: true, reasons: [] });
    const evaluated = await PATHS[1]![1](p, chain);
    expect(evaluated).toMatchObject({ ok: false, code: 'chain_invalid' });
  });
});
