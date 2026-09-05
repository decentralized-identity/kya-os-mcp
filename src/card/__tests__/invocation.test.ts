import { describe, expect, it, vi } from 'vitest';
import {
  buildCardProof,
  requireDelegatedInvocation,
  type DelegationCredential,
  type DelegatedInvocationDeps,
} from '../index.js';
import { AUD, DID, REQ, clock, deps, keypair } from './proof-helpers.js';

const OWNER = 'did:web:merchant.example';
const RESOURCE = 'https://merchant.example/accounts/shopper-a/cart';
const ACTION = 'cart:read';
const OPTIONS = { resourceOwner: OWNER, resource: RESOURCE, action: ACTION };

function chain(): DelegationCredential[] {
  return [{
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1', 'https://kya-os.org/ns/delegation/v1'],
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: OWNER,
    validUntil: '2026-07-01T00:00:00Z',
    credentialSubject: {
      id: 'urn:zcap:cart',
      parentCapability: RESOURCE,
      invocationTarget: RESOURCE,
      invoker: DID,
      allowedAction: [ACTION],
    },
    proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofValue: 'signature-provider-fixture' },
    credentialStatus: {
      type: 'BitstringStatusListEntry', statusPurpose: 'revocation',
      statusListCredential: 'https://merchant.example/status', statusListIndex: '0',
    },
  }];
}

async function setup(overrides: Partial<DelegatedInvocationDeps> = {}) {
  const { signer, publicJwk } = await keypair();
  const seen = new Set<string>();
  const verifyCredentialSignature = vi.fn(async () => true);
  const checkRevocation = vi.fn(async () => ({ revoked: false, fresh: true }));
  const authorizeInvocation = vi.fn(async () => true);
  const guard = requireDelegatedInvocation({
    proof: deps(publicJwk, {
      resolveDidKeys: () => [publicJwk],
      consumeNonceIfFresh: (nonce, did) => {
        const key = `${did}:${nonce}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      },
    }),
    // These tests qualify the mandatory seam composition. The request signature
    // is real Ed25519; credential signature/status providers have separate suites.
    verifyCredentialSignature, checkRevocation, authorizeInvocation, ...overrides,
  }, OPTIONS);
  let sequence = 0;
  const mint = () => buildCardProof(REQ, signer, {
    audience: AUD, nonce: `nonce-0123456789abcdef-${sequence++}`, now: clock,
  });
  return { guard, mint, verifyCredentialSignature, checkRevocation, authorizeInvocation };
}

describe('native delegated invocation admission', () => {
  it('recomputes the issuer/holder join and rechecks authority on each fresh retry', async () => {
    const s = await setup();
    const result = await s.guard(REQ, await s.mint(), chain());
    expect(result).toEqual({ ok: true, invocation: {
      responsibleParty: OWNER, leafInvoker: DID, resource: RESOURCE, action: ACTION, proofLevel: 'L3-minus',
    } });
    expect((await s.guard(REQ, await s.mint(), chain())).ok).toBe(true);
    expect(s.verifyCredentialSignature).toHaveBeenCalledTimes(2);
    expect(s.checkRevocation).toHaveBeenCalledTimes(2);
    expect(s.authorizeInvocation).toHaveBeenCalledTimes(2);
  });

  it('cannot use a valid chain without proof, after request mutation, or with a replay', async () => {
    const s = await setup();
    expect((await s.guard(REQ, {}, chain())).ok).toBe(false);
    expect((await s.guard({ ...REQ, params: { account: 'shopper-b' } }, await s.mint(), chain())).ok).toBe(false);
    const meta = await s.mint();
    expect((await s.guard(REQ, meta, chain())).ok).toBe(true);
    expect((await s.guard(REQ, meta, chain())).ok).toBe(false);
    expect(s.authorizeInvocation).toHaveBeenCalledTimes(1);
  });

  it('a forged request cannot burn a real request nonce, and concurrent valid replays allow only once', async () => {
    const s = await setup();
    const meta = await s.mint();
    const forged = structuredClone(meta);
    forged['org.kya-os/request-proof'].jws = 'forged..signature';
    expect((await s.guard(REQ, forged, chain())).ok).toBe(false);
    const results = await Promise.all([
      s.guard(REQ, meta, chain()),
      s.guard(REQ, meta, chain()),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(s.authorizeInvocation).toHaveBeenCalledTimes(1);
  });

  it('preserves signed extension fields when passing credentials to the signature verifier', async () => {
    const s = await setup();
    const presented = chain();
    Object.assign(presented[0]!.credentialStatus!, { issuerExtension: 'signed-value' });
    expect((await s.guard(REQ, await s.mint(), presented)).ok).toBe(true);
    expect(s.verifyCredentialSignature).toHaveBeenCalledWith(presented[0]);
  });

  it.each([
    ['untrusted root', (vc: DelegationCredential) => { vc.issuer = 'did:web:other.example'; }],
    ['wrong resource', (vc: DelegationCredential) => { vc.credentialSubject.invocationTarget = 'https://merchant.example/accounts/shopper-b/cart'; }],
    ['wrong holder', (vc: DelegationCredential) => { vc.credentialSubject.invoker = 'did:web:other.example'; }],
    ['wrong action', (vc: DelegationCredential) => { vc.credentialSubject.allowedAction = ['cart:write']; }],
    ['expired authority', (vc: DelegationCredential) => { vc.validUntil = '2026-01-01T00:00:00Z'; }],
    ['no credential signature', (vc: DelegationCredential) => { delete vc.proof; }],
    ['no revocation entry', (vc: DelegationCredential) => { delete vc.credentialStatus; }],
    ['wrong status purpose', (vc: DelegationCredential) => { vc.credentialStatus!.statusPurpose = 'suspension'; }],
  ])('rejects %s before resource policy', async (_name, mutate) => {
    const s = await setup();
    const presented = chain();
    mutate(presented[0]!);
    expect((await s.guard(REQ, await s.mint(), presented)).ok).toBe(false);
    expect(s.authorizeInvocation).not.toHaveBeenCalled();
  });

  it.each([undefined, [], [{}], Array.from({ length: 11 }, () => chain()[0])])('rejects malformed or excessive chains', async (presented) => {
    const s = await setup();
    expect((await s.guard(REQ, await s.mint(), presented)).ok).toBe(false);
    expect(s.verifyCredentialSignature).not.toHaveBeenCalled();
  });

  it('checks signatures on every hop before reading status references', async () => {
    const verify = vi.fn(async () => true).mockResolvedValueOnce(true).mockResolvedValueOnce(false);
    const s = await setup({ verifyCredentialSignature: verify });
    const parent = chain()[0]!;
    parent.credentialSubject.invoker = 'did:web:intermediate.example';
    const child = chain()[0]!;
    child.issuer = 'did:web:intermediate.example';
    child.credentialSubject.id = 'urn:zcap:child';
    child.credentialSubject.parentCapability = parent.credentialSubject.id;
    expect((await s.guard(REQ, await s.mint(), [parent, child])).ok).toBe(false);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(s.checkRevocation).not.toHaveBeenCalled();
  });

  it('rechecks revocation on a saved chain and denies a previously authorized holder', async () => {
    let revoked = false;
    const s = await setup({ checkRevocation: async () => ({ revoked, fresh: true }) });
    const savedChain = chain();
    expect((await s.guard(REQ, await s.mint(), savedChain)).ok).toBe(true);
    revoked = true;
    expect((await s.guard(REQ, await s.mint(), savedChain)).ok).toBe(false);
  });

  it.each([
    { verifyCredentialSignature: async () => false },
    { verifyCredentialSignature: async () => { throw new Error('unavailable'); } },
    { checkRevocation: async () => ({ revoked: false, fresh: false }) },
    { checkRevocation: async () => { throw new Error('unavailable'); } },
    { authorizeInvocation: async () => false },
    { authorizeInvocation: async () => { throw new Error('unavailable'); } },
  ])('denies failed signature, liveness or account/caveat policy seams', async (overrides) => {
    const s = await setup(overrides);
    expect((await s.guard(REQ, await s.mint(), chain())).ok).toBe(false);
  });

  it('requires a resource policy callback at runtime as well as in TypeScript', async () => {
    const s = await setup({ authorizeInvocation: undefined as never });
    expect((await s.guard(REQ, await s.mint(), chain())).ok).toBe(false);
  });
});
