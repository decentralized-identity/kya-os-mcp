/**
 * The delegation chain carried with a request (SPEC-ENTITY-CARD §10.5, §11.4). Every case runs the
 * real default path: hops signed with eddsa-jcs-2022 by real Ed25519 keys, did:key resolution,
 * the shipped hop-proof verifier, and the shipped Bitstring Status List checker reading a signed
 * list. Only the network is faked.
 */

import { describe, it, expect, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { DelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { buildCardProof, ed25519SignerFromJwk, InMemoryNonceCache } from '../proof/index.js';
import { requireProof } from '../middleware.js';
import {
  DEFAULT_CARRIED_CHAIN_LIMIT,
  KYA_OS_DELEGATION_CHAIN_META_KEY,
  readDelegationChain,
  requireDelegation,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RequestDelegationInput,
  type VerifyRequestDelegationDeps,
} from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import {
  NOW_MS,
  RESOURCE,
  hop,
  identity,
  parties,
  serve,
  statusList,
  twoHopChain,
  type ChainParties,
} from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();

/**
 * The verifier's wiring, all shipped implementations, trusting Acme as the root, so Acme's list, at
 * the status URL, is read for every hop of its chains. `list` is what the status URL serves.
 */
function deps(
  p: ChainParties,
  overrides: Partial<VerifyRequestDelegationDeps> & { list?: Record<string, unknown> | null } = {},
): VerifyRequestDelegationDeps {
  const { list, ...rest } = overrides;
  return {
    resource: RESOURCE,
    trustedRootIssuers: [p.acme.did],
    verifyHopProof: createDelegationProofVerifier({ didResolver }),
    checkRevocation: createRevocationChecker({
      fetch: serve(list === null ? undefined : (list ?? statusList(p.acme))),
      now: () => NOW_MS,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    }),
    now: () => NOW_MS,
    ...rest,
  };
}

function carried(chain: DelegationChain, p: ChainParties, action = 'orders.place'): RequestDelegationInput {
  return { meta: { ...toDelegationChainMeta(chain) }, proofDid: p.subAgent.did, action };
}

// ── Reading the member ───────────────────────────────────────────────────────

describe('readDelegationChain', () => {
  it('reads back what toDelegationChainMeta wrote, keeping each hop as received', () => {
    const chain = twoHopChain(parties());
    const read = readDelegationChain(toDelegationChainMeta(chain));
    expect(read).toMatchObject({ carried: true, ok: true });
    if (!read.carried || !read.ok) throw new Error('unreachable');
    expect(read.chain).toHaveLength(2);
    expect(read.credentials[0]).toBe(chain[0]);
    expect(read.credentials[1]).toBe(chain[1]);
  });

  it('treats an absent member, or no _meta at all, as not carried', () => {
    expect(readDelegationChain({ other: 1 })).toEqual({ carried: false });
    expect(readDelegationChain(undefined)).toEqual({ carried: false });
    expect(readDelegationChain('not a record')).toEqual({ carried: false });
  });

  it('rejects a member that is not a non-empty array', () => {
    for (const value of [{}, 'chain', 42, []]) {
      const read = readDelegationChain({ [KYA_OS_DELEGATION_CHAIN_META_KEY]: value });
      expect(read).toMatchObject({ carried: true, ok: false });
    }
  });

  it('bounds the length before parsing any entry', () => {
    const tooLong = Array.from({ length: DEFAULT_CARRIED_CHAIN_LIMIT + 1 }, () => 'not a credential');
    const read = readDelegationChain({ [KYA_OS_DELEGATION_CHAIN_META_KEY]: tooLong });
    expect(read).toEqual({
      carried: true,
      ok: false,
      reasons: [`carried delegation chain of 11 credentials exceeds the limit of ${DEFAULT_CARRIED_CHAIN_LIMIT}`],
    });
  });

  it('names the hop and the field when an entry is not a DelegationCredential', () => {
    const [root, leaf] = twoHopChain(parties());
    const broken = { ...leaf, type: ['VerifiableCredential'] };
    const read = readDelegationChain(toDelegationChainMeta([root, broken as never]));
    expect(read).toMatchObject({ carried: true, ok: false });
    if (read.carried && !read.ok) expect(read.reasons[0]).toMatch(/^hop 1: not a DelegationCredential at type/);
  });
});

// ── Carried chains ───────────────────────────────────────────────────────────

describe('verifyRequestDelegation: a carried chain', () => {
  it('accepts a two-hop chain and recomputes the grant from it', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p));
    expect(result).toEqual({
      ok: true,
      source: 'carried',
      responsibleParty: p.acme.did,
      leafInvoker: p.subAgent.did,
      invocationTarget: RESOURCE,
      allowedAction: ['orders.place'],
      depth: 2,
      fresh: true,
    });
  });

  it('never consults the by-reference resolver when the request carries a chain', async () => {
    const p = parties();
    const resolveDelegationChain = vi.fn(async () => twoHopChain(p));
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { resolveDelegationChain }));
    expect(result.ok).toBe(true);
    expect(resolveDelegationChain).not.toHaveBeenCalled();
  });

  it('rejects a malformed carried chain without falling back to the resolver', async () => {
    const p = parties();
    const resolveDelegationChain = vi.fn(async () => twoHopChain(p));
    const input = { meta: { [KYA_OS_DELEGATION_CHAIN_META_KEY]: 'not a chain' }, proofDid: p.subAgent.did, action: 'orders.place' };
    const result = await verifyRequestDelegation(input, deps(p, { resolveDelegationChain }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid', source: 'carried' });
    expect(resolveDelegationChain).not.toHaveBeenCalled();
  });

  it('grants nothing to a caller that does not hold the leaf key', async () => {
    const p = parties();
    const input = { ...carried(twoHopChain(p), p), proofDid: identity().did };
    const result = await verifyRequestDelegation(input, deps(p));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid' });
    if (!result.ok) expect(result.reasons[0]).toMatch(/^leaf delegate .* is not the request proof's DID/);
  });

  it('rejects a hop changed after signing, even when the change still attenuates', async () => {
    const p = parties();
    const [root, leaf] = twoHopChain(p);
    const swapped = { ...leaf, credentialSubject: { ...leaf.credentialSubject, allowedAction: ['orders.read'] } };
    const result = await verifyRequestDelegation(carried([root, swapped], p, 'orders.read'), deps(p));
    expect(result).toEqual({ ok: false, code: 'delegation_invalid', reasons: ['hop 1: proof did not verify'], source: 'carried' });
  });

  it('rejects a hop signed by someone other than its issuer', async () => {
    const p = parties();
    const [root] = twoHopChain(p);
    const forged = hop({
      issuer: p.agent,
      signer: identity(),
      invoker: p.subAgent.did,
      id: 'urn:zcap:agent-leaf',
      parentCapability: 'urn:zcap:acme-root',
      allowedAction: ['orders.place'],
      caveats: [{ type: 'MaxAmount', limit: '100.00', currency: 'USD' }],
    });
    const result = await verifyRequestDelegation(carried([root, forged], p), deps(p));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid', reasons: ['hop 1: proof did not verify'] });
  });

  it('rejects a hop that broadens its parent before checking any signature', async () => {
    const p = parties();
    const [root] = twoHopChain(p);
    const broader = hop({
      issuer: p.agent,
      invoker: p.subAgent.did,
      id: 'urn:zcap:agent-leaf',
      parentCapability: 'urn:zcap:acme-root',
      allowedAction: ['orders.place', 'orders.refund'],
    });
    const verifyHopProof = vi.fn(async () => true);
    const result = await verifyRequestDelegation(carried([root, broader], p), deps(p, { verifyHopProof }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid' });
    expect(verifyHopProof).not.toHaveBeenCalled();
  });

  it('rejects a chain minted for a different resource', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(
      carried(twoHopChain(p), p),
      deps(p, { resource: 'did:web:other-merchant.example' }),
    );
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid' });
    if (!result.ok) expect(result.reasons).toContain('root invocationTarget ≠ the expected resource');
  });

  it('enforces trustedRootIssuers against the recomputed Responsible Party', async () => {
    const p = parties();
    const untrusted = await verifyRequestDelegation(
      carried(twoHopChain(p), p),
      deps(p, { trustedRootIssuers: [identity().did] }),
    );
    expect(untrusted).toMatchObject({ ok: false, code: 'delegation_invalid' });
    const trusted = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { trustedRootIssuers: [p.acme.did] }));
    expect(trusted.ok).toBe(true);
    // Each listed DID is compared whole: one the root issuer starts with, or that starts with it, is another DID.
    for (const nearMiss of [p.acme.did.slice(0, -1), `${p.acme.did}x`]) {
      expect(await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { trustedRootIssuers: [nearMiss] }))).toMatchObject({
        ok: false, code: 'delegation_invalid', reasons: [`root issuer ${p.acme.did} is not a trusted root issuer`],
      });
    }
  });

  it('refuses a trustedRootIssuers that is not an array of DIDs, a string and null included, naming the option', async () => {
    const p = parties();
    const refusal = /^\[kya-os\] trustedRootIssuers must be an array of DIDs, each a string that starts with "did:" and has no white space around it \(got /;
    for (const list of [p.acme.did, `${identity().did} ${p.acme.did}`, null, [''], [5], [`${p.acme.did} `]]) {
      const configured = deps(p, { trustedRootIssuers: list as unknown as string[] });
      await expect(verifyRequestDelegation(carried(twoHopChain(p), p), configured)).rejects.toThrow(refusal);
      expect(() => requireDelegation(configured)).toThrow(TypeError);
      expect(() => requireDelegation(configured)).toThrow(refusal);
    }
  });

  it('refuses an action the leaf does not grant, even one an ancestor granted', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p, 'orders.read'), deps(p));
    expect(result).toMatchObject({ ok: false, code: 'action_not_delegated' });
  });

  it('rejects the whole chain when an ancestor is revoked', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { list: statusList(p.acme, [3]) }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked' });
  });

  it('fails closed when the status list cannot be read', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { list: null }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked' });
  });

  it('fails closed when the status list is not signed by a key its issuer published', async () => {
    const p = parties();
    const forgedList = { ...statusList(identity()), issuer: p.acme.did };
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { list: forgedList }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked' });
  });

  it('honours a tighter maxChainLength', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { maxChainLength: 1 }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid', source: 'carried' });
  });

  it('rejects when the hop-proof seam throws', async () => {
    const p = parties();
    const verifyHopProof = async () => {
      throw new Error('boom');
    };
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { verifyHopProof }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid', reasons: ['hop 0: proof did not verify'] });
  });

  it('rejects when the revocation seam throws', async () => {
    const p = parties();
    const checkRevocation = async () => {
      throw new Error('boom');
    };
    const result = await verifyRequestDelegation(carried(twoHopChain(p), p), deps(p, { checkRevocation }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked' });
  });
});

// ── By reference ─────────────────────────────────────────────────────────────

describe('verifyRequestDelegation: by reference', () => {
  const input = (p: ChainParties): RequestDelegationInput => ({ meta: {}, proofDid: p.subAgent.did, action: 'orders.place' });

  it('reports delegation_missing when nothing is carried and no resolver is configured', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(input(p), deps(p));
    expect(result).toMatchObject({ ok: false, code: 'delegation_missing' });
  });

  it('verifies a resolved chain exactly as a carried one', async () => {
    const p = parties();
    const resolveDelegationChain = vi.fn(async () => twoHopChain(p));
    const result = await verifyRequestDelegation(input(p), deps(p, { resolveDelegationChain }));
    expect(result).toMatchObject({ ok: true, source: 'resolved', responsibleParty: p.acme.did });
    expect(resolveDelegationChain).toHaveBeenCalledWith({ proofDid: p.subAgent.did });
  });

  it('reports delegation_unresolvable when the registry cannot be reached', async () => {
    const p = parties();
    const resolveDelegationChain = async (): Promise<DelegationChain> => {
      throw new Error('registry.acme.example unreachable');
    };
    const result = await verifyRequestDelegation(input(p), deps(p, { resolveDelegationChain }));
    expect(result).toEqual({
      ok: false,
      code: 'delegation_unresolvable',
      reasons: ['delegation chain could not be resolved: registry.acme.example unreachable'],
      source: 'resolved',
    });
  });

  it('reports delegation_missing when the resolver finds nothing', async () => {
    const p = parties();
    const result = await verifyRequestDelegation(input(p), deps(p, { resolveDelegationChain: async () => undefined }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_missing', source: 'resolved' });
  });

  it('parses what the resolver returns', async () => {
    const p = parties();
    const resolveDelegationChain = async () => [{ not: 'a credential' }] as unknown as DelegationChain;
    const result = await verifyRequestDelegation(input(p), deps(p, { resolveDelegationChain }));
    expect(result).toMatchObject({ ok: false, code: 'delegation_invalid', source: 'resolved' });
  });
});

// ── The guard, composed after requireProof ───────────────────────────────────

describe('requireDelegation', () => {
  it('authorizes a call end to end: the request proof by the leaf key, the chain in the same _meta', async () => {
    const p = parties();
    const request = { method: 'tools/call', params: { name: 'orders.place', arguments: { sku: 'A-100', qty: 1 } } };
    const kid = p.subAgent.method;
    const signer = await ed25519SignerFromJwk({ did: p.subAgent.did, kid, privateJwk: p.subAgent.privateJwk });
    const proofMeta = await buildCardProof(request, signer, { audience: RESOURCE, nonce: 'n-0001' });
    const meta = { ...proofMeta, ...toDelegationChainMeta(twoHopChain(p)) };

    const proofGuard = requireProof({
      resolveKey: () => ({ ...p.subAgent.publicJwk, kid }),
      resolveDidKeys: (did) => (did === p.subAgent.did ? [p.subAgent.publicJwk] : []),
      expectedAudience: RESOURCE,
      consumeNonceIfFresh: new InMemoryNonceCache().consume,
    });
    const proof = await proofGuard(request, meta);
    expect(proof).toMatchObject({ ok: true, did: p.subAgent.did });
    if (!proof.ok) throw new Error('unreachable');

    const delegationGuard = requireDelegation(deps(p));
    const authority = await delegationGuard({ meta, proofDid: proof.did, action: request.params.name });
    expect(authority).toMatchObject({ ok: true, source: 'carried', responsibleParty: p.acme.did });
  });

  it('is 401-shaped when no authority is presented, and 403-shaped when it does not authorize', async () => {
    const p = parties();
    const guard = requireDelegation(deps(p));
    const missing = await guard({ meta: {}, proofDid: p.subAgent.did, action: 'orders.place' });
    expect(missing).toMatchObject({ ok: false, status: 401, error: { code: 'delegation_missing' } });
    const denied = await guard(carried(twoHopChain(p), p, 'orders.refund'));
    expect(denied).toMatchObject({
      ok: false,
      status: 403,
      error: { code: 'action_not_delegated', message: 'the delegation chain does not grant this action' },
    });
  });
});
