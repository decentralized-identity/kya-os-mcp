/**
 * Who may sign the status list a Card's `revocation` entry names (SPEC-ENTITY-CARD.md §10.3): the
 * Card's Entity, its `id`; the Card's responsible party, once the accountability check has verified
 * it as the root issuer of the Card's delegation chain (§10.2); and an issuer `statusListIssuers`
 * accepts for the Card's `id`. The Entity is the Card's own issuer, so its list may state no `id`
 * when it is the one issuer accepted for the Card. Otherwise every list is read only when it states,
 * as its `id`, the URL it was fetched from.
 *
 * The Card and its list take the shape of Appendix B's `agent` example, with did:web DIDs whose
 * documents a stub resolver serves. Every case runs `verifyCard` with the shipped checker and proof
 * verifier over lists signed by real keys; only the network is faked.
 */

import { describe, it, expect, vi } from 'vitest';
import type { DelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker, type RevocationCheckerDeps } from '../revocation.js';
import type { EntityCard } from '../schema.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { verifyCard, type AccountabilityVerifier, type VerifyCardDeps } from '../verify.js';
import type { DIDDocument, DIDResolver } from '../../delegation/vc-verifier.types.js';
import {
  hop,
  identity,
  NOW_MS,
  RESOURCE,
  serveAt,
  signEddsaJcs2022,
  statusList,
  type TestIdentity,
} from './signed-chain-helpers.js';

const now = () => NOW_MS;
const CARDS_URL = 'https://example.com/status/cards';

/** An Ed25519 key published as the verification method `<did>#key-1` of a did:web DID. */
function webIdentity(did: string): TestIdentity {
  return { ...identity(), did, method: `${did}#key-1` };
}

const entity = webIdentity('did:web:example.com:agents:acme-pay');
const responsibleParty = webIdentity('did:web:api.example');
const anotherRoot = webIdentity('did:web:other.example');
const statusService = webIdentity('did:web:status.example');

/** Each party's DID document, naming its key for assertions. */
const didResolver: DIDResolver = {
  resolve: async (did) => {
    const party = [entity, responsibleParty, anotherRoot, statusService].find((p) => p.did === did);
    if (!party) return null;
    const document: DIDDocument = {
      id: did,
      verificationMethod: [{ id: party.method, type: 'JsonWebKey2020', controller: did, publicKeyJwk: party.publicJwk }],
      assertionMethod: [party.method],
    };
    return document;
  },
};

const card: EntityCard = {
  id: entity.did,
  entityType: 'agent',
  name: 'Acme Pay Agent',
  kid: entity.method,
  capabilities: ['handshake'],
  responsibleParty: responsibleParty.did,
  principal: 'did:web:example.com:users:alice',
  delegationRef: 'urn:zcap:root',
  revocation: { statusListCredential: CARDS_URL, statusListIndex: '3' },
};

/** The list at `CARDS_URL` that `signer` signed with `revoked` bits set, stating that URL as its `id` or not. */
function cardsList(signer: TestIdentity, revoked: number[] = [], { statesId = true } = {}) {
  const list = statusList(signer, revoked, { id: CARDS_URL, credentialSubject: { id: `${CARDS_URL}#list` } });
  if (statesId) return list;
  const { id: _id, proof: _proof, ...unsigned } = list;
  return signEddsaJcs2022(unsigned, signer);
}

/** The Card's delegation chain, from `root` to the Entity. */
function chainFrom(root: TestIdentity): DelegationChain {
  return [
    hop({
      issuer: root,
      invoker: entity.did,
      id: 'urn:zcap:root',
      parentCapability: RESOURCE,
      allowedAction: ['payments.transfer'],
    }),
  ];
}

/** The host's accountability policy binds the Card to a cryptographically verified chain. */
function accountableThrough(chain: DelegationChain): AccountabilityVerifier {
  return async (c, ctx) => {
    // Independent host policy for this fixture, not a pin copied from the Card.
    if (c.id !== entity.did || c.responsibleParty !== responsibleParty.did) return false;
    if (c.delegationRef !== 'urn:zcap:root' || (ctx.proofDid !== undefined && ctx.proofDid !== c.id)) return false;
    const result = await verifyRequestDelegation({
      meta: toDelegationChainMeta(chain), proofDid: c.id, action: 'payments.transfer',
    }, {
      resource: RESOURCE, resourceOwner: responsibleParty.did, now,
      verifyHopProof: createDelegationProofVerifier({ didResolver }),
      checkRevocation: createRevocationChecker({ fetch: serveAt({}), now }),
    });
    return { verified: result.ok, fresh: result.ok && result.fresh };
  };
}

/** `verifyCard` over `card`, with the shipped checker reading `list` at `CARDS_URL`. */
function verifyWith(list: Record<string, unknown>, deps: Partial<VerifyCardDeps> = {}, checker: Partial<RevocationCheckerDeps> = {}) {
  const statusListChecker = createRevocationChecker({
    fetch: serveAt({ [CARDS_URL]: list }),
    now,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
    ...checker,
  });
  return verifyCard(card, { accountabilityVerifier: accountableThrough(chainFrom(responsibleParty)), statusListChecker, ...deps });
}

const READ_CLEAR = { revoked: false, fresh: true };
const READ_REVOKED = { revoked: true, fresh: true };
const REFUSED = { revoked: true, fresh: false };

describe("the Card's verified responsible party", () => {
  it.each(['false', 1, {}, null])('does not grant authority for a malformed seam verdict: %j', async (verified) => {
    const accountabilityVerifier = async () => ({ verified }) as unknown as Awaited<ReturnType<AccountabilityVerifier>>;
    expect(await verifyWith(cardsList(responsibleParty), { accountabilityVerifier })).toMatchObject({
      ok: false, revocation: REFUSED,
    });
  });

  it.each([['true'], [1], [[true]]])('does not grant authority for a malformed bare verdict: %j', async (raw) => {
    const accountabilityVerifier = async () => raw as unknown as Awaited<ReturnType<AccountabilityVerifier>>;
    expect(await verifyWith(cardsList(responsibleParty), { accountabilityVerifier })).toMatchObject({
      ok: false, accountability: { verified: false }, revocation: REFUSED,
    });
  });

  /** Every other input is live, so the seam's `fresh` alone decides between L3 and L2. */
  function reporting(verdict: Record<string, unknown>): Partial<VerifyCardDeps> {
    return {
      accountabilityVerifier: async () => verdict as unknown as Awaited<ReturnType<AccountabilityVerifier>>,
      capabilityVerifier: async () => ({ verified: ['handshake'], unverified: [] }),
      proof: {},
      request: { method: 'tools/call', params: { name: 'handshake' } },
      proofVerifier: async () => ({ ok: true, reasons: [], level: 'L3', did: entity.did }),
    };
  }

  it.each<[{ verified: boolean; fresh?: boolean }, string]>([
    [{ verified: true, fresh: true }, 'L3'],
    [{ verified: true, fresh: false }, 'L2'],
    [{ verified: true }, 'L3'],
    [{ verified: true, fresh: undefined }, 'L3'],
  ])('keeps a boolean fresh, and reads an absent one as unknown: %j', async (verdict, level) => {
    const result = await verifyWith(cardsList(entity), reporting(verdict));
    expect(result).toMatchObject({ ok: true, conformanceLevel: level, revocation: READ_CLEAR });
    expect(result.accountability?.fresh).toBe(verdict.fresh);
  });

  it.each([['false'], ['true'], [1], [0], [''], [{}], [[]], [null]])('reads a fresh that is present and not a boolean as not fresh: %j', async (fresh) => {
    const result = await verifyWith(cardsList(entity), reporting({ verified: true, fresh }));
    expect(result).toMatchObject({ ok: true, conformanceLevel: 'L2', revocation: READ_CLEAR });
    expect(result.accountability).toMatchObject({ verified: true, fresh: false });
  });

  it('rejects a structurally valid chain with a forged root proof', async () => {
    const chain = [...chainFrom(responsibleParty)];
    chain[0] = { ...chain[0]!, proof: chainFrom(anotherRoot)[0]!.proof };
    expect(await verifyWith(cardsList(responsibleParty), { accountabilityVerifier: accountableThrough(chain) }))
      .toMatchObject({ ok: false, revocation: REFUSED });
  });
  it('signs a list that is read when it states its URL as its id', async () => {
    const clear = await verifyWith(cardsList(responsibleParty));
    expect(clear.accountability).toMatchObject({ responsibleParty: responsibleParty.did, verified: true });
    expect(clear).toMatchObject({ ok: true, revocation: READ_CLEAR });
    expect(await verifyWith(cardsList(responsibleParty, [3]))).toMatchObject({ ok: false, revocation: READ_REVOKED });
  });

  it('signs a list that is refused when it states no id', async () => {
    const result = await verifyWith(cardsList(responsibleParty, [], { statesId: false }));
    expect(result).toMatchObject({ ok: false, revocation: REFUSED });
  });

  it("is named to the checker as the chain's root only once accountability verified it", async () => {
    const check = vi.fn(createRevocationChecker({ fetch: serveAt({}), now }));
    await verifyCard(card, { accountabilityVerifier: accountableThrough(chainFrom(responsibleParty)), statusListChecker: check });
    await verifyCard(card, { accountabilityVerifier: accountableThrough(chainFrom(anotherRoot)), statusListChecker: check });
    await verifyCard(card, { statusListChecker: check });
    expect(check.mock.calls).toEqual([
      [card.revocation, { credentialIssuer: entity.did, trustedRootIssuer: responsibleParty.did }],
      [card.revocation, { credentialIssuer: entity.did }],
      [card.revocation, { credentialIssuer: entity.did }],
    ]);
  });
});

describe("a responsible party accountability did not verify", () => {
  it('signs a list that is refused when no accountability verifier runs or it rejects the party', async () => {
    const list = cardsList(responsibleParty);
    for (const accountabilityVerifier of [undefined, async () => false, async () => ({ verified: false })]) {
      const result = await verifyWith(list, { accountabilityVerifier });
      expect(result.accountability).toMatchObject({ verified: false });
      expect(result.revocation).toEqual(REFUSED);
    }
  });

  it("signs a list that is refused when another DID is the root of the Card's chain", async () => {
    const accountabilityVerifier = accountableThrough(chainFrom(anotherRoot));
    for (const signer of [responsibleParty, anotherRoot]) {
      const result = await verifyWith(cardsList(signer), { accountabilityVerifier });
      expect(result.accountability).toMatchObject({ verified: false });
      expect(result.revocation).toEqual(REFUSED);
    }
  });
});

describe("the Card's Entity and other signers", () => {
  it('signs a list that is read when it states its id, with a responsible party verified or not', async () => {
    expect((await verifyWith(cardsList(entity))).revocation).toEqual(READ_CLEAR);
    expect((await verifyWith(cardsList(entity, [3]))).revocation).toEqual(READ_REVOKED);
    const unverified = await verifyWith(cardsList(entity, [3]), { accountabilityVerifier: undefined });
    expect(unverified.revocation).toEqual(READ_REVOKED);
  });

  it('signs a list that is read when it states no id only while the Entity is the one issuer accepted for the Card', async () => {
    const idless = (revoked: number[]) => cardsList(entity, revoked, { statesId: false });
    const alone = { accountabilityVerifier: undefined };
    expect((await verifyWith(idless([]), alone)).revocation).toEqual(READ_CLEAR);
    expect((await verifyWith(idless([3]), alone)).revocation).toEqual(READ_REVOKED);
    expect((await verifyWith(idless([]))).revocation).toEqual(REFUSED);
    const statusListIssuers = { [entity.did]: [statusService.did] };
    expect((await verifyWith(idless([]), alone, { statusListIssuers })).revocation).toEqual(REFUSED);
  });

  it("is a third party whose list is refused, unless statusListIssuers accepts it for the Card's id and it states its id", async () => {
    expect((await verifyWith(cardsList(statusService))).revocation).toEqual(REFUSED);
    const statusListIssuers = { [entity.did]: [statusService.did] };
    expect((await verifyWith(cardsList(statusService, [3]), {}, { statusListIssuers })).revocation).toEqual(READ_REVOKED);
    const idless = cardsList(statusService, [], { statesId: false });
    expect((await verifyWith(idless, {}, { statusListIssuers })).revocation).toEqual(REFUSED);
  });
});
