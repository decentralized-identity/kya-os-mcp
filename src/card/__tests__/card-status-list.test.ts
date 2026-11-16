/**
 * Who may sign the status list a Card's `revocation` entry names (SPEC-ENTITY-CARD.md §10.3): the
 * one keeper of the entry's URL. That is the issuer `statusListIssuers` binds the URL or its origin
 * to, and otherwise the Card's Entity, its `id`. The Card's responsible party, once the
 * accountability check has verified it as the root issuer of the Card's delegation chain (§10.2), is
 * named to the checker as that root, with no status-list URL of its own, so its list counts for the
 * Card only at a URL the configuration binds to it: served at the Card's own list URL it is refused.
 * The Entity is the Card's own issuer, so its list may state no `id` when no responsible party is
 * verified and nobody else is configured. Otherwise every list is read only when it states, as its
 * `id`, the URL it was fetched from.
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
import { issuerDidDocument, methodOf } from '../../__tests__/utils/did-documents.js';
import type { DIDResolver } from '../../delegation/vc-verifier.types.js';
import {
  hop,
  identity,
  published,
  RESOURCE,
  serveAt,
  signEddsaJcs2022,
  statusList,
  type TestIdentity,
  now,
} from './signed-chain-helpers.js';
import { moveBinding, nameSigner } from './status-list-paths.js';

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
    return party ? issuerDidDocument(methodOf(published(party))) : null;
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

/**
 * The same policy, also reporting `rootStatusList` as the list URL the root credential of the
 * Card's chain names, whatever the chain itself states: the report is what `verifyCard` reads.
 */
function reportingRootList(rootStatusList: unknown, chain = chainFrom(responsibleParty)): AccountabilityVerifier {
  const verify = accountableThrough(chain);
  return async (c, ctx) => {
    const verdict = (await verify(c, ctx)) as object;
    return { ...verdict, rootStatusList } as never;
  };
}

const READ_CLEAR = { revoked: false, fresh: true };
const READ_REVOKED = { revoked: true, fresh: true };
const REFUSED = { revoked: true, fresh: false, reason: expect.any(String) as string };

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
  /** The verifier's configuration binds the Card's list URL to the responsible party. */
  const boundToParty = { statusListIssuers: { [responsibleParty.did]: [CARDS_URL] } };

  it('signs a list that is read at a URL the configuration binds to it, when it states that URL as its id', async () => {
    const clear = await verifyWith(cardsList(responsibleParty), {}, boundToParty);
    expect(clear.accountability).toMatchObject({ responsibleParty: responsibleParty.did, verified: true });
    expect(clear).toMatchObject({ ok: true, revocation: READ_CLEAR });
    expect(await verifyWith(cardsList(responsibleParty, [3]), {}, boundToParty)).toMatchObject({ ok: false, revocation: READ_REVOKED });
    const origin = { statusListIssuers: { [responsibleParty.did]: [/^https:\/\/[^/]+/.exec(CARDS_URL)![0]] } };
    expect(await verifyWith(cardsList(responsibleParty), {}, origin)).toMatchObject({ ok: true, revocation: READ_CLEAR });
  });

  it("signs a list that is refused at the Card's own list URL, which nothing binds to it, though it is verified", async () => {
    const result = await verifyWith(cardsList(responsibleParty));
    expect(result.accountability).toMatchObject({ responsibleParty: responsibleParty.did, verified: true });
    expect(result).toMatchObject({ ok: false });
    expect(result.revocation).toStrictEqual({
      revoked: true,
      fresh: false,
      reason:
        `status list issuer "${responsibleParty.did}" does not keep this list's URL: "${entity.did}" does, as the issuer of the credential` +
        nameSigner(responsibleParty.did, 'https://example.com/'),
    });
  });

  it("keeps the Entity's own list out of a URL the configuration binds to it", async () => {
    const result = await verifyWith(cardsList(entity), {}, boundToParty);
    expect(result.revocation).toStrictEqual({
      revoked: true,
      fresh: false,
      reason:
        `status list issuer "${entity.did}" does not keep this list's URL: "${responsibleParty.did}" does, as the issuer statusListIssuers binds this URL to` +
        moveBinding(entity.did, CARDS_URL),
    });
  });

  it('signs a list that is refused when it states no id', async () => {
    const result = await verifyWith(cardsList(responsibleParty, [], { statesId: false }), {}, boundToParty);
    expect(result).toMatchObject({ ok: false, revocation: REFUSED });
  });

  it("signs a list that is read at the Card's own list URL once accountability reports it as the URL the root credential names", async () => {
    const reported = { accountabilityVerifier: reportingRootList(CARDS_URL) };
    const clear = await verifyWith(cardsList(responsibleParty), reported);
    expect(clear.accountability).toMatchObject({ responsibleParty: responsibleParty.did, verified: true, rootStatusList: CARDS_URL });
    expect(clear).toMatchObject({ ok: true, revocation: READ_CLEAR });
    expect(await verifyWith(cardsList(responsibleParty, [3]), reported)).toMatchObject({ ok: false, revocation: READ_REVOKED });
    expect((await verifyWith(cardsList(entity), reported)).revocation).toStrictEqual({
      revoked: true,
      fresh: false,
      reason:
        `status list issuer "${entity.did}" does not keep this list's URL: "${responsibleParty.did}" does, as the pinned root whose own credential names it` +
        nameSigner(entity.did, 'https://example.com/'),
    });
    expect(await verifyWith(cardsList(responsibleParty, [], { statesId: false }), reported)).toMatchObject({ ok: false, revocation: REFUSED });
  });

  it.each<[string, unknown]>([
    ['another URL', 'https://example.com/status/root'],
    ['a URL that differs from it in case', CARDS_URL.toUpperCase()],
    ['an empty string', ''],
    ['a number', 7],
    ['an array holding the URL', [CARDS_URL]],
    ['an object', { url: CARDS_URL }],
    ['null', null],
  ])("keeps no list at the Card's own list URL when accountability reports %s", async (_label, rootStatusList) => {
    const result = await verifyWith(cardsList(responsibleParty), { accountabilityVerifier: reportingRootList(rootStatusList) });
    expect(result.accountability).toMatchObject({ verified: true });
    expect(result.revocation).toStrictEqual({
      revoked: true,
      fresh: false,
      reason:
        `status list issuer "${responsibleParty.did}" does not keep this list's URL: "${entity.did}" does, as the issuer of the credential` +
        nameSigner(responsibleParty.did, 'https://example.com/'),
    });
  });

  it('lets the configuration decide over the URL accountability reports', async () => {
    const boundToService = { statusListIssuers: { [statusService.did]: [CARDS_URL] } };
    const reported = { accountabilityVerifier: reportingRootList(CARDS_URL) };
    expect(await verifyWith(cardsList(statusService), reported, boundToService)).toMatchObject({ ok: true, revocation: READ_CLEAR });
    expect(await verifyWith(cardsList(responsibleParty), reported, boundToService)).toMatchObject({ ok: false, revocation: REFUSED });
  });

  it('is named with the URL accountability reports only when it is verified and the URL is a string', async () => {
    const check = vi.fn(createRevocationChecker({ fetch: serveAt({}), now }));
    const run = (accountabilityVerifier: AccountabilityVerifier) => verifyCard(card, { accountabilityVerifier, statusListChecker: check });
    await run(reportingRootList(CARDS_URL));
    await run(reportingRootList(7));
    await run(reportingRootList(''));
    await run(reportingRootList(CARDS_URL, chainFrom(anotherRoot)));
    await run(async () => ({ verified: 'true', rootStatusList: CARDS_URL }) as never);
    const root = { credentialIssuer: entity.did, trustedRootIssuer: responsibleParty.did };
    expect(check.mock.calls).toStrictEqual([
      [card.revocation, { ...root, trustedRootStatusList: CARDS_URL }],
      [card.revocation, root],
      [card.revocation, root],
      [card.revocation, { credentialIssuer: entity.did }],
      [card.revocation, { credentialIssuer: entity.did }],
    ]);
    const unverified = await run(reportingRootList(CARDS_URL, chainFrom(anotherRoot)));
    expect(unverified.accountability).not.toHaveProperty('rootStatusList');
  });

  it('takes the URL only from the one read of verified, so a getter that turns cannot name it', async () => {
    const check = vi.fn(createRevocationChecker({ fetch: serveAt({}), now }));
    const reads = { verified: 0, rootStatusList: 0 };
    const turning = {
      get verified() {
        reads.verified += 1;
        return reads.verified !== 1;
      },
      get rootStatusList() {
        reads.rootStatusList += 1;
        return CARDS_URL;
      },
    };
    const result = await verifyCard(card, { accountabilityVerifier: async () => turning as never, statusListChecker: check });
    expect(result.accountability).toMatchObject({ verified: false });
    expect(result.accountability).not.toHaveProperty('rootStatusList');
    expect(check.mock.calls).toStrictEqual([[card.revocation, { credentialIssuer: entity.did }]]);
    expect(reads).toEqual({ verified: 1, rootStatusList: 1 });
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

  it('signs a list that is read when it states no id only while no responsible party is verified and nobody is configured', async () => {
    const idless = (revoked: number[]) => cardsList(entity, revoked, { statesId: false });
    const alone = { accountabilityVerifier: undefined };
    expect((await verifyWith(idless([]), alone)).revocation).toEqual(READ_CLEAR);
    expect((await verifyWith(idless([3]), alone)).revocation).toEqual(READ_REVOKED);
    expect((await verifyWith(idless([]))).revocation).toEqual(REFUSED);
    const statusListIssuers = { [statusService.did]: ['https://lists.elsewhere.example'] };
    expect((await verifyWith(idless([]), alone, { statusListIssuers })).revocation).toEqual(REFUSED);
  });

  it("is a third party whose list is refused, unless statusListIssuers binds the Card's list URL to it and it states its id", async () => {
    expect((await verifyWith(cardsList(statusService))).revocation).toEqual(REFUSED);
    const statusListIssuers = { [statusService.did]: [CARDS_URL] };
    expect((await verifyWith(cardsList(statusService, [3]), {}, { statusListIssuers })).revocation).toEqual(READ_REVOKED);
    const idless = cardsList(statusService, [], { statesId: false });
    expect((await verifyWith(idless, {}, { statusListIssuers })).revocation).toEqual(REFUSED);
  });
});
