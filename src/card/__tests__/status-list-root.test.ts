/**
 * A hop's status list may be its own issuer's, or the chain's root issuer's when the verifier pins
 * that root with `trustedRootIssuers` or `resourceOwner` (SPEC.md §6.6), and nobody else's unless
 * `statusListIssuers` accepts it for the hop's issuer. A hop commits to its parent only by an id its
 * parent's issuer chose, so whoever presents a chain decides who stands between the root and a hop:
 * only the pinned root is held to the verifier's own configuration. It can revoke its own credential,
 * which revokes every hop below it, so its list may speak for each of them when it states its URL as
 * its `id` (./status-list-id.test.ts). Every case runs the shipped checker, proof verifiers and chain
 * evaluators over hops and lists signed by real keys; only the network is faked.
 */

import { describe, it, expect, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { evaluateDelegationChain, revocationEntriesOf } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker, evaluateRevocationChain, type BitstringRevocationChecker } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import {
  hop,
  identity,
  NOW_MS,
  parties,
  RESOURCE,
  serveAt,
  STATUS_URL,
  statusList,
  twoHopChain,
  type TestIdentity,
} from './signed-chain-helpers.js';
import { cast, expectAccepted, expectRevokedAt, listOf, listUrlOf, servedBy, threeHopChain } from './status-list-paths.js';

const didResolver = createDidKeyResolver();
const now = () => NOW_MS;
const ctx = { resource: RESOURCE, now };

describe("the pinned root's list speaks for every hop of its chains", () => {
  it("reads a leaf entry on the root's list, as a two-hop chain carried by value documents it", async () => {
    const p = parties();
    const chain = twoHopChain(p);
    expect(chain[1].issuer).toBe(p.agent.did);
    expect(chain[1].credentialStatus).toMatchObject({ statusListCredential: STATUS_URL, statusListIndex: '7' });
    await expectAccepted(chain, { [STATUS_URL]: statusList(p.acme) });
    await expectRevokedAt(1, chain, { [STATUS_URL]: statusList(p.acme, [7]) });
  });

  it("reads the last hop's entry in a three-hop chain on the root's list", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.acme]);
    await expectAccepted(chain, servedBy(listOf(c.acme), listOf(c.agent)));
    await expectRevokedAt(2, chain, servedBy(listOf(c.acme, [2]), listOf(c.agent)));
  });

  it("reads each hop's entry on its own issuer's list, whether the root is pinned or not", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = (revoked: number[]) => servedBy(listOf(c.acme), listOf(c.agent, revoked), listOf(c.subAgent));
    for (const pinned of [true, false]) {
      await expectAccepted(chain, lists([]), { pinned });
      await expectRevokedAt(1, chain, lists([1]), { pinned });
    }
  });
});

describe("no other issuer's list does, unless statusListIssuers accepts it", () => {
  it("refuses a hop's entry on the list of an issuer between it and the root", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.agent]);
    const lists = (revoked: number[]) => servedBy(listOf(c.acme), listOf(c.agent, revoked));
    await expectRevokedAt(2, chain, lists([]));

    const statusListIssuers = { [c.subAgent.did]: [c.agent.did] };
    await expectAccepted(chain, lists([]), { statusListIssuers });
    await expectRevokedAt(2, chain, lists([2]), { statusListIssuers });
  });

  it('refuses a revoked hop grafted under a parent that a delegate of the root forged, whose list clears it', async () => {
    const c = cast();
    const AGENT_URL = 'https://agent.example/status/delegations';
    const genuineParent = hop({
      issuer: c.acme,
      invoker: c.agent.did,
      id: 'urn:zcap:acme-agent',
      parentCapability: RESOURCE,
      allowedAction: ['orders.place'],
      statusIndex: 3,
    });
    const revokedHop = hop({
      issuer: c.agent,
      invoker: c.worker.did,
      id: 'urn:zcap:agent-worker',
      parentCapability: 'urn:zcap:acme-agent',
      allowedAction: ['orders.place'],
      statusIndex: 7,
      statusListCredential: AGENT_URL,
    });
    // Mallory holds a genuine grant from the root, and issues a parent of her own under it with the
    // id the revoked hop names, so the hop links to it and Mallory stands above the hop.
    const malloryGrant = hop({
      issuer: c.acme,
      invoker: c.mallory.did,
      id: 'urn:zcap:acme-mallory',
      parentCapability: RESOURCE,
      allowedAction: ['orders.place'],
      statusIndex: 4,
    });
    const forgedParent = hop({
      issuer: c.mallory,
      invoker: c.agent.did,
      id: 'urn:zcap:acme-agent',
      parentCapability: 'urn:zcap:acme-mallory',
      allowedAction: ['orders.place'],
      statusIndex: 5,
    });
    const at = (list: Record<string, unknown>) => ({ [STATUS_URL]: statusList(c.acme), [AGENT_URL]: list });
    const agentsList = statusList(c.agent, [7], { id: AGENT_URL, credentialSubject: { id: `${AGENT_URL}#list` } });
    const mallorysList = statusList(c.mallory, [], { id: AGENT_URL, credentialSubject: { id: `${AGENT_URL}#list` } });

    for (const chain of [[genuineParent, revokedHop], [malloryGrant, forgedParent, revokedHop]]) {
      await expectRevokedAt(chain.length - 1, chain, at(agentsList));
      await expectRevokedAt(chain.length - 1, chain, at(mallorysList));
    }
    const agentsClearList = statusList(c.agent, [], { id: AGENT_URL, credentialSubject: { id: `${AGENT_URL}#list` } });
    await expectAccepted([genuineParent, revokedHop], at(agentsClearList));
  });

  it("refuses the root's list for every hop but the root's own when no root is pinned", async () => {
    const p = parties();
    const chain = twoHopChain(p);
    await expectRevokedAt(1, chain, { [STATUS_URL]: statusList(p.acme) }, { pinned: false });
    await expectRevokedAt(0, chain, { [STATUS_URL]: statusList(p.acme, [3]) }, { pinned: false });
    await expectAccepted(chain, { [STATUS_URL]: statusList(p.acme) }, { pinned: false, statusListIssuers: { [p.agent.did]: [p.acme.did] } });
  });

  it("refuses the root's entry on a list an issuer below it signed", async () => {
    const c = cast();
    for (const below of [c.agent, c.subAgent]) {
      const chain = threeHopChain(c, [below, c.agent, c.subAgent]);
      await expectRevokedAt(0, chain, servedBy(listOf(c.agent), listOf(c.subAgent)));
    }
  });

  it("refuses a hop's entry on a list its own delegate signed", async () => {
    const c = cast();
    const middle = threeHopChain(c, [c.acme, c.subAgent, c.subAgent]);
    expect(middle[1].credentialSubject.invoker).toBe(c.subAgent.did);
    await expectRevokedAt(1, middle, servedBy(listOf(c.acme), listOf(c.subAgent)));

    const leaf = threeHopChain(c, [c.acme, c.agent, c.worker]);
    expect(leaf[2].credentialSubject.invoker).toBe(c.worker.did);
    await expectRevokedAt(2, leaf, servedBy(listOf(c.acme), listOf(c.agent), listOf(c.worker)));
  });

  it('refuses an entry on a list an outsider signed, at any hop', async () => {
    const c = cast();
    const owners: [TestIdentity, TestIdentity, TestIdentity] = [c.acme, c.agent, c.subAgent];
    for (const k of [0, 1, 2]) {
      const withMallory = owners.map((owner, i) => (i === k ? c.mallory : owner)) as typeof owners;
      const lists = servedBy(listOf(c.acme), listOf(c.agent), listOf(c.subAgent), listOf(c.mallory));
      await expectRevokedAt(k, threeHopChain(c, withMallory), lists);
    }
  });

  it('refuses a list that names the pinned root when the root did not sign it', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.acme]);
    const forged = statusList(c.mallory, [], {
      id: listUrlOf(c.acme),
      issuer: c.acme.did,
      credentialSubject: { id: `${listUrlOf(c.acme)}#list` },
    });
    await expectRevokedAt(0, chain, servedBy(forged, listOf(c.agent)));
  });
});

describe("each path names a hop's issuer, and the chain's root only as the verifier pins it", () => {
  const statusOf = (k: number, owner: TestIdentity) => ({
    statusListCredential: listUrlOf(owner),
    statusListIndex: String(k),
    statusPurpose: 'revocation',
  });

  it('revocationEntriesOf pairs each hop that has a status entry with its issuer, and with the root it is given', () => {
    const c = cast();
    const [root, middle, leaf] = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const { credentialStatus: _status, ...unlisted } = middle;
    expect(revocationEntriesOf([root, middle, leaf])).toEqual([
      { entry: statusOf(0, c.acme), credentialIssuer: c.acme.did, position: 0 },
      { entry: statusOf(1, c.agent), credentialIssuer: c.agent.did, position: 1 },
      { entry: statusOf(2, c.subAgent), credentialIssuer: c.subAgent.did, position: 2 },
    ]);
    expect(revocationEntriesOf([root, unlisted as typeof middle, leaf], c.acme.did)).toEqual([
      { entry: statusOf(0, c.acme), credentialIssuer: c.acme.did, position: 0, trustedRootIssuer: c.acme.did },
      { entry: statusOf(2, c.subAgent), credentialIssuer: c.subAgent.did, position: 2, trustedRootIssuer: c.acme.did },
    ]);
  });

  it("revocationEntriesOf names no root that is not the chain's own", () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    for (const other of [c.agent.did, c.mallory.did, '']) {
      expect(revocationEntriesOf(chain, other).map((item) => Object.keys(item).sort())).toEqual([
        ['credentialIssuer', 'entry', 'position'],
        ['credentialIssuer', 'entry', 'position'],
        ['credentialIssuer', 'entry', 'position'],
      ]);
    }
    // A root whose issuer names no DID is not pinned either, by a root left unnamed as by any other.
    const [root, ...below] = chain;
    for (const issuer of [{ name: 'Acme' }, 7]) {
      const unnamed = [{ ...root, issuer }, ...below] as unknown as typeof chain;
      expect(revocationEntriesOf(unnamed).map((item) => Object.keys(item).sort())).toEqual([
        ['credentialIssuer', 'entry', 'position'],
        ['credentialIssuer', 'entry', 'position'],
        ['credentialIssuer', 'entry', 'position'],
      ]);
    }
  });

  it('evaluateRevocationChain hands the checker what a paired entry names, and no context for a bare or malformed one', async () => {
    const check = vi.fn<BitstringRevocationChecker>(async () => ({ revoked: false, fresh: true }));
    const entry = (index: number) => ({ statusListCredential: STATUS_URL, statusListIndex: String(index) });
    const paired = { credentialIssuer: 'did:web:b.example', trustedRootIssuer: 'did:web:a.example' };
    const unpaired = { entry: null, ...paired };
    await evaluateRevocationChain([{ entry: entry(1), ...paired }, entry(2), unpaired] as never, check);
    expect(check.mock.calls).toEqual([[entry(1), paired], [entry(2)], [unpaired]]);
  });

  it('evaluateRevocationChain refuses, and does not throw on, an item that is neither a status entry nor a paired one', async () => {
    const acme = identity();
    const check = createRevocationChecker({
      fetch: serveAt({ [STATUS_URL]: statusList(acme) }),
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    });
    for (const item of [{}, null, 'entry', { entry: null, credentialIssuer: acme.did }]) {
      const result = await evaluateRevocationChain([item] as never, check);
      expect(result).toEqual({
        ok: false,
        fresh: false,
        reasons: [expect.stringMatching(/^revocation: hop 0 \(list of type undefined, index of type undefined\) /)],
      });
    }
  });

  it('evaluateDelegationChain names the root only with resourceOwner, and verifyRequestDelegation only when it pins the root', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const issuers = [c.acme.did, c.agent.did, c.subAgent.did];
    const contexts = async (run: (check: BitstringRevocationChecker) => Promise<unknown>) => {
      const check = vi.fn<BitstringRevocationChecker>(async () => ({ revoked: false, fresh: true }));
      await run(check);
      return check.mock.calls.map(([, context]) => context);
    };
    const request = (deps: { trustedRootIssuers?: string[]; resourceOwner?: string }) =>
      (check: BitstringRevocationChecker) =>
        verifyRequestDelegation(
          { meta: toDelegationChainMeta(chain), proofDid: c.worker.did, action: 'orders.place' },
          { resource: RESOURCE, verifyHopProof: createDelegationProofVerifier({ didResolver }), checkRevocation: check, now, ...deps },
        );
    const unpinned = issuers.map((credentialIssuer) => ({ credentialIssuer }));
    const pinned = issuers.map((credentialIssuer) => ({ credentialIssuer, trustedRootIssuer: c.acme.did }));

    expect(await contexts((check) => evaluateDelegationChain(chain, check, ctx))).toEqual(unpinned);
    expect(await contexts((check) => evaluateDelegationChain(chain, check, { ...ctx, resourceOwner: c.acme.did }))).toEqual(pinned);
    expect(await contexts(request({}))).toEqual(unpinned);
    expect(await contexts(request({ trustedRootIssuers: [c.mallory.did, c.acme.did] }))).toEqual(pinned);
    expect(await contexts(request({ resourceOwner: c.acme.did }))).toEqual(pinned);
  });

  it('the checker reads a list from the root a direct call names, and from no other issuer it names', async () => {
    const c = cast();
    const check = createRevocationChecker({
      fetch: serveAt(servedBy(listOf(c.acme, [5]))),
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver }),
    });
    const onAcmes = (index: number) => ({ statusListCredential: listUrlOf(c.acme), statusListIndex: String(index) });
    const below = { credentialIssuer: c.subAgent.did, trustedRootIssuer: c.acme.did };
    expect(await check(onAcmes(5), below)).toEqual({ revoked: true, fresh: true });
    expect(await check(onAcmes(6), below)).toEqual({ revoked: false, fresh: true });
    for (const trustedRootIssuer of [undefined, c.agent.did, c.mallory.did]) {
      expect(await check(onAcmes(6), { credentialIssuer: c.subAgent.did, trustedRootIssuer })).toEqual({
        revoked: true,
        fresh: false,
      });
    }
  });
});
