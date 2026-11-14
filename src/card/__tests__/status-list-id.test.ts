/**
 * W3C Bitstring Status List v1.0 §2.2 makes a list's `id` optional, but the `id` is all that binds a
 * list to the URL it is served at. A hop's own issuer may leave it out only when it is the one issuer
 * the verifier accepts for the hop, so its list can stand in only for another list that issuer
 * signed. Where the verifier also accepts the chain's pinned root, or an issuer `statusListIssuers`
 * accepts for the hop's issuer, every list must state, as its `id`, the URL it was fetched from:
 * otherwise a list of one of them, with the hop's bit clear, could be served at the URL of another's
 * list and clear the hop's revocation there. Every case runs every shipped path
 * (./status-list-paths.ts).
 */

import { describe, it } from 'vitest';
import { identity, statusList } from './signed-chain-helpers.js';
import {
  cast,
  expectAccepted,
  expectRevokedAt,
  idlessListOf,
  listOf,
  listUrlOf,
  servedBy,
  threeHopChain,
} from './status-list-paths.js';

describe("the pinned root's list that states no id", () => {
  it("does not stand in for the list of a hop below the root, at that list's URL", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const atAgents = (list: Record<string, unknown>) => ({
      ...servedBy(listOf(c.acme), listOf(c.subAgent)),
      [listUrlOf(c.agent)]: list,
    });
    await expectRevokedAt(1, chain, atAgents(listOf(c.agent, [1])));
    for (const pinned of [true, false]) {
      await expectRevokedAt(1, chain, atAgents(idlessListOf(c.acme)), { pinned });
    }
  });

  it("is not read for a hop below the root even at the root's own URL, where the root's list stating that URL is", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.acme]);
    await expectAccepted(chain, servedBy(listOf(c.acme), listOf(c.agent)));
    await expectRevokedAt(2, chain, { ...servedBy(listOf(c.agent)), [listUrlOf(c.acme)]: idlessListOf(c.acme) });
  });

  it("is read for the root's own credential, whether the root is pinned or not", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = (revoked: number[]) => ({
      ...servedBy(listOf(c.agent), listOf(c.subAgent)),
      [listUrlOf(c.acme)]: idlessListOf(c.acme, revoked),
    });
    for (const pinned of [true, false]) {
      await expectAccepted(chain, lists([]), { pinned });
      await expectRevokedAt(0, chain, lists([0]), { pinned });
    }
  });
});

describe("a hop issuer's own list that states no id", () => {
  /** Another list of acme's, the pinned root's, at a URL of its own. */
  const ROOT_LIST = 'https://status.example/root-list-2';

  it('is read for each hop it issued, when its issuer is the one issuer the verifier accepts for the hop', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = (revoked: number[]) => ({
      ...servedBy(listOf(c.acme), listOf(c.subAgent)),
      [listUrlOf(c.agent)]: idlessListOf(c.agent, revoked),
    });
    await expectAccepted(chain, lists([]), { pinned: false });
    await expectRevokedAt(1, chain, lists([1]), { pinned: false });
  });

  it('is refused for the hop when the verifier pins the root or accepts another issuer for the hop', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = { ...servedBy(listOf(c.acme), listOf(c.subAgent)), [listUrlOf(c.agent)]: idlessListOf(c.agent) };
    await expectRevokedAt(1, chain, lists);
    await expectRevokedAt(1, chain, lists, { pinned: false, statusListIssuers: { [c.agent.did]: [identity().did] } });
  });

  it("does not stand in for the pinned root's list, at that list's URL", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, ROOT_LIST, c.subAgent]);
    const atRootList = (list: Record<string, unknown>) => ({ ...servedBy(listOf(c.acme), listOf(c.subAgent)), [ROOT_LIST]: list });
    await expectAccepted(chain, atRootList(statusList(c.acme, [], { id: ROOT_LIST })));
    await expectRevokedAt(1, chain, atRootList(statusList(c.acme, [1], { id: ROOT_LIST })));
    await expectRevokedAt(1, chain, atRootList(idlessListOf(c.agent)));
  });

  it("does not stand in for the list of an issuer statusListIssuers accepts for the hop, at that list's URL", async () => {
    const c = cast();
    const service = identity();
    const chain = threeHopChain(c, [c.acme, service, c.subAgent]);
    const verifier = { pinned: false, statusListIssuers: { [c.agent.did]: [service.did] } };
    const atServices = (list: Record<string, unknown>) => ({ ...servedBy(listOf(c.acme), listOf(c.subAgent)), [listUrlOf(service)]: list });
    await expectAccepted(chain, atServices(listOf(service)), verifier);
    await expectRevokedAt(1, chain, atServices(listOf(service, [1])), verifier);
    await expectRevokedAt(1, chain, atServices(idlessListOf(c.agent)), verifier);
  });
});

describe('the list of an issuer statusListIssuers accepts for a hop, when it states no id', () => {
  it('is not read for the hop, where the same list stating its URL is', async () => {
    const c = cast();
    const service = identity();
    const chain = threeHopChain(c, [c.acme, service, c.subAgent]);
    const statusListIssuers = { [c.agent.did]: [service.did] };
    const atServices = (list: Record<string, unknown>) => ({
      ...servedBy(listOf(c.acme), listOf(c.subAgent)),
      [listUrlOf(service)]: list,
    });
    await expectAccepted(chain, atServices(listOf(service)), { statusListIssuers });
    await expectRevokedAt(1, chain, atServices(listOf(service, [1])), { statusListIssuers });
    await expectRevokedAt(1, chain, atServices(idlessListOf(service)), { statusListIssuers });
  });

  it("does not stand in for the hop issuer's own list, at that list's URL", async () => {
    const c = cast();
    const service = identity();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const statusListIssuers = { [c.agent.did]: [service.did] };
    const atAgents = (list: Record<string, unknown>) => ({
      ...servedBy(listOf(c.acme), listOf(c.subAgent)),
      [listUrlOf(c.agent)]: list,
    });
    await expectRevokedAt(1, chain, atAgents(listOf(c.agent, [1])), { statusListIssuers });
    await expectRevokedAt(1, chain, atAgents(idlessListOf(service)), { statusListIssuers });
  });
});
