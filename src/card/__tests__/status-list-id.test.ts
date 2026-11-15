/**
 * W3C Bitstring Status List v1.0 §2.2 makes a list's `id` optional, but the `id` is all that binds a
 * list to the URL it is served at. A hop's own issuer may leave it out only when nobody else keeps
 * any URL, so its list can stand in only for another list that issuer signed. Where the verifier
 * pins the chain's root, or `statusListIssuers` names any other issuer, every list must state, as
 * its `id`, the URL it was fetched from: otherwise a list an issuer signed for one URL it keeps,
 * with the hop's bit clear, could be served at another. A root's list at the URL its own credential
 * names is the root's by that credential, not by default, so it states its `id` as well. Every case
 * runs every shipped path
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

  it("is read for no hop at the root's own URL while the root is pinned, where the root's list stating that URL is read for each", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.acme]);
    await expectAccepted(chain, servedBy(listOf(c.acme), listOf(c.agent)));
    await expectRevokedAt(2, chain, servedBy(listOf(c.acme, [2]), listOf(c.agent)));
    await expectRevokedAt(0, chain, { ...servedBy(listOf(c.agent)), [listUrlOf(c.acme)]: idlessListOf(c.acme) });
  });

  it("is read for the root's own credential only while the root is not pinned, and for no hop below it", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = (revoked: number[]) => ({
      ...servedBy(listOf(c.agent), listOf(c.subAgent)),
      [listUrlOf(c.acme)]: idlessListOf(c.acme, revoked),
    });
    await expectAccepted(chain, lists([]), { pinned: false });
    await expectRevokedAt(0, chain, lists([0]), { pinned: false });
    // Pinned, the root keeps that URL because its own credential names it, and such a list states its id.
    await expectRevokedAt(0, chain, lists([]), { pinned: true });
    await expectAccepted(chain, servedBy(listOf(c.acme), listOf(c.agent), listOf(c.subAgent)), { pinned: true });
  });
});

describe("a hop issuer's own list that states no id", () => {
  /** Another list of acme's, the pinned root's, at a URL of its own. */
  const ROOT_LIST = 'https://status.example/root-list-2';

  it('is read for each hop it issued, when no root is pinned and nobody is configured', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = (revoked: number[]) => ({
      ...servedBy(listOf(c.acme), listOf(c.subAgent)),
      [listUrlOf(c.agent)]: idlessListOf(c.agent, revoked),
    });
    await expectAccepted(chain, lists([]), { pinned: false });
    await expectRevokedAt(1, chain, lists([1]), { pinned: false });
  });

  it('is refused for the hop when the verifier pins the root or its configuration names another issuer', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = { ...servedBy(listOf(c.acme), listOf(c.subAgent)), [listUrlOf(c.agent)]: idlessListOf(c.agent) };
    await expectRevokedAt(1, chain, lists);
    await expectRevokedAt(1, chain, lists, { pinned: false, statusListIssuers: { [identity().did]: ['https://lists.elsewhere.example'] } });
    await expectRevokedAt(1, chain, lists, { pinned: false, statusListIssuers: { [identity().did]: [] } });
  });

  it("does not stand in for the pinned root's list, at a URL the configuration binds to the root", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, ROOT_LIST, c.subAgent]);
    const verifier = { statusListIssuers: { [c.acme.did]: [ROOT_LIST] } };
    const atRootList = (list: Record<string, unknown>) => ({ ...servedBy(listOf(c.acme), listOf(c.subAgent)), [ROOT_LIST]: list });
    await expectAccepted(chain, atRootList(statusList(c.acme, [], { id: ROOT_LIST })), verifier);
    await expectRevokedAt(1, chain, atRootList(statusList(c.acme, [1], { id: ROOT_LIST })), verifier);
    await expectRevokedAt(1, chain, atRootList(idlessListOf(c.agent)), verifier);
    await expectRevokedAt(1, chain, atRootList(statusList(c.agent, [], { id: ROOT_LIST })), verifier);
  });

  it("does not stand in for the list of an issuer statusListIssuers binds the hop's URL to", async () => {
    const c = cast();
    const service = identity();
    const chain = threeHopChain(c, [c.acme, service, c.subAgent]);
    const verifier = { pinned: false, statusListIssuers: { [service.did]: [listUrlOf(service)] } };
    const atServices = (list: Record<string, unknown>) => ({ ...servedBy(listOf(c.acme), listOf(c.subAgent)), [listUrlOf(service)]: list });
    await expectAccepted(chain, atServices(listOf(service)), verifier);
    await expectRevokedAt(1, chain, atServices(listOf(service, [1])), verifier);
    await expectRevokedAt(1, chain, atServices(idlessListOf(c.agent)), verifier);
  });
});

describe("the list of an issuer statusListIssuers binds a hop's URL to, when it states no id", () => {
  it('is not read for the hop, where the same list stating its URL is', async () => {
    const c = cast();
    const service = identity();
    const chain = threeHopChain(c, [c.acme, service, c.subAgent]);
    const statusListIssuers = { [service.did]: [listUrlOf(service)] };
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
    const statusListIssuers = { [service.did]: [listUrlOf(service)] };
    const atAgents = (list: Record<string, unknown>) => ({
      ...servedBy(listOf(c.acme), listOf(c.subAgent)),
      [listUrlOf(c.agent)]: list,
    });
    await expectRevokedAt(1, chain, atAgents(listOf(c.agent, [1])), { statusListIssuers });
    await expectRevokedAt(1, chain, atAgents(idlessListOf(service)), { statusListIssuers });
  });
});
