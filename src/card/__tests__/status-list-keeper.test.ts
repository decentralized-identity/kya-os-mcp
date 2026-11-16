/**
 * Every status-list URL has one keeper, and a list is read for an entry only when the keeper of the
 * entry's URL signed it. A list's `id` binds it to a URL, but nothing in a list binds the URL to one
 * signer, so a verifier that read a list from any issuer it trusts for a hop let each of them speak
 * at every URL a hop names: the pinned root at a delegate's own URL, a configured status service
 * there too, and a delegate at the root's. The keeper is decided before any fetch from the
 * verifier's configuration and the signed credentials: the issuer `statusListIssuers` binds the URL
 * or its origin to, else the pinned root when the root's own credential names the URL, else the
 * hop's own issuer. Every case runs `evaluateDelegationChain`, `verifyRequestDelegation` and
 * `requireDelegation` (./status-list-paths.ts) over hops and lists signed by real keys.
 *
 * Acme (the root) grants the agent, the agent the sub-agent, the sub-agent the worker. Hop k has its
 * entry at index k.
 */
import { describe, expect, it } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import {
  AS_BOUND_ORIGIN,
  AS_BOUND_URL,
  AS_ISSUER,
  AS_ROOT,
  cast,
  expectAccepted,
  expectRevokedAt,
  listAt,
  listOf,
  listUrlOf,
  notKeeper,
  servedBy,
  threeHopChain,
} from './status-list-paths.js';

/** A URL the root's own credential is on, apart from the list the root keeps for its delegates. */
const ROOT_OWN = 'https://status.example/root-own';
/** A status service's lists, at an origin of its own. */
const SERVICE_ORIGIN = 'https://lists.service.example';
const SERVICE_LIST = `${SERVICE_ORIGIN}/herd/1`;

describe("a list at a hop issuer's own URL (the lead's cases A and B)", () => {
  it("A: the pinned root's list there is refused, where the agent's own list, which revokes the hop, is read", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const genuine = servedBy(listOf(c.acme), listOf(c.agent, [1]), listOf(c.subAgent));
    await expectRevokedAt(1, chain, genuine);
    const swapped = { ...genuine, [listUrlOf(c.agent)]: listAt(c.acme, listUrlOf(c.agent)) };
    await expectRevokedAt(1, chain, swapped, { pinned: true }, notKeeper(c.acme, c.agent, AS_ISSUER));
    await expectRevokedAt(1, chain, swapped, { pinned: false }, notKeeper(c.acme, c.agent, AS_ISSUER));
  });

  it("B: the list of an issuer the configuration binds elsewhere is refused there, by URL or by origin", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const genuine = servedBy(listOf(c.acme), listOf(c.agent, [1]), listOf(c.subAgent));
    const swapped = { ...genuine, [listUrlOf(c.agent)]: listAt(c.mallory, listUrlOf(c.agent)) };
    for (const binding of [SERVICE_LIST, SERVICE_ORIGIN, `${listUrlOf(c.agent)}/2`]) {
      const verifier = { pinned: false, statusListIssuers: { [c.mallory.did]: [binding] } };
      await expectRevokedAt(1, chain, genuine, verifier);
      await expectRevokedAt(1, chain, swapped, verifier, notKeeper(c.mallory, c.agent, AS_ISSUER));
    }
  });

  it("each issuer's own list at its own URL is read, with nobody else involved, pinned or not", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    for (const pinned of [true, false]) {
      await expectAccepted(chain, servedBy(listOf(c.acme), listOf(c.agent), listOf(c.subAgent)), { pinned });
      await expectRevokedAt(2, chain, servedBy(listOf(c.acme), listOf(c.agent), listOf(c.subAgent, [2])), { pinned });
    }
  });
});

describe("a hop on the root's list (the lead's cases C and D)", () => {
  it("D: is read from the root's list when the root's own credential names that list, and from nobody else's", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.acme, c.subAgent]);
    await expectAccepted(chain, servedBy(listOf(c.acme), listOf(c.subAgent)));
    await expectRevokedAt(1, chain, servedBy(listOf(c.acme, [1]), listOf(c.subAgent)));
    // The agent's list served there is refused at the root's own hop, which names the same URL.
    const swapped = { ...servedBy(listOf(c.subAgent)), [listUrlOf(c.acme)]: listAt(c.agent, listUrlOf(c.acme)) };
    await expectRevokedAt(0, chain, swapped, {}, notKeeper(c.agent, c.acme, AS_ROOT));
  });

  it("D: at the URL the root's credential names, the hop issuer's own list is refused for its own hop", async () => {
    const c = cast();
    // The root's credential names one list, and the agent's hop names it too.
    const chain = threeHopChain(c, [ROOT_OWN, ROOT_OWN, c.subAgent]);
    const lists = (signer: typeof c.acme) => ({ ...servedBy(listOf(c.subAgent)), [ROOT_OWN]: listAt(signer, ROOT_OWN) });
    await expectAccepted(chain, lists(c.acme));
    // Hop 0 is the root's own, so the agent's list fails there first; with no root pinned, hop 1 is the agent's own URL.
    await expectRevokedAt(0, chain, lists(c.agent), { pinned: true }, notKeeper(c.agent, c.acme, AS_ROOT));
    await expectRevokedAt(0, chain, lists(c.agent), { pinned: false }, notKeeper(c.agent, c.acme, AS_ISSUER));
    await expectRevokedAt(1, chain, lists(c.acme), { pinned: false }, notKeeper(c.acme, c.agent, AS_ISSUER));
  });

  describe("C: when the root's own credential names another URL", () => {
    // The root's credential is on ROOT_OWN. The agent's hop names the URL of the list the root in
    // fact keeps for its delegates, on which the root has revoked that hop.
    const c = cast();
    // The sub-agent keeps its list at another origin, so a binding of the root's origin leaves it alone.
    const SUB_AGENTS = 'https://lists.sub-agent.example/1';
    const chain = threeHopChain(c, [ROOT_OWN, c.acme, SUB_AGENTS]);
    const rootsUrl = listUrlOf(c.acme);
    const genuine = {
      ...servedBy(listOf(c.acme, [1])),
      [ROOT_OWN]: listAt(c.acme, ROOT_OWN),
      [SUB_AGENTS]: listAt(c.subAgent, SUB_AGENTS),
    };
    const swapped = { ...genuine, [rootsUrl]: listAt(c.agent, rootsUrl) };

    it.each([
      ['the exact URL', () => ({ [c.acme.did]: [rootsUrl] }), AS_BOUND_URL],
      ['its origin', () => ({ [c.acme.did]: ['https://status.example'] }), AS_BOUND_ORIGIN],
    ])('bound to the root by %s: C0, the revocation, is read, and C1, the agent\'s list served there, is refused', async (_label, bind, as) => {
      const verifier = { statusListIssuers: bind() };
      await expectRevokedAt(1, chain, genuine, verifier);
      await expectRevokedAt(1, chain, swapped, verifier, notKeeper(c.agent, c.acme, as));
      // With the hop's bit clear on the root's list, the chain passes.
      await expectAccepted(chain, { ...genuine, [rootsUrl]: listOf(c.acme) }, verifier);
    });

    it("bound to nobody: the URL is the agent's, since it is the agent's credential that names it", async () => {
      // Nothing the verifier holds says the URL is the root's: no binding, and the root's own
      // credential names another. So C0, the root's genuine list, is refused there (fail closed),
      // and C1, a list the agent signed there, is the agent's own list and is read.
      await expectRevokedAt(1, chain, genuine, {}, notKeeper(c.acme, c.agent, AS_ISSUER));
      await expectAccepted(chain, swapped);
      await expectRevokedAt(1, chain, { ...swapped, [rootsUrl]: listAt(c.agent, rootsUrl, [1]) });
    });
  });
});

describe('a URL the configuration binds', () => {
  it('to the root, once: several lists of one herd, each named by a delegate, are the root\'s', async () => {
    const c = cast();
    const [first, second] = ['https://herd.acme.example/1', 'https://herd.acme.example/2'];
    const chain = threeHopChain(c, [ROOT_OWN, first, second]);
    const lists = (onSecond: number[], signer = c.acme) => ({
      [ROOT_OWN]: listAt(c.acme, ROOT_OWN),
      [first]: listAt(c.acme, first),
      [second]: listAt(signer, second, onSecond),
    });
    for (const statusListIssuers of [{ [c.acme.did]: [first, second] }, { [c.acme.did]: ['https://herd.acme.example'] }]) {
      await expectAccepted(chain, lists([]), { statusListIssuers });
      await expectRevokedAt(2, chain, lists([2]), { statusListIssuers });
      await expectRevokedAt(2, chain, lists([], c.subAgent), { statusListIssuers });
    }
    // Unbound, each of those URLs is its hop issuer's, so the root's lists there are refused.
    await expectRevokedAt(1, chain, lists([]), {}, notKeeper(c.acme, c.agent, AS_ISSUER));
  });

  it.each([
    ['an exact URL', SERVICE_LIST, AS_BOUND_URL],
    ['an origin', SERVICE_ORIGIN, AS_BOUND_ORIGIN],
  ])('to a status service, as %s: its list is read there for any hop, and no other issuer\'s is', async (_label, binding, as) => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, SERVICE_LIST, SERVICE_LIST]);
    const statusListIssuers = { [c.mallory.did]: [binding] };
    const lists = (signer: typeof c.acme, revoked: number[] = []) => ({ ...servedBy(listOf(c.acme)), [SERVICE_LIST]: listAt(signer, SERVICE_LIST, revoked) });
    for (const pinned of [true, false]) {
      await expectAccepted(chain, lists(c.mallory), { pinned, statusListIssuers });
      await expectRevokedAt(2, chain, lists(c.mallory, [2]), { pinned, statusListIssuers });
      // The hop's own issuer, and the pinned root, are refused at a URL the service keeps.
      await expectRevokedAt(1, chain, lists(c.agent), { pinned, statusListIssuers }, notKeeper(c.agent, c.mallory, as));
      await expectRevokedAt(1, chain, lists(c.acme), { pinned, statusListIssuers }, notKeeper(c.acme, c.mallory, as));
    }
    // Without the binding the URL is each hop's own issuer's, and the service's list is refused.
    await expectRevokedAt(1, chain, lists(c.mallory), {}, notKeeper(c.mallory, c.agent, AS_ISSUER));
  });

  it.each([
    'https://lists.service.example.evil.example/herd/1',
    'https://lists.service.example@evil.example/herd/1',
    'https://lists.service.example:8443/herd/1',
    'https://LISTS.service.example/herd/1',
    'http://lists.service.example/herd/1',
  ])('by origin does not reach %s, which stays its hop issuer\'s', async (lookalike) => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, lookalike, c.subAgent]);
    const statusListIssuers = { [c.mallory.did]: [SERVICE_ORIGIN] };
    const lists = (signer: typeof c.acme) => ({ ...servedBy(listOf(c.acme), listOf(c.subAgent)), [lookalike]: listAt(signer, lookalike) });
    await expectRevokedAt(1, chain, lists(c.mallory), { statusListIssuers }, notKeeper(c.mallory, c.agent, AS_ISSUER));
    await expectAccepted(chain, lists(c.agent), { statusListIssuers });
  });

  it("decides over the root's credential: a URL both name is the configured issuer's", async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.acme, c.subAgent]);
    const statusListIssuers = { [c.mallory.did]: [listUrlOf(c.acme)] };
    const lists = (signer: typeof c.acme, revoked: number[] = []) => ({
      ...servedBy(listOf(c.subAgent)),
      [listUrlOf(c.acme)]: listAt(signer, listUrlOf(c.acme), revoked),
    });
    await expectAccepted(chain, lists(c.mallory), { statusListIssuers });
    await expectRevokedAt(1, chain, lists(c.mallory, [1]), { statusListIssuers });
    await expectRevokedAt(0, chain, lists(c.acme), { statusListIssuers }, notKeeper(c.acme, c.mallory, AS_BOUND_URL));
    // Without the binding the same list of the root's is read for both hops.
    await expectAccepted(chain, lists(c.acme));
  });
});

describe('the keeper is decided before any fetch', () => {
  it('resolves no DID for a list it refuses for its signer', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const swapped = { ...servedBy(listOf(c.acme), listOf(c.subAgent)), [listUrlOf(c.agent)]: listAt(c.mallory, listUrlOf(c.agent)) };
    const fetched: string[] = [];
    const resolved: string[] = [];
    const didKeys = createDidKeyResolver();
    const didResolver = {
      resolve: (did: string) => {
        resolved.push(did);
        return didKeys.resolve(did);
      },
    };
    await expectRevokedAt(1, chain, swapped, { fetched, didResolver });
    // Each of the three paths reads hop 0's list, then fetches hop 1's and stops.
    const perPath = [listUrlOf(c.acme), listUrlOf(c.agent)];
    expect(fetched).toEqual([...perPath, ...perPath, ...perPath]);
    expect(resolved).not.toContain(c.mallory.did);
  });
});
