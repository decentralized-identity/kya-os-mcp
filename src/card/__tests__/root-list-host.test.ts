/**
 * A pinned root's own status list may live on a private host, as an internal registry's does, when
 * that host is the root's own: the https origin, host and port, its did:web DID names. The URL is
 * the root's word once the root credential's proof has verified, so the shipped checker then reads
 * it as a URL the operator named, through SafeFetch, still pinned. A list on any other private host,
 * and any list of a root with no host of its own, such as a did:key root, is held to the
 * private-network rule as a URL a presenter names, unless `statusListIssuers` binds it. Before the
 * proof has verified, and wherever it did not verify or was not checked, the URL is only what
 * whoever presented the chain wrote, and SafeFetch refuses its private host before any connection.
 *
 * Every hop and list is signed by a real key and checked by the shipped verifiers. Only DNS and the
 * connection are faked: every name under `corp.example` resolves to a private address, and the
 * transport serves the lists and records each connection.
 */

import { describe, expect, it } from 'vitest';
import { createSafeFetch, type DnsLookup, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import type { StatusCheckContext } from '../../utils/statuslist-keeper.js';
import { evaluateDelegationChain, type DelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import type { EntityCard } from '../schema.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { verifyCard } from '../verify.js';
import {
  hop,
  identity,
  now,
  parties as didKeyParties,
  resolverServing,
  RESOURCE,
  statusList,
  webIdentity,
  type ChainParties,
  type TestIdentity,
} from './signed-chain-helpers.js';

const PRIVATE = '10.0.0.7';
/** The pinned root's own host, which its did:web DID names. */
const ROOT_DID = 'did:web:lists.corp.example';
const ROOT_LIST = 'https://lists.corp.example/acme';
const AGENT_LIST = 'https://lists.corp.example/agent';
/** A private host that is not the root's own. */
const REGISTRY_LIST = 'https://registry.corp.example/acme';

/** The did:web roots the tests make, whose documents the resolver serves, the newest first, since several share a DID. */
const webRoots: TestIdentity[] = [];
const didResolver = resolverServing(webRoots);

/** Acme, the root, as the did:web DID `rootDid` (by default one on {@link ROOT_LIST}'s host), and two did:key delegates. */
function parties(rootDid = ROOT_DID): ChainParties {
  const acme = webIdentity(rootDid);
  webRoots.unshift(acme);
  return { ...didKeyParties(), acme };
}

/** The list at `url` that `signer` signed, with `revoked` bits set. */
const listAt = (signer: TestIdentity, url: string, revoked: number[] = []) =>
  statusList(signer, revoked, { id: url, credentialSubject: { id: `${url}#list` } });

/** A redirect the network answers in place of a list. */
type Moved = { readonly location: string };

/** A network on which every name under corp.example is private, serving `lists` and recording each connection. */
function network(lists: Record<string, Record<string, unknown> | Moved>) {
  const connected: [string, string][] = [];
  const looked: string[] = [];
  const lookup: DnsLookup = async (name) => {
    looked.push(name);
    return [{ address: name.endsWith('corp.example') ? PRIVATE : '93.184.216.34', family: 4 }];
  };
  const transport: SafeFetchTransport = async (url, init) => {
    connected.push([url, init.pinnedAddress]);
    const body = lists[url];
    if (body !== undefined && 'location' in body) {
      const { location } = body as Moved;
      return { status: 302, headers: { get: (name) => (name === 'location' ? location : null) }, text: async () => '' };
    }
    return { status: body ? 200 : 404, headers: { get: () => null }, text: async () => JSON.stringify(body ?? {}) };
  };
  const checker = (more: { statusListIssuers?: Record<string, string[]> } = {}) =>
    createRevocationChecker({
      fetch: createSafeFetch({ lookup, transport }), now, verifyStatusList: createStatusListProofVerifier({ didResolver }), ...more,
    });
  return { connected, looked, checker };
}

/** Acme's root grant to the agent, on Acme's list at `rootList`, and the agent's grant on `leafList`. */
function chainOn(p: ChainParties, rootList: string, leafList: string, signer: TestIdentity = p.acme): DelegationChain {
  return [
    hop({
      issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:acme-root', parentCapability: RESOURCE,
      allowedAction: ['orders.place'], statusIndex: 3, statusListCredential: rootList, signer,
    }),
    hop({
      issuer: p.agent, invoker: p.subAgent.did, id: 'urn:zcap:agent-leaf', parentCapability: 'urn:zcap:acme-root',
      allowedAction: ['orders.place'], statusIndex: 7, statusListCredential: leafList,
    }),
  ];
}

const verifyHopProof = createDelegationProofVerifier({ didResolver });

describe("a pinned root's own list on a private host", () => {
  it('is read, pinned, once every hop proof has verified, for each hop on that list', async () => {
    const p = parties();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST) });
    const chain = chainOn(p, ROOT_LIST, ROOT_LIST);
    const verdict = await evaluateDelegationChain(chain, net.checker(), { resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof });
    expect(verdict).toMatchObject({ ok: true, fresh: true });
    expect(net.connected).toEqual([[ROOT_LIST, PRIVATE], [ROOT_LIST, PRIVATE]]);

    const request = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
      { resource: RESOURCE, now, trustedRootIssuers: [p.acme.did], verifyHopProof, checkRevocation: net.checker() },
    );
    expect(request).toMatchObject({ ok: true });
    expect(net.connected).toHaveLength(4);
  });

  it('holds a redirect from that list to any other URL as one a presenter named, decided hop by hop', async () => {
    const p = parties();
    const MOVED = 'https://lists.corp.example/acme-moved';
    const net = network({ [ROOT_LIST]: { location: MOVED }, [MOVED]: listAt(p.acme, MOVED) });
    const verdict = await evaluateDelegationChain(chainOn(p, ROOT_LIST, ROOT_LIST), net.checker(), {
      resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof,
    });
    expect(verdict).toMatchObject({ ok: false, reasons: [expect.stringMatching(/^revocation: hop 0 /)] });
    expect(net.connected).toEqual([[ROOT_LIST, PRIVATE]]);
  });

  it('is refused before any connection when the hop proofs were not checked', async () => {
    const p = parties();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST) });
    const verdict = await evaluateDelegationChain(chainOn(p, ROOT_LIST, ROOT_LIST), net.checker(), {
      resource: RESOURCE, now, resourceOwner: p.acme.did,
    });
    expect(verdict).toMatchObject({ ok: false, code: 'status_unavailable' });
    expect(net.connected).toEqual([]);
  });

  it('makes no connection for a forged root: a credential claiming the pinned root names a private list, and its proof fails', async () => {
    const p = parties();
    const forger = identity();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST) });
    const forged = chainOn(p, ROOT_LIST, ROOT_LIST, forger);
    const verdict = await evaluateDelegationChain(forged, net.checker(), { resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof });
    expect(verdict).toMatchObject({ ok: false, code: 'invalid_proof' });
    const request = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(forged), proofDid: p.subAgent.did, action: 'orders.place' },
      { resource: RESOURCE, now, trustedRootIssuers: [p.acme.did], verifyHopProof, checkRevocation: net.checker() },
    );
    expect(request).toMatchObject({ ok: false, code: 'delegation_invalid', refusalCode: 'invalid_proof' });
    expect({ connected: net.connected, looked: net.looked }).toEqual({ connected: [], looked: [] });
  });

  it.each([
    ['a did:key root, which has no host of its own', () => didKeyParties(), ROOT_LIST],
    ["a did:web root, on a private host other than its own", () => parties(), REGISTRY_LIST],
    ["a did:web root, on its own host name at another port", () => parties(), 'https://lists.corp.example:8443/acme'],
    ["a did:web root with a port, on its own host name at the default port", () => parties('did:web:lists.corp.example%3A8443'), ROOT_LIST],
    ['a did:web root, on a host under its own', () => parties(), 'https://status.lists.corp.example/acme'],
  ])('refuses the list of %s before any connection, its proof verified', async (_case, cast, url) => {
    const p = cast();
    const net = network({ [url]: listAt(p.acme, url) });
    const chain = chainOn(p, url, url);
    const verdict = await evaluateDelegationChain(chain, net.checker(), { resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof });
    expect(verdict).toMatchObject({ ok: false, code: 'status_unavailable', reasons: [expect.stringMatching(/^revocation: hop 0 /)] });
    const request = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
      { resource: RESOURCE, now, trustedRootIssuers: [p.acme.did], verifyHopProof, checkRevocation: net.checker() },
    );
    expect(request).toMatchObject({ ok: false });
    expect(net.connected).toEqual([]);
  });

  it.each([
    ['its own host and port, which its DID names', 'did:web:lists.corp.example%3A8443', 'https://lists.corp.example:8443/acme'],
    ['its own host, whatever path its DID names', 'did:web:lists.corp.example:tenants:acme', ROOT_LIST],
  ])('reads the list of a did:web root on %s', async (_case, rootDid, url) => {
    const p = parties(rootDid);
    const net = network({ [url]: listAt(p.acme, url) });
    const verdict = await evaluateDelegationChain(chainOn(p, url, url), net.checker(), { resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof });
    expect(verdict).toMatchObject({ ok: true, fresh: true });
    expect(net.connected).toEqual([[url, PRIVATE], [url, PRIVATE]]);
  });

  it('reads the list of a did:key root, or of a root on another host, that statusListIssuers binds', async () => {
    for (const [p, url] of [[didKeyParties(), ROOT_LIST], [parties(), REGISTRY_LIST]] as const) {
      const net = network({ [url]: listAt(p.acme, url) });
      const checker = net.checker({ statusListIssuers: { [p.acme.did]: [url] } });
      const verdict = await evaluateDelegationChain(chainOn(p, url, url), checker, { resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof });
      expect(verdict).toMatchObject({ ok: true, fresh: true });
      expect(net.connected).toEqual([[url, PRIVATE], [url, PRIVATE]]);
    }
  });

  it("refuses a hop's own private list before any connection, the root's proof verified or not", async () => {
    const p = parties();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST), [AGENT_LIST]: listAt(p.agent, AGENT_LIST) });
    const verdict = await evaluateDelegationChain(chainOn(p, ROOT_LIST, AGENT_LIST), net.checker(), {
      resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof,
    });
    expect(verdict).toMatchObject({ ok: false, code: 'status_unavailable', reasons: [expect.stringMatching(/^revocation: hop 1 /)] });
    expect(net.connected).toEqual([[ROOT_LIST, PRIVATE]]);
  });

  it('honours no mark a caller writes into a context, nor one copied from data', async () => {
    const p = parties();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST) });
    const entry = { statusListCredential: ROOT_LIST, statusListIndex: '3', statusPurpose: 'revocation' };
    const pinned = { credentialIssuer: p.acme.did, trustedRootIssuer: p.acme.did, trustedRootStatusList: ROOT_LIST };
    for (const trustedRootVerified of [{}, Object.freeze(Object.create(null) as object), JSON.parse('{"verified":true}') as object]) {
      const context = { ...pinned, trustedRootVerified } as unknown as StatusCheckContext;
      expect(await net.checker()(entry, context)).toMatchObject({ revoked: true, fresh: false, code: 'status_unavailable' });
    }
    expect(net.connected).toEqual([]);
  });
});

describe('a list statusListIssuers binds on a private host', () => {
  it('is read, pinned, as the operator named it, whether or not the hop proofs were checked', async () => {
    const p = parties();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST), [AGENT_LIST]: listAt(p.agent, AGENT_LIST) });
    const checker = net.checker({ statusListIssuers: { [p.agent.did]: [AGENT_LIST] } });
    const verdict = await evaluateDelegationChain(chainOn(p, ROOT_LIST, AGENT_LIST), checker, {
      resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof,
    });
    expect(verdict).toMatchObject({ ok: true });
    expect(net.connected).toEqual([[ROOT_LIST, PRIVATE], [AGENT_LIST, PRIVATE]]);
  });

  it.each([
    ['its host in upper case', 'https://LISTS.corp.example/agent'],
    ['a /./ in its path', 'https://lists.corp.example/./agent'],
  ])('is refused before any connection where a credential names it with %s, as the keeper does not bind that spelling', async (_case, spelled) => {
    const p = parties();
    const net = network({ [ROOT_LIST]: listAt(p.acme, ROOT_LIST), [AGENT_LIST]: listAt(p.agent, AGENT_LIST) });
    const checker = net.checker({ statusListIssuers: { [p.agent.did]: [AGENT_LIST] } });
    const verdict = await evaluateDelegationChain(chainOn(p, ROOT_LIST, spelled), checker, {
      resource: RESOURCE, now, resourceOwner: p.acme.did, verifyHopProof,
    });
    expect(verdict).toMatchObject({ ok: false });
    expect(net.connected).toEqual([[ROOT_LIST, PRIVATE]]);
  });
});

describe("a Card's responsible party", () => {
  const CARDS_LIST = 'https://lists.corp.example/cards';
  const cardOf = (p: ChainParties): EntityCard => ({
    id: p.agent.did, entityType: 'agent', name: 'Agent', kid: `${p.agent.did}#key-1`, capabilities: ['handshake'],
    responsibleParty: p.acme.did, principal: 'did:web:example.com:users:alice', delegationRef: 'urn:zcap:acme-root',
    revocation: { statusListCredential: CARDS_LIST, statusListIndex: '3' },
  });

  it('has its own list read on a private host once accountability verified it as a root trustedRootIssuers pins, and refused before any connection otherwise', async () => {
    const p = parties();
    for (const [verified, trustedRootIssuers, read] of [
      [true, [p.acme.did], true],
      [false, [p.acme.did], false],
      // Verified, but the host pins no root, or another one, or this one spelled another way: the URL is the presenter's word.
      [true, undefined, false],
      [true, [p.agent.did], false],
      [true, [`${p.acme.did.slice(0, 8)}${p.acme.did.slice(8).toUpperCase()}`], false],
    ] as const) {
      const net = network({ [CARDS_LIST]: listAt(p.acme, CARDS_LIST) });
      const result = await verifyCard(cardOf(p), {
        accountabilityVerifier: async () => ({ verified, rootStatusList: CARDS_LIST }),
        statusListChecker: net.checker(),
        ...(trustedRootIssuers === undefined ? {} : { trustedRootIssuers }),
      });
      expect(result.revocation).toMatchObject(read ? { revoked: false, fresh: true } : { revoked: true, fresh: false });
      if (verified) expect(result).toMatchObject(read ? { ok: true } : { ok: false, code: 'status_unavailable' });
      expect(net.connected).toEqual(read ? [[CARDS_LIST, PRIVATE]] : []);
    }
  });

  it('refuses a trustedRootIssuers that is not a list of DIDs, naming the option', async () => {
    const p = parties();
    await expect(verifyCard(cardOf(p), { trustedRootIssuers: p.acme.did as never })).rejects.toThrow(
      /^\[kya-os\] VerifyCardDeps\.trustedRootIssuers must be an array of DIDs/,
    );
  });
});
