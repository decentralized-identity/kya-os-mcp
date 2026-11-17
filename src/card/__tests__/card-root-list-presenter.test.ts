/**
 * A host that accepts any root, as `verifyRequestDelegation` does under `allowAnyRootIssuer: true`,
 * lets the presenter be the root of its own chain, and so choose the URL its root credential names.
 * When such a host's accountability verifier reports that URL as `rootStatusList`, as UPGRADING.md
 * says it may, `verifyCard` must not read it as the operator's own: only a root the operator pins in
 * `trustedRootIssuers` makes it so, as on the delegation paths. Otherwise the URL is held to the
 * private-network rule as any URL a presenter names, so a name that resolves to a public address
 * once, and to a private one when the Card's own entry is read, is refused at the second lookup.
 *
 * Real keys and the shipped verifiers throughout. Only DNS and the connection are faked: the
 * presenter's list host resolves to a public address the first time and a private one after.
 */

import { describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { logger } from '../../logging/index.js';
import { createSafeFetch, type DnsLookup, type SafeFetchTransport } from '../../utils/safe-fetch.js';
import { evaluateDelegationChain, type DelegationChain } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import type { EntityCard } from '../schema.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { verifyCard } from '../verify.js';
import { hop, now, parties, RESOURCE, statusList, type ChainParties, type TestIdentity } from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const verifyHopProof = createDelegationProofVerifier({ didResolver });
const PUBLIC = '93.184.216.34';
const PRIVATE = '10.0.0.7';
const HOST = 'lists.presenter.example';
const LIST = `https://${HOST}/root`;

const listAt = (signer: TestIdentity, url: string) => statusList(signer, [], { id: url, credentialSubject: { id: `${url}#list` } });

/** A network whose DNS answers `HOST` with a public address the first time and a private one after, serving `lists` and recording each connection. */
function rebindingNetwork(lists: Record<string, Record<string, unknown>>) {
  const connected: [string, string][] = [];
  let asked = 0;
  const lookup: DnsLookup = async (name) => [{ address: name === HOST && asked++ > 0 ? PRIVATE : PUBLIC, family: 4 }];
  const transport: SafeFetchTransport = async (url, init) => {
    connected.push([url, init.pinnedAddress]);
    const body = lists[url];
    return { status: body ? 200 : 404, headers: { get: () => null }, text: async () => JSON.stringify(body ?? {}) };
  };
  const checker = () =>
    createRevocationChecker({ fetch: createSafeFetch({ lookup, transport }), now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });
  return { connected, checker };
}

/** The presenter's own chain: its root grants its agent, on the root's own list at `LIST`. */
const presenterChain = (p: ChainParties): DelegationChain => [
  hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:root', parentCapability: RESOURCE, allowedAction: ['orders.place'], statusIndex: 3, statusListCredential: LIST }),
  hop({ issuer: p.agent, invoker: p.subAgent.did, id: 'urn:zcap:leaf', parentCapability: 'urn:zcap:root', allowedAction: ['orders.place'] }),
];

const cardOf = (p: ChainParties): EntityCard => ({
  id: p.agent.did, entityType: 'agent', name: 'Agent', kid: `${p.agent.did}#key-1`, capabilities: ['handshake'],
  responsibleParty: p.acme.did, principal: 'did:web:example.com:users:alice', delegationRef: 'urn:zcap:root',
  revocation: { statusListCredential: LIST, statusListIndex: '3' },
});

/** `verifyCard` under a host whose accountability verifier accepts any root and reports the root's list URL. */
async function verifyUnderAnyRoot(p: ChainParties, trustedRootIssuers?: readonly string[]) {
  const chain = presenterChain(p);
  const net = rebindingNetwork({ [LIST]: listAt(p.acme, LIST) });
  const accountabilityVerifier = async () => {
    const result = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
      { resource: RESOURCE, now, allowAnyRootIssuer: true, verifyHopProof, checkRevocation: net.checker() },
    );
    return { verified: result.ok, rootStatusList: LIST };
  };
  const result = await verifyCard(cardOf(p), {
    accountabilityVerifier,
    statusListChecker: net.checker(),
    ...(trustedRootIssuers === undefined ? {} : { trustedRootIssuers }),
  });
  return { result, connected: net.connected };
}

describe('a Card whose responsible party is the presenter, under a host that accepts any root', () => {
  it("never reads the presenter's list URL at the private address its name resolves to the second time", async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const { result, connected } = await verifyUnderAnyRoot(parties());
    expect(result.accountability).toMatchObject({ verified: true, rootStatusList: LIST });
    expect(connected).toEqual([[LIST, PUBLIC]]);
    expect(result.revocation).toMatchObject({ revoked: true, fresh: false, code: 'status_unavailable' });
  });

  it('reads it there once the operator pins that party in trustedRootIssuers, as the delegation paths do', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const p = parties();
    const { result, connected } = await verifyUnderAnyRoot(p, [p.acme.did]);
    expect(connected).toEqual([[LIST, PUBLIC], [LIST, PRIVATE]]);
    expect(result.revocation).toMatchObject({ revoked: false, fresh: true });
  });
});

describe('the delegation paths, which mark only a root the operator pins', () => {
  it('gives a presenter root under allowAnyRootIssuer no exemption in verifyRequestDelegation', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const p = parties();
    const chain = presenterChain(p);
    const net = rebindingNetwork({ [LIST]: listAt(p.acme, LIST) });
    for (let read = 0; read < 2; read += 1) {
      await verifyRequestDelegation(
        { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
        { resource: RESOURCE, now, allowAnyRootIssuer: true, verifyHopProof, checkRevocation: net.checker() },
      );
    }
    expect(net.connected).toEqual([[LIST, PUBLIC]]);
  });

  it('gives a chain whose proofs verified, with no resourceOwner, no exemption in evaluateDelegationChain', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const p = parties();
    const net = rebindingNetwork({ [LIST]: listAt(p.acme, LIST) });
    for (let read = 0; read < 2; read += 1) {
      await evaluateDelegationChain(presenterChain(p), net.checker(), { resource: RESOURCE, now, verifyHopProof });
    }
    expect(net.connected).toEqual([[LIST, PUBLIC]]);
  });
});
