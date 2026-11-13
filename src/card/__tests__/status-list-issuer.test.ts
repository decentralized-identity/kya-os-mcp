/**
 * A status list is read for a credential only when its issuer is one the verifier accepts for that
 * credential (W3C Bitstring Status List v1.0 §3.2), its purpose is the entry's, and its `id` is, byte
 * for byte, the URL it was fetched from, which only the credential's own issuer's list may leave out,
 * when no other issuer is accepted for the credential.
 * A list's proof shows only who signed it, so a list served at the status URL and validly signed by
 * any other resolvable DID, with the bit cleared, must not clear a revocation on any path that
 * verifies a list's proof. A chain's pinned root, and the issuers between it and a hop, are covered
 * in ./status-list-root.test.ts, and a list that states no `id` in ./status-list-id.test.ts.
 */

import { describe, it, expect, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { evaluateDelegationChain, revocationEntriesOf, statusEntryOf } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import {
  createRevocationChecker,
  evaluateRevocationChain,
  type RevocationCheckerDeps,
  type RevocationStatus,
} from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { verifyCard } from '../verify.js';
import { BitstringStatusListEntrySchema, type EntityCard } from '../schema.js';
import {
  hop,
  identity,
  NOW_MS,
  parties,
  RESOURCE,
  serve,
  serveAt,
  signEddsaJcs2022,
  STATUS_URL,
  statusList,
  twoHopChain,
  type TestIdentity,
} from './signed-chain-helpers.js';

const didResolver = createDidKeyResolver();
const now = () => NOW_MS;
const ctx = { resource: RESOURCE, now };

/** The shipped checker with the shipped proof verifier, reading whatever the status URL serves. */
function checkerServing(list: Record<string, unknown>, deps: Partial<RevocationCheckerDeps> = {}) {
  return createRevocationChecker({
    fetch: serve(list),
    now,
    verifyStatusList: createStatusListProofVerifier({ didResolver }),
    ...deps,
  });
}

const entry = (index: number) => ({ statusListCredential: STATUS_URL, statusListIndex: String(index) });
const issuedBy = (party: TestIdentity) => ({ credentialIssuer: party.did });

const REVOKED_UNPROVEN: RevocationStatus = { revoked: true, fresh: false };

function cardOf(entity: TestIdentity): EntityCard {
  return {
    id: entity.did,
    entityType: 'agent',
    name: 'Acme agent',
    revocation: { statusListCredential: STATUS_URL, statusListIndex: '3' },
  };
}

describe('a status list signed by another DID does not clear a revocation', () => {
  it('evaluateDelegationChain reads the root as revoked', async () => {
    const p = parties();
    const mallory = identity();
    const result = await evaluateDelegationChain(twoHopChain(p), checkerServing(statusList(mallory)), ctx);
    expect(result.ok).toBe(false);
    expect(result.reasons).toEqual([expect.stringMatching(/^revocation: hop 0 /)]);
  });

  it('verifyRequestDelegation rejects the carried chain as delegation_revoked', async () => {
    const p = parties();
    const mallory = identity();
    const result = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(twoHopChain(p)), proofDid: p.subAgent.did, action: 'orders.place' },
      {
        resource: RESOURCE,
        verifyHopProof: createDelegationProofVerifier({ didResolver }),
        checkRevocation: checkerServing(statusList(mallory)),
        now,
      },
    );
    expect(result).toMatchObject({ ok: false, code: 'delegation_revoked' });
  });

  it('verifyCard reads the card as revoked', async () => {
    const acme = identity();
    const mallory = identity();
    const result = await verifyCard(cardOf(acme), { statusListChecker: checkerServing(statusList(mallory)) });
    expect(result.revocation).toEqual(REVOKED_UNPROVEN);
    expect(result.ok).toBe(false);
  });

  it("verifyCard names the card's id, and reads a list the card's entity signed", async () => {
    const acme = identity();
    const check = vi.fn(checkerServing(statusList(acme, [3])));
    const revoked = await verifyCard(cardOf(acme), { statusListChecker: check });
    expect(revoked.revocation).toEqual({ revoked: true, fresh: true });
    expect(check.mock.calls).toEqual([[cardOf(acme).revocation, issuedBy(acme)]]);
    const clear = await verifyCard(cardOf(acme), { statusListChecker: checkerServing(statusList(acme)) });
    expect(clear.revocation).toEqual({ revoked: false, fresh: true });
  });
});

describe('createRevocationChecker holds a verified list to the credential', () => {
  it("reads a list its issuer signed, with the issuer written as a string or as an object's id", async () => {
    const acme = identity();
    for (const list of [statusList(acme, [3]), statusList(acme, [3], { issuer: { id: acme.did, name: 'Acme' } })]) {
      const check = checkerServing(list);
      expect(await check(entry(3), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
      expect(await check(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    }
  });

  it('fails closed on a list another DID issued and signed, written either way, before checking its proof', async () => {
    const acme = identity();
    const mallory = identity();
    const verifyStatusList = vi.fn(createStatusListProofVerifier({ didResolver }));
    for (const list of [statusList(mallory), statusList(mallory, [], { issuer: { id: mallory.did } })]) {
      expect(await checkerServing(list, { verifyStatusList })(entry(4), issuedBy(acme))).toEqual(REVOKED_UNPROVEN);
    }
    expect(verifyStatusList).not.toHaveBeenCalled();
  });

  it('reads a list from an issuer statusListIssuers accepts for the credential issuer, and only for it', async () => {
    const acme = identity();
    const statusService = identity();
    const check = checkerServing(statusList(statusService, [3]), {
      statusListIssuers: { [acme.did]: [statusService.did] },
    });
    expect(await check(entry(3), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
    expect(await check(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    expect(await check(entry(4), issuedBy(identity()))).toEqual(REVOKED_UNPROVEN);
  });

  it('fails closed on a list whose id names another URL, and reads one that states no id', async () => {
    const acme = identity();
    const elsewhere = statusList(acme, [], { id: 'https://acme.example/status/other' });
    expect(await checkerServing(elsewhere)(entry(4), issuedBy(acme))).toEqual(REVOKED_UNPROVEN);

    const { id: _id, proof: _proof, ...withoutId } = statusList(acme, [3]);
    const check = checkerServing(signEddsaJcs2022(withoutId, acme));
    expect(await check(entry(3), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
    expect(await check(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
  });

  it('fails closed on a list whose id is a prefix of its URL, or differs from it only in the query', async () => {
    const acme = identity();
    const url = 'https://resolver.example/1.0/identifiers/did:example:acme?resourceName=revocation-a&resourceType=StatusList';
    const stating = (id: string) =>
      createRevocationChecker({
        fetch: serveAt({ [url]: statusList(acme, [], { id }) }),
        now,
        verifyStatusList: createStatusListProofVerifier({ didResolver }),
      });
    const onList = { statusListCredential: url, statusListIndex: '3' };
    expect(await stating(url)(onList, issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    for (const id of [url.slice(0, url.indexOf('?')), url.replace('revocation-a', 'revocation-b'), 'https://resolver.example/']) {
      expect(await stating(id)(onList, issuedBy(acme))).toEqual(REVOKED_UNPROVEN);
    }
  });

  it('reads a list that states no id wherever it is served, so it binds the list to no URL', async () => {
    const acme = identity();
    const other = 'https://acme.example/status/other';
    const { id: _id, proof: _proof, ...anotherList } = statusList(acme, [], { credentialSubject: { id: `${other}#list` } });
    expect(await checkerServing(signEddsaJcs2022(anotherList, acme))(entry(3), issuedBy(acme))).toEqual({
      revoked: false,
      fresh: true,
    });
  });

  it('fails closed on a list of another purpose, and reads one whose purposes include its own', async () => {
    const acme = identity();
    const suspension = statusList(acme, [], { credentialSubject: { statusPurpose: 'suspension' } });
    expect(await checkerServing(suspension)(entry(4), issuedBy(acme))).toEqual(REVOKED_UNPROVEN);

    const both = statusList(acme, [3], { credentialSubject: { statusPurpose: ['suspension', 'revocation'] } });
    expect(await checkerServing(both)(entry(3), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
    expect(await checkerServing(both)(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    expect(await checkerServing(both, { statusPurpose: 'suspension' })(entry(4), issuedBy(acme))).toEqual({
      revoked: false,
      fresh: true,
    });
  });

  it("holds a list to the checker's configured statusPurpose, verified or not", async () => {
    const acme = identity();
    const suspension = statusList(acme, [3], { credentialSubject: { statusPurpose: 'suspension' } });
    const revocation = statusList(acme, [3]);
    expect(await checkerServing(suspension, { statusPurpose: 'suspension' })(entry(3), issuedBy(acme))).toEqual({
      revoked: true,
      fresh: true,
    });
    expect(await checkerServing(revocation, { statusPurpose: 'suspension' })(entry(3), issuedBy(acme))).toEqual(
      REVOKED_UNPROVEN,
    );
    const unverified = (list: Record<string, unknown>) =>
      createRevocationChecker({ fetch: serve(list), now, statusPurpose: 'suspension' });
    expect(await unverified(suspension)(entry(3))).toEqual({ revoked: true, fresh: true });
    expect(await unverified(revocation)(entry(3))).toEqual(REVOKED_UNPROVEN);
  });
});

// Verifiable Credentials Status List v2021 §2.2 has a StatusList2021 list state one purpose, and
// Bitstring Status List v1.0 §2.2 lets a list typed as one in both places state several.
describe("a list's statusPurpose takes the form its type allows", () => {
  const BOTH = ['suspension', 'revocation'];
  const STATUS_LIST_2021 = ['VerifiableCredential', 'StatusList2021Credential'];
  const unverified = (list: Record<string, unknown>) => createRevocationChecker({ fetch: serve(list), now });
  /** Lists not typed as a Bitstring Status List in both places, by the members that type them. */
  const ONE_STRING: [string, { type?: string[]; subjectType: string }][] = [
    ['a StatusList2021 list', { type: STATUS_LIST_2021, subjectType: 'StatusList2021' }],
    ['a BitstringStatusListCredential whose subject is a StatusList2021', { subjectType: 'StatusList2021' }],
    ['a StatusList2021Credential whose subject is a BitstringStatusList', { type: STATUS_LIST_2021, subjectType: 'BitstringStatusList' }],
  ];
  /** `signer`'s list, typed as `typing` says, stating `statusPurpose`, with no bit set. */
  const typedList = (signer: TestIdentity, { type, subjectType }: { type?: string[]; subjectType: string }, statusPurpose: unknown) =>
    statusList(signer, [], { ...(type === undefined ? {} : { type }), credentialSubject: { type: subjectType, statusPurpose } });

  it('reads a purpose array on a list typed as a Bitstring Status List in both places, verified or not', async () => {
    const acme = identity();
    const both = statusList(acme, [3], { credentialSubject: { statusPurpose: BOTH } });
    expect(await checkerServing(both)(entry(3), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
    expect(await checkerServing(both)(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    expect(await unverified(both)(entry(3))).toEqual({ revoked: true, fresh: true });
    expect(await unverified(both)(entry(4))).toEqual({ revoked: false, fresh: true });
  });

  it.each(ONE_STRING)('holds %s to one string, verified or not', async (_list, typing) => {
    const acme = identity();
    for (const statusPurpose of [BOTH, ['revocation']]) {
      const array = typedList(acme, typing, statusPurpose);
      expect(await checkerServing(array)(entry(4), issuedBy(acme))).toEqual(REVOKED_UNPROVEN);
      expect(await unverified(array)(entry(4))).toEqual(REVOKED_UNPROVEN);
    }
    const one = typedList(acme, typing, 'revocation');
    expect(await checkerServing(one)(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    expect(await unverified(one)(entry(4))).toEqual({ revoked: false, fresh: true });
  });

  it('evaluateDelegationChain fails closed on a chain whose StatusList2021 list states its purposes in an array', async () => {
    const p = parties();
    const chain = twoHopChain(p);
    const pinned = { ...ctx, resourceOwner: p.acme.did };
    const [, typing] = ONE_STRING[0]!;
    const result = await evaluateDelegationChain(chain, checkerServing(typedList(p.acme, typing, BOTH)), pinned);
    expect(result.ok).toBe(false);
    expect(result.reasons).toEqual([expect.stringMatching(/^revocation: hop 0 /)]);
    const read = await evaluateDelegationChain(chain, checkerServing(typedList(p.acme, typing, 'revocation')), pinned);
    expect(read).toMatchObject({ ok: true, fresh: true });
  });
});

describe("an entry's own statusPurpose", () => {
  const stating = (index: number, statusPurpose: string) => ({ ...entry(index), statusPurpose });

  it("reads an entry that states the checker's purpose like one that states none", async () => {
    const acme = identity();
    const check = checkerServing(statusList(acme, [3]));
    expect(await check(stating(3, 'revocation'), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
    expect(await check(stating(4, 'revocation'), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
    const suspensions = checkerServing(statusList(acme, [3], { credentialSubject: { statusPurpose: 'suspension' } }), {
      statusPurpose: 'suspension',
    });
    expect(await suspensions(stating(3, 'suspension'), issuedBy(acme))).toEqual({ revoked: true, fresh: true });
  });

  it('fails closed before any fetch on an entry that states another purpose, verified or not, whatever it states', async () => {
    const acme = identity();
    // A list that tracks both purposes would otherwise answer the suspension entry's bit as revocation.
    const both = statusList(acme, [], { credentialSubject: { statusPurpose: ['suspension', 'revocation'] } });
    const fetch = vi.fn(serve(both));
    const verified = createRevocationChecker({ fetch, now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });
    const unverified = createRevocationChecker({ fetch, now });
    const named = JSON.parse('{"toString":"revocation"}') as string;
    const notStrings = [null, 7, false, ['revocation'], { revocation: true }] as unknown as string[];
    for (const purpose of ['suspension', '', 's'.repeat(100_000), named, ...notStrings]) {
      expect(await verified(stating(4, purpose), issuedBy(acme))).toEqual(REVOKED_UNPROVEN);
      expect(await unverified(stating(4, purpose))).toEqual(REVOKED_UNPROVEN);
    }
    expect(fetch).not.toHaveBeenCalled();
    expect(await verified(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
  });

  it('statusEntryOf projects a hop onto a Bitstring Status List entry, which states no purpose', () => {
    const p = parties();
    const [root] = twoHopChain(p);
    expect(root.credentialStatus?.statusPurpose).toBe('revocation');
    expect(statusEntryOf(root)).toEqual(entry(3));
    expect(BitstringStatusListEntrySchema.safeParse(statusEntryOf(root)).success).toBe(true);
  });

  it("revocationEntriesOf carries a hop's statusPurpose to the checker, so a hop of another purpose fails closed", async () => {
    const p = parties();
    const [root, leaf] = twoHopChain(p);
    expect(revocationEntriesOf([root])[0]?.entry).toEqual({ ...entry(3), statusPurpose: 'revocation' });
    const both = statusList(p.acme, [], { credentialSubject: { statusPurpose: ['suspension', 'revocation'] } });
    expect(await evaluateDelegationChain([root, leaf], checkerServing(both), { ...ctx, resourceOwner: p.acme.did })).toMatchObject({
      ok: true,
    });

    for (const statusPurpose of ['suspension', '', null]) {
      const credentialStatus = { ...root.credentialStatus, statusPurpose };
      const { proof: _proof, ...unsigned } = { ...root, credentialStatus } as Record<string, unknown>;
      const restated = signEddsaJcs2022(unsigned, p.acme) as unknown as typeof root;
      expect(revocationEntriesOf([restated])[0]?.entry).toEqual({ ...entry(3), statusPurpose });
      const result = await evaluateDelegationChain([restated, leaf], checkerServing(both), ctx);
      expect(result.ok).toBe(false);
      expect(result.reasons).toEqual([expect.stringMatching(/^revocation: hop 0 /)]);
    }
  });

  it("revocationEntriesOf leaves out a purpose the hop does not state, so the checker's applies", () => {
    const p = parties();
    const credentialStatus = { type: 'BitstringStatusListEntry', statusListIndex: '3', statusListCredential: STATUS_URL };
    const unstated = hop({ issuer: p.acme, invoker: p.agent.did, id: 'urn:zcap:x', parentCapability: RESOURCE, allowedAction: ['orders.place'] });
    expect(revocationEntriesOf([{ ...unstated, credentialStatus } as typeof unstated])[0]?.entry).toEqual(entry(3));
  });
});

describe('a call that names no credential issuer', () => {
  it('fails closed before any fetch when the checker verifies list proofs', async () => {
    const acme = identity();
    const fetch = vi.fn(serve(statusList(acme)));
    const check = createRevocationChecker({ fetch, now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });
    expect(await check(entry(4))).toEqual(REVOKED_UNPROVEN);
    expect(await check(entry(4), { credentialIssuer: '' })).toEqual(REVOKED_UNPROVEN);
    expect(await check(entry(4), { credentialIssuer: '', trustedRootIssuer: acme.did })).toEqual(REVOKED_UNPROVEN);
    expect(fetch).not.toHaveBeenCalled();
    expect(await check(entry(4), issuedBy(acme))).toEqual({ revoked: false, fresh: true });
  });

  it("reads the credential issuer as a credential's issuer member names one, failing closed before any fetch on one that names no DID", async () => {
    const acme = identity();
    const fetch = vi.fn(serve(statusList(acme)));
    const check = createRevocationChecker({ fetch, now, verifyStatusList: createStatusListProofVerifier({ didResolver }) });
    for (const credentialIssuer of [7, true, [acme.did], { id: 7 }, { id: [acme.did] }] as unknown as string[]) {
      expect(await check(entry(4), { credentialIssuer })).toEqual(REVOKED_UNPROVEN);
    }
    expect(fetch).not.toHaveBeenCalled();
    expect(await check(entry(4), { credentialIssuer: { id: acme.did } as unknown as string })).toEqual({ revoked: false, fresh: true });
  });

  it('revocationEntriesOf names no issuer for a hop whose issuer names no DID, so the checker gets no context for it', async () => {
    const p = parties();
    const [root, leaf] = twoHopChain(p);
    for (const issuer of [null, 7, [p.acme.did], { id: 7 }]) {
      const unnamed = { ...root, issuer } as unknown as typeof root;
      const entries = revocationEntriesOf([unnamed, leaf], p.acme.did);
      expect(entries.map(({ credentialIssuer, trustedRootIssuer }) => [credentialIssuer, trustedRootIssuer])).toEqual([
        [undefined, undefined],
        [p.agent.did, undefined],
      ]);
      const contexts: unknown[] = [];
      const recording = async (_entry: unknown, context?: unknown): Promise<RevocationStatus> => {
        contexts.push(context);
        return { revoked: false, fresh: true };
      };
      await evaluateRevocationChain(entries, recording);
      expect(contexts).toEqual([undefined, { credentialIssuer: p.agent.did }]);
    }
  });

  it('fails closed for a bare entry in evaluateRevocationChain when the checker verifies list proofs', async () => {
    const acme = identity();
    const result = await evaluateRevocationChain([entry(4)], checkerServing(statusList(acme)));
    expect(result).toMatchObject({ ok: false, fresh: false });
    const paired = await evaluateRevocationChain([{ entry: entry(4), credentialIssuer: acme.did }], checkerServing(statusList(acme)));
    expect(paired).toEqual({ ok: true, fresh: true, reasons: [] });
  });

  it('reads the list as before when the checker verifies no proof, since nothing about it is authenticated', async () => {
    const mallory = identity();
    const check = createRevocationChecker({ fetch: serve(statusList(mallory, [3])), now });
    expect(await check(entry(3))).toEqual({ revoked: true, fresh: true });
    expect(await check(entry(4))).toEqual({ revoked: false, fresh: true });
    expect(await check(entry(4), issuedBy(identity()))).toEqual({ revoked: false, fresh: true });
  });
});

describe('statusListIssuers is checked when the checker is created', () => {
  const verifyStatusList = createStatusListProofVerifier({ didResolver });
  const create = (statusListIssuers: unknown, deps: Partial<RevocationCheckerDeps> = { verifyStatusList }) => () =>
    createRevocationChecker({ fetch: serve(undefined), statusListIssuers: statusListIssuers as never, ...deps });

  it('refuses it without verifyStatusList, since no list could then be held to it', () => {
    expect(create({}, {})).toThrow(new TypeError('statusListIssuers is set but verifyStatusList is not, so no status list is held to an issuer'));
    expect(create(undefined, {})).not.toThrow();
  });

  it('refuses a value that is not a plain object, null included', () => {
    for (const value of [null, [], 'did:web:status.example', 7, new Map(), new (class Issuers {})()]) {
      expect(create(value)).toThrow(
        new TypeError('statusListIssuers must be a plain object mapping credential issuer DIDs to arrays of status-list issuer DIDs'),
      );
    }
  });

  it('refuses an entry that is not an array of strings, naming its key', () => {
    for (const value of ['did:web:status.example', null, [7], ['did:web:status.example', null], { 0: 'did:web:status.example' }]) {
      expect(create({ 'did:web:acme.example': [], 'did:web:agent.example': value })).toThrow(
        new TypeError('statusListIssuers["did:web:agent.example"] must be an array of status-list issuer DIDs'),
      );
    }
  });

  it('quotes the key of an entry it refuses as a refusal quotes a value: bounded, and on one line', () => {
    const key = `did:web:${'k'.repeat(292)}\u2028`;
    expect(create({ [key]: 'did:web:status.example' })).toThrow(
      new TypeError(`statusListIssuers["did:web:${'k'.repeat(56)}"...] must be an array of status-list issuer DIDs`),
    );
    expect(create({ 'did:web:acme.example\u2028': null })).toThrow(
      new TypeError('statusListIssuers["did:web:acme.example\\u2028"] must be an array of status-list issuer DIDs'),
    );
  });

  it('takes a plain object of string arrays, however it was made', () => {
    const bare = Object.assign(Object.create(null) as Record<string, string[]>, { 'did:web:acme.example': ['did:web:status.example'] });
    for (const value of [undefined, {}, { 'did:web:acme.example': [] }, Object.freeze({ 'did:web:acme.example': Object.freeze(['did:web:s.example']) }), bare]) {
      expect(create(value)).not.toThrow();
    }
  });
});
