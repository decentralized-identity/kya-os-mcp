/**
 * A status checker an adopter wraps and calls with the status entry alone. The library tells every
 * status-list resolver and checker it calls which credential the entry belongs to, as a second
 * argument that TypeScript lets a wrapper drop. So each call also hands over a fresh copy of the
 * entry that carries that context, out of sight of JSON and of any enumeration, and the library's
 * own checkers read it there when no second argument is given. A wrapper that forwards the entry it
 * was given then keeps working, through the delegation verifier, the chain's revocation walk and
 * Entity Card verification alike. Every test uses the package's public exports, as an adopter would.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { DelegationCredentialVerifier, type CredentialStatus, type StatusListResolver } from '../../index.js';
import { withStatusCache } from '../../delegation/index.js';
import {
  createRevocationChecker,
  createStatusListProofVerifier,
  evaluateRevocationChain,
  verifyCard,
  type BitstringRevocationChecker,
  type BitstringStatusListEntry,
  type EntityCard,
} from '../index.js';
import { documentsOf, servingFromMemory, signedStatusList, webParty, type WebParty } from '../../__tests__/utils/adopter-issuers.js';
import { credentialJwt, delegationRecord, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { codedAs } from '../../__tests__/utils/refusal-coding.js';

const LIST_URL = 'https://issuer.example/status/1';
const CLEAR = 3;
const REVOKED = 7;

let issuer: WebParty;
let other: WebParty;
let checker: BitstringRevocationChecker;
beforeAll(async () => {
  [issuer, other] = await Promise.all([webParty('did:web:issuer.example'), webParty('did:web:other.example')]);
  checker = createRevocationChecker({
    fetch: servingFromMemory({ [LIST_URL]: await signedStatusList(issuer, LIST_URL, [REVOKED]) }),
    verifyStatusList: createStatusListProofVerifier({ didResolver: documentsOf(issuer, other) }),
  });
});

/** A credential's status entry at `index` of the list at {@link LIST_URL}. */
const entryAt = (index: number): CredentialStatus => ({
  id: `${LIST_URL}#${index}`,
  type: 'BitstringStatusListEntry',
  statusPurpose: 'revocation',
  statusListIndex: String(index),
  statusListCredential: LIST_URL,
});

/**
 * An adopter's resolver over the library's checker, written before the checker took a context: it
 * calls the checker with the entry alone, and throws when the checker could not prove the status.
 */
function wrapping(check: BitstringRevocationChecker): StatusListResolver & { seen: unknown[] } {
  const seen: unknown[] = [];
  return {
    seen,
    async checkStatus(status) {
      seen.push(status);
      const verdict = await check(status as unknown as BitstringStatusListEntry);
      if (verdict.revoked && !verdict.fresh) throw new Error(verdict.reason ?? 'status list unavailable');
      return verdict.revoked;
    },
  };
}

/** What the delegation verifier says of a VC-JWT `party` issues with its status at `index`, through `resolver`. */
async function verified(party: WebParty, index: number, resolver: StatusListResolver) {
  const credential = await signedCredential(party.key, { record: delegationRecord(party.did), credentialStatus: entryAt(index) });
  const verifier = new DelegationCredentialVerifier({ didResolver: documentsOf(issuer, other) });
  return verifier.verifyDelegationJwt(await credentialJwt(credential, party.key), { statusListResolver: resolver, skipCache: true });
}

describe('a StatusListResolver that wraps the library checker and forwards only the entry', () => {
  it('verifies a credential whose bit is clear, through the delegation verifier', async () => {
    expect(await verified(issuer, CLEAR, wrapping(checker))).toMatchObject({ valid: true });
  });

  it('refuses a credential whose bit is set, as revoked', async () => {
    expect(await verified(issuer, REVOKED, wrapping(checker))).toMatchObject({
      valid: false,
      statusOutcome: 'revoked',
      reason: 'Credential revoked via "BitstringStatusListEntry" ("revocation")',
    });
  });

  it("still holds the list to the credential's issuer, so another issuer's credential is refused", async () => {
    expect(await verified(other, CLEAR, wrapping(checker))).toMatchObject({
      valid: false,
      statusOutcome: 'status_unresolvable',
      reason: expect.stringContaining(`Status check error: status list issuer "${issuer.did}" does not keep this list's URL`),
    });
  });

  it('works behind withStatusCache, which hands its resolver the context too', async () => {
    expect(await verified(issuer, CLEAR, withStatusCache(wrapping(checker), { maxStalenessMs: 60_000 }))).toMatchObject({ valid: true });
  });

  it('keeps withStatusCache, wrapped in turn, from serving one issuer the verdict of another', async () => {
    // The adopter's wrapper forwards only the entry to the library's cache, and the cache to a
    // resolver that passes its context on: the cache keys on the context the entry carries.
    const contextual: StatusListResolver = {
      async checkStatus(status, context) {
        const verdict = await checker(status as unknown as BitstringStatusListEntry, context);
        if (verdict.revoked && !verdict.fresh) throw new Error(verdict.reason ?? 'status list unavailable');
        return verdict.revoked;
      },
    };
    const cache = withStatusCache(contextual, { maxStalenessMs: 60_000 });
    const outer = wrapping((entry) => cache.checkStatus(entry as unknown as CredentialStatus).then((revoked) => ({ revoked, fresh: true })));
    expect(await verified(issuer, CLEAR, outer)).toMatchObject({ valid: true });
    expect(await verified(other, CLEAR, outer)).toMatchObject({ valid: false, statusOutcome: 'status_unresolvable' });
  });

  it('hands each call a fresh copy that reads and serializes as the entry, and leaves the entry as it was', async () => {
    const resolver = wrapping(checker);
    await verified(issuer, CLEAR, resolver);
    await verified(issuer, CLEAR, resolver);
    const [first, second] = resolver.seen as Record<string, unknown>[];
    expect(first).not.toBe(second);
    expect(first).toEqual(entryAt(CLEAR));
    expect(JSON.stringify(first)).toBe(JSON.stringify(entryAt(CLEAR)));
    expect(Object.keys(first!)).toEqual(Object.keys(entryAt(CLEAR)));
    expect(Object.getOwnPropertySymbols(first!).map((key) => Object.getOwnPropertyDescriptor(first, key)?.enumerable)).toEqual([false]);
  });
});

describe('a BitstringRevocationChecker that wraps the library checker and forwards only the entry', () => {
  const forwardingEntry = (check: BitstringRevocationChecker): BitstringRevocationChecker =>
    async (entry) => check(entry);

  it("reads a chain's hop through evaluateRevocationChain", async () => {
    const hop = { entry: entryAt(CLEAR), credentialIssuer: issuer.did, position: 0 };
    expect(await evaluateRevocationChain([hop], forwardingEntry(checker))).toMatchObject({ ok: true });
  });

  it('keeps each call to its own context when one entry is checked under two at the same time', async () => {
    const entry = entryAt(CLEAR);
    const slow: BitstringRevocationChecker = async (given) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return checker(given);
    };
    const [byAcme, byOther] = await Promise.all([
      evaluateRevocationChain([{ entry, credentialIssuer: issuer.did }], slow),
      evaluateRevocationChain([{ entry, credentialIssuer: other.did }], slow),
    ]);
    expect(byAcme).toMatchObject({ ok: true });
    expect(byOther).toMatchObject({ ok: false, reasons: [expect.stringContaining(`"${other.did}" does, as the issuer of the credential`)] });
    expect(Object.getOwnPropertySymbols(entry)).toEqual([]);
  });

  it("reads an Entity Card's revocation entry through verifyCard", async () => {
    const card: EntityCard = {
      id: issuer.did,
      entityType: 'agent',
      name: 'Issuer Agent',
      kid: issuer.key.kid,
      capabilities: ['handshake'],
      revocation: { statusListCredential: LIST_URL, statusListIndex: String(CLEAR) },
    };
    const result = await verifyCard(card, { statusListChecker: forwardingEntry(checker) });
    expect(result.revocation).toEqual({ revoked: false, fresh: true });
  });

  it('says how to fix a call that names no credential issuer, as a wrapper that drops the context makes', async () => {
    const entry = { statusListCredential: LIST_URL, statusListIndex: String(CLEAR) };
    expect(await checker(entry)).toEqual({
      revoked: true,
      fresh: false,
      reason:
        'no credential issuer named to hold the status list to: a resolver or checker that wraps a library ' +
        'checker must pass its second argument on, or else the very entry it was given',
      ...codedAs('configuration_error'),
    });
    expect(await checker({ ...entry })).toMatchObject({ revoked: true, fresh: false, ...codedAs('configuration_error') });
  });
});
