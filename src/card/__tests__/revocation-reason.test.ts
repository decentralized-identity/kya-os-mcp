/**
 * A refused status entry says why. The checker `createRevocationChecker` builds answers every entry
 * it cannot prove clear with `{ revoked: true, fresh: false, reason }`, the reason naming the step
 * that refused it: the entry's purpose or size, or the list's purpose, issuer or `id`, or its proof.
 * A list that could not be read, or whose bits could not be decoded, is named and said only to be
 * unread, since whoever presented the entry chose its URL, and what the read or the decoder said
 * goes to the operator's log. `evaluateRevocationChain` appends the reason a checker gives to the hop's
 * refusal, so it reaches `evaluateDelegationChain`, `verifyRequestDelegation` and
 * `requireDelegation`, and `verifyCard` reports it. A reason is text for people: the shipped
 * checker's own is cut at `CHECKER_REASON_LENGTH`, 512, UTF-16 code units, a custom checker's at
 * `WRAPPED_REASON_LENGTH`, 640, which leaves room for a wrapper's words before the shipped
 * checker's reason, and neither shows a control character.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { logger } from '../../logging/index.js';
import { CHECKER_REASON_LENGTH, createRevocationChecker, evaluateRevocationChain, type RevocationStatusEntry } from '../revocation.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { verifyCard } from '../verify.js';
import type { EntityCard } from '../schema.js';
import { identity, now, serve, statusList, STATUS_URL } from './signed-chain-helpers.js';
import { BIT_SET, codedAs } from '../../__tests__/utils/refusal-coding.js';
import { WRAPPED_REASON_LENGTH } from '../../utils/revocation-answer.js';
import type { RefusalCode } from '../../refusal-codes.js';
import { cast, listOf, listUrlOf, servedBy, threeHopChain, verdicts } from './status-list-paths.js';

const owner = identity();
const other = identity();
const ENTRY: RevocationStatusEntry = { statusListCredential: STATUS_URL, statusListIndex: '7' };
const UNREAD = `the status list at "${STATUS_URL}" could not be read`;
const HOP = `revocation: hop 0 (list "${STATUS_URL}", index "7") is revoked or unresolvable ${String.fromCodePoint(0x2014)} fail-closed, subtree invalidated`;

/** The verdict of the shipped checker, holding lists to `owner`, on `entry` when `body` is served at the list's URL. */
const checked = (body: Record<string, unknown> | undefined, entry: Record<string, unknown> = ENTRY) =>
  createRevocationChecker({
    fetch: serve(body),
    now,
    verifyStatusList: createStatusListProofVerifier({ didResolver: createDidKeyResolver() }),
  })(entry as RevocationStatusEntry, { credentialIssuer: owner.did });

afterEach(() => {
  vi.restoreAllMocks();
});

/** What the operator's log was told while `run` ran. */
async function logged<T>(run: () => Promise<T>): Promise<{ answer: T; lines: string[] }> {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const answer = await run();
  return { answer, lines: warn.mock.calls.map((call) => call.map(String).join(' ')) };
}

describe('the reason the shipped checker gives', () => {
  it('gives none for an entry it reads, set or clear', async () => {
    expect(await checked(statusList(owner, []))).toStrictEqual({ revoked: false, fresh: true });
    expect(await checked(statusList(owner, [7]))).toStrictEqual({ revoked: true, fresh: true, ...BIT_SET });
  });

  it.each([
    ['states another purpose', { ...ENTRY, statusPurpose: 'suspension' }, statusList(owner), `the entry's statusPurpose is "suspension", not the checker's "revocation"`],
    ['is two bits wide', { ...ENTRY, statusSize: 2 }, statusList(owner), "the entry's statusSize is 2, and only an entry of one bit is read"],
    ['names an index that is not a decimal string', { ...ENTRY, statusListIndex: '7x' }, statusList(owner), 'Invalid statusListIndex "7x": must be a non-negative decimal string'],
  ])('says why it refuses an entry that %s', async (_label, entry, body, reason) => {
    expect(await checked(body, entry)).toStrictEqual({ revoked: true, fresh: false, reason, ...codedAs('delegation_malformed') });
  });

  it.each<[string, Record<string, unknown> | undefined, string, RefusalCode]>([
    ['is of another purpose', statusList(owner, [], { credentialSubject: { statusPurpose: 'suspension' } }), `status list statusPurpose mismatch: the list's is "suspension" and the entry's is "revocation"`, 'status_signer_untrusted'],
    ['states another id', statusList(owner, [], { id: 'https://elsewhere.example/1' }), `status list id "https://elsewhere.example/1" is not the URL it was fetched from ("${STATUS_URL}")`, 'status_signer_untrusted'],
  ])('says why it refuses an entry whose list %s', async (_label, body, reason, code) => {
    expect(await checked(body)).toStrictEqual({ revoked: true, fresh: false, reason, ...codedAs(code) });
  });

  it.each<[string, Record<string, unknown> | undefined, string]>([
    ['is not served', undefined, `status-list GET ${STATUS_URL} \u2192 503`],
    ['has no encodedList', statusList(owner, [], { credentialSubject: { encodedList: '' } }), 'status-list has no encodedList'],
  ])('names an entry\'s list that %s and says only that it could not be read, logging why', async (_label, body, why) => {
    const { answer, lines } = await logged(() => checked(body));
    expect(answer).toStrictEqual({ revoked: true, fresh: false, reason: UNREAD, ...codedAs('status_unavailable') });
    expect(lines).toEqual([`[revocation] ${UNREAD}: revocation: ${why}`]);
  });

  it('says that a list altered after it was signed has a proof that does not verify', async () => {
    const altered = { ...statusList(owner), validFrom: '2026-02-02T00:00:00Z' };
    expect(await checked(altered)).toStrictEqual({ revoked: true, fresh: false, reason: 'status-list proof rejected', ...codedAs('status_signer_untrusted') });
  });

  it('says that a call naming no credential issuer cannot be held to anyone', async () => {
    const checker = createRevocationChecker({
      fetch: serve(statusList(owner)),
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver: createDidKeyResolver() }),
    });
    expect(await checker(ENTRY)).toStrictEqual({
      revoked: true,
      fresh: false,
      reason:
        'no credential issuer named to hold the status list to: a resolver or checker that wraps a library ' +
        'checker must pass its second argument on, or else the very entry it was given',
      ...codedAs('configuration_error'),
    });
  });

  it('tells no part of what a fetch that throws said, and logs it bounded, with no control character of it', async () => {
    const checker = createRevocationChecker({
      fetch: async () => {
        throw new Error(`boom\n${'x'.repeat(2000)}`);
      },
      now,
    });
    const { answer, lines } = await logged(() => checker(ENTRY));
    expect(answer).toStrictEqual({ revoked: true, fresh: false, reason: UNREAD, ...codedAs('status_unavailable') });
    expect(lines).toEqual([`[revocation] ${UNREAD}: boom\uFFFD${'x'.repeat(1024 - 5)}\u2026`]);
  });

  it('gives a reason when what was thrown is not an Error', async () => {
    const checker = createRevocationChecker({
      fetch: async () => {
        throw 'boom';
      },
      now,
    });
    const { answer, lines } = await logged(() => checker(ENTRY));
    expect(answer).toStrictEqual({ revoked: true, fresh: false, reason: UNREAD, ...codedAs('status_unavailable') });
    expect(lines).toEqual([`[revocation] ${UNREAD}: a thrown string`]);
  });
});

describe("evaluateRevocationChain and a checker's reason", () => {
  it('appends the reason a checker gives for a revoked hop', async () => {
    const result = await evaluateRevocationChain([ENTRY], async () => ({ revoked: true, fresh: false, reason: 'status-list proof rejected' }));
    expect(result).toEqual({ ok: false, fresh: false, reasons: [`${HOP}: status-list proof rejected`], ...BIT_SET });
  });

  it.each([undefined, '', 7, { text: 'why' }])('appends nothing for a reason of %o', async (reason) => {
    const result = await evaluateRevocationChain([ENTRY], async () => ({ revoked: true, fresh: false, reason }) as never);
    expect(result.reasons).toEqual([HOP]);
  });

  it('cuts a reason at WRAPPED_REASON_LENGTH UTF-16 code units and replaces its control characters', async () => {
    const result = await evaluateRevocationChain([ENTRY], async () => ({ revoked: true, fresh: false, reason: `a\u0000b${'c'.repeat(1000)}` }));
    expect(result.reasons).toEqual([`${HOP}: a\uFFFDb${'c'.repeat(WRAPPED_REASON_LENGTH - 3)}\u2026`]);
  });

  it('carries the reason of the shipped checker through all three paths', async () => {
    const c = cast();
    const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
    const lists = { ...servedBy(listOf(c.acme), listOf(c.subAgent)), [listUrlOf(c.agent)]: statusList(c.mallory, [], { id: listUrlOf(c.agent) }) };
    const { evaluated, request, guarded } = await verdicts(chain, lists, { pinned: false });
    const reason = expect.stringMatching(
      new RegExp(`^revocation: hop 1 .* fail-closed, subtree invalidated: status list issuer "${c.mallory.did}" `),
    );
    expect(evaluated.reasons).toEqual([reason]);
    expect(request).toMatchObject({ ok: false, code: 'delegation_revoked', reasons: [reason] });
    expect(guarded).toMatchObject({ ok: false, error: { code: 'delegation_revoked', reasons: [reason] } });
  });
});

describe("verifyCard and a checker's reason", () => {
  const card: EntityCard = { id: owner.did, entityType: 'agent', name: 'Acme', capabilities: ['orders.place'], revocation: ENTRY };
  const verify = (body: Record<string, unknown>) =>
    verifyCard(card, {
      statusListChecker: createRevocationChecker({
        fetch: serve(body),
        now,
        verifyStatusList: createStatusListProofVerifier({ didResolver: createDidKeyResolver() }),
      }),
    });

  it('reports why the Card reads as revoked when its list is refused', async () => {
    expect((await verify(statusList(other))).revocation).toStrictEqual({
      revoked: true,
      fresh: false,
      reason: expect.stringMatching(new RegExp(`^status list issuer "${other.did}" `)),
      ...codedAs('status_signer_untrusted'),
    });
  });

  it('reports no reason for a Card whose bit is set, or clear', async () => {
    expect((await verify(statusList(owner, [7]))).revocation).toStrictEqual({ revoked: true, fresh: true, ...BIT_SET });
    expect((await verify(statusList(owner))).revocation).toStrictEqual({ revoked: false, fresh: true });
  });

  it('reports no reason a checker gives for a Card it does not revoke', async () => {
    const result = await verifyCard(card, { statusListChecker: async () => ({ revoked: false, fresh: true, reason: 'all clear' }) });
    expect(result.revocation).toStrictEqual({ revoked: false, fresh: true });
  });

  it('bounds the reason of a custom checker', async () => {
    const result = await verifyCard(card, { statusListChecker: async () => ({ revoked: true, fresh: false, reason: `a\n${'c'.repeat(1000)}` }) });
    expect(result.revocation).toStrictEqual({
      revoked: true,
      fresh: false,
      reason: `a\uFFFD${'c'.repeat(WRAPPED_REASON_LENGTH - 2)}\u2026`,
      ...BIT_SET,
    });
  });
});
