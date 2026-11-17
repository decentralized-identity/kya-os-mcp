/**
 * The Entity Card's revocation seam reads a checker's answer as the delegation side does, through
 * the one shared reader. A `BitstringRevocationChecker` is code the host supplies, and a JavaScript
 * one can answer anything: only an answer whose `revoked` is the literal `false` passes, only the
 * literal `true` revokes, `fresh` is fresh only as the literal `true`, and every other answer is
 * refused as a status that could not be read, with a reason that says what was wrong. Nothing
 * throws. Each path that asks a checker is held to it: `evaluateRevocationChain`,
 * `evaluateDelegationChain`, `verifyRequestDelegation`, `requireDelegation` and `verifyCard`.
 */
import { describe, expect, it } from 'vitest';
import { countingAnswer, PASSING_WITH_THROWING_CODE, UNREADABLE_ANSWERS } from '../../__tests__/utils/revocation-answers.js';
import { evaluateDelegationChain, leafInvokerOf } from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { requireDelegation, toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { evaluateRevocationChain, type BitstringRevocationChecker, type RevocationStatusEntry } from '../revocation.js';
import type { EntityCard } from '../schema.js';
import { verifyCard } from '../verify.js';
import { now, RESOURCE } from './signed-chain-helpers.js';
import { cast, threeHopChain } from './status-list-paths.js';
import { BIT_SET, codedAs } from '../../__tests__/utils/refusal-coding.js';
import { anyRootUnlessPinned } from './root-issuers.js';

const ENTRY: RevocationStatusEntry = { statusListCredential: 'https://status.example/1', statusListIndex: '7' };
/** A checker whose every answer is `answer`, typed as the status it claims to be. */
const answering = (answer: unknown): BitstringRevocationChecker => async () => answer as never;
/** Why hop `hop`, whose entry is at `index` of `list`, is refused on an answer that could not be read. */
const unreadableHop = (hop: number, list: string, index: string, why: string) =>
  `revocation: hop ${hop} (list "${list}", index "${index}") has a status that could not be read: ${why}`;

describe('evaluateRevocationChain', () => {
  it('passes a hop only on an answer whose revoked is the literal false', async () => {
    expect(await evaluateRevocationChain([ENTRY], answering({ revoked: false, fresh: true }))).toEqual({
      ok: true,
      fresh: true,
      reasons: [],
    });
  });

  it.each([undefined, null, false, 0, 1, 'true', {}, new Boolean(true)])('reads a fresh of %o as not fresh', async (fresh) => {
    expect(await evaluateRevocationChain([ENTRY], answering({ revoked: false, fresh }))).toEqual({
      ok: true,
      fresh: false,
      reasons: [],
    });
  });

  it('refuses a hop as revoked only on the literal true', async () => {
    expect(await evaluateRevocationChain([ENTRY], answering({ revoked: true, fresh: true }))).toEqual({
      ok: false,
      fresh: false,
      reasons: [
        `revocation: hop 0 (list "https://status.example/1", index "7") is revoked or unresolvable ${String.fromCodePoint(0x2014)} fail-closed, subtree invalidated`,
      ],
      ...BIT_SET,
    });
  });

  it.each(UNREADABLE_ANSWERS)('refuses a hop, and does not throw, when its checker answers %s', async (_label, answer, why) => {
    expect(await evaluateRevocationChain([ENTRY], answering(answer))).toEqual({
      ok: false,
      fresh: false,
      reasons: [unreadableHop(0, ENTRY.statusListCredential, ENTRY.statusListIndex, why)],
      ...codedAs('status_unavailable'),
    });
  });

  it('stops at the first hop whose answer could not be read', async () => {
    const answers: unknown[] = [{ revoked: false, fresh: true }, {}, { revoked: false, fresh: true }];
    let asked = 0;
    const result = await evaluateRevocationChain([ENTRY, ENTRY, ENTRY], async () => answers[asked++] as never);
    expect(result).toMatchObject({ ok: false, fresh: false });
    expect(result.reasons).toEqual([expect.stringMatching(/^revocation: hop 1 .* has a status that could not be read: /)]);
    expect(asked).toBe(2);
  });

  it('passes a hop on an answer that does not revoke, whatever its code getter would do', async () => {
    expect(await evaluateRevocationChain([ENTRY], answering(PASSING_WITH_THROWING_CODE))).toMatchObject({ ok: true, fresh: true });
  });

  it('reads each member of an answer once', async () => {
    const { answer, reads } = countingAnswer({ revoked: false, fresh: true });
    expect(await evaluateRevocationChain([ENTRY], answering(answer))).toMatchObject({ ok: true, fresh: true });
    expect(reads).toMatchObject({ revoked: 1, fresh: 1 });
  });
});

describe('the paths that walk a delegation chain', () => {
  const c = cast();
  const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
  const list = (chain[0].credentialStatus as { statusListCredential: string }).statusListCredential;
  const input = { meta: toDelegationChainMeta(chain), proofDid: leafInvokerOf(chain) ?? '', action: 'orders.place' };
  const deps = (checkRevocation: BitstringRevocationChecker) =>
    anyRootUnlessPinned({
      resource: RESOURCE,
      verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
      checkRevocation,
      now,
    });

  it('accept the chain on answers whose revoked is the literal false', async () => {
    const checker = answering({ revoked: false, fresh: true });
    expect(await evaluateDelegationChain(chain, checker, { resource: RESOURCE, now })).toMatchObject({ ok: true, fresh: true });
    expect(await verifyRequestDelegation(input, deps(checker))).toMatchObject({ ok: true, fresh: true });
    expect(await requireDelegation(deps(checker))(input)).toMatchObject({ ok: true, fresh: true });
  });

  it.each(UNREADABLE_ANSWERS)('refuse the chain when the checker answers %s', async (_label, answer, why) => {
    const checker = answering(answer);
    const reasons = [unreadableHop(0, list, '0', why)];
    expect(await evaluateDelegationChain(chain, checker, { resource: RESOURCE, now })).toMatchObject({ ok: false, reasons });
    expect(await verifyRequestDelegation(input, deps(checker))).toEqual({
      ok: false,
      code: 'delegation_revoked',
      reasons,
      source: 'carried',
      refusalCode: 'status_unavailable',
      transient: true,
    });
    expect(await requireDelegation(deps(checker))(input)).toMatchObject({
      ok: false,
      status: 403,
      error: { code: 'delegation_revoked', reasons },
      refusalCode: 'status_unavailable',
    });
  });
});

describe("verifyCard's revocation check", () => {
  const card: EntityCard = {
    id: 'did:web:example.com:agents:acme',
    entityType: 'agent',
    name: 'Acme',
    capabilities: [{ name: 'payments.transfer', attestations: [{ vc: 'jwt' }] }],
    revocation: ENTRY,
  };
  const verify = (answer: unknown) =>
    verifyCard(card, {
      capabilityVerifier: async () => ({ verified: ['payments.transfer'], unverified: [] }),
      // An empty proof on purpose: the stub verifier below answers for it without reading it.
      proof: {},
      request: { method: 'tools/call', params: { name: 'search' } },
      proofVerifier: async () => ({ ok: true, reasons: [], level: 'L3', did: card.id }),
      statusListChecker: answering(answer),
    });

  it('passes a Card only on an answer whose revoked is the literal false', async () => {
    expect(await verify({ revoked: false, fresh: true })).toMatchObject({
      ok: true,
      conformanceLevel: 'L3',
      revocation: { revoked: false, fresh: true },
    });
    expect((await verify({ revoked: false, fresh: true })).revocation).toStrictEqual({ revoked: false, fresh: true });
  });

  it.each([undefined, 1, 'true'])('reads a fresh of %o as not fresh, which demotes L3 to L2', async (fresh) => {
    expect(await verify({ revoked: false, fresh })).toMatchObject({
      ok: true,
      conformanceLevel: 'L2',
      revocation: { revoked: false, fresh: false },
    });
  });

  it('reads the literal true as revoked', async () => {
    const result = await verify({ revoked: true, fresh: true });
    expect(result).toMatchObject({ ok: false, conformanceLevel: 'L1' });
    expect(result.revocation).toEqual({ revoked: true, fresh: true, ...BIT_SET });
  });

  it.each(UNREADABLE_ANSWERS)('refuses a Card, and does not throw, when its checker answers %s', async (_label, answer, why) => {
    const result = await verify(answer);
    expect(result).toMatchObject({ ok: false, conformanceLevel: 'L1', verifiedCapabilities: ['payments.transfer'] });
    expect(result.revocation).toEqual({
      revoked: true,
      fresh: false,
      reason: `the Card's revocation status could not be read: ${why}`,
      ...codedAs('status_unavailable'),
    });
  });
});
