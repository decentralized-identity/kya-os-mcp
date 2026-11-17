/**
 * A status entry of more than one bit is never read from another entry's bit. Bitstring Status List
 * v1.0 lets an entry state `statusSize`, and an entry of two bits at index 7 has its value at bits
 * 14 and 15, while bit 7 belongs to entry 3. The checker reads one bit per entry, so it refuses
 * every entry whose `statusSize` is not 1, before it fetches any list: a two-bit entry whose value
 * is set is not passed on bit 7 being clear, and one whose value is clear is not refused on bit 7
 * being set, which would be reading entry 3. An entry that states 1, or no size, is read as before.
 * The hop schema and the Card's entry schema keep `statusSize` and `statusMessage`, so the checker
 * sees them, and refuse a malformed one.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MALFORMED_STATUS_SIZES, TWO_BIT_MESSAGES, wideSizeReason } from '../../__tests__/utils/status-sizes.js';
import {
  DelegationCredentialSchema,
  DelegationCredentialStatusSchema,
  evaluateDelegationChain,
  leafInvokerOf,
  revocationEntriesOf,
  type DelegationCredential,
} from '../delegation.js';
import { createDelegationProofVerifier } from '../delegation-proof.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { toDelegationChainMeta, verifyRequestDelegation } from '../request-delegation.js';
import { createRevocationChecker } from '../revocation.js';
import { BitstringStatusListEntrySchema, EntityCardSchema } from '../schema.js';
import { createStatusListProofVerifier } from '../status-list-proof.js';
import { verifyCard } from '../verify.js';
import { identity, now, RESOURCE, serveAt, signEddsaJcs2022, statusList } from './signed-chain-helpers.js';
import {
  cast,
  expectAccepted,
  expectRevokedAt,
  listOf,
  listUrlOf,
  servedBy,
  threeHopChain,
  type Cast,
  type ThreeHopChain,
} from './status-list-paths.js';

/** The standard chain with hop 1's entry, at index 7 of the agent's list, stating `members` as well. */
function chainWith(c: Cast, members: Record<string, unknown>): ThreeHopChain {
  const chain = threeHopChain(c, [c.acme, c.agent, c.subAgent]);
  const { proof: _proof, ...unsigned } = chain[1] as unknown as Record<string, unknown>;
  unsigned.credentialStatus = {
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '7',
    statusListCredential: listUrlOf(c.agent),
    ...members,
  };
  chain[1] = signEddsaJcs2022(unsigned, c.agent) as unknown as DelegationCredential;
  return chain;
}
const lists = (c: Cast, agentBits: number[]) => servedBy(listOf(c.acme), listOf(c.agent, agentBits), listOf(c.subAgent));
const TWO_BITS = { statusSize: 2, statusMessage: TWO_BIT_MESSAGES };

describe('a hop whose status entry is two bits wide', () => {
  it('is refused on every path, and its list is not fetched, when its value is set at bits 14 and 15 and bit 7 is clear', async () => {
    const c = cast();
    const fetched: string[] = [];
    await expectRevokedAt(1, chainWith(c, TWO_BITS), lists(c, [14, 15]), { fetched });
    // Each of the three paths reads hop 0's list and stops at hop 1 before any fetch.
    expect(fetched).toEqual([listUrlOf(c.acme), listUrlOf(c.acme), listUrlOf(c.acme)]);
  });

  it('is refused for its size, and not on bit 7, which is entry 3 of two bits, when only that bit is set', async () => {
    const c = cast();
    const fetched: string[] = [];
    await expectRevokedAt(1, chainWith(c, TWO_BITS), lists(c, [7]), { fetched });
    expect(fetched).toEqual([listUrlOf(c.acme), listUrlOf(c.acme), listUrlOf(c.acme)]);
  });

  it('is refused when its list is clear as well', async () => {
    const c = cast();
    await expectRevokedAt(1, chainWith(c, TWO_BITS), lists(c, []));
  });
});

describe('a hop whose status entry is one bit wide', () => {
  it.each([
    ['states a statusSize of 1', { statusSize: 1 }],
    ['states a statusSize of 1 and its two messages', { statusSize: 1, statusMessage: TWO_BIT_MESSAGES.slice(0, 2) }],
    ['states no statusSize', {}],
  ])('is read from the bit at its index when it %s', async (_label, members) => {
    const c = cast();
    const fetched: string[] = [];
    await expectAccepted(chainWith(c, members), lists(c, [6, 8, 14, 15]), { fetched });
    expect(fetched).toContain(listUrlOf(c.agent));
    await expectRevokedAt(1, chainWith(c, members), lists(c, [7]));
  });
});

describe('a hop whose statusSize is not an integer greater than zero', () => {
  it.each(MALFORMED_STATUS_SIZES)('is refused when it is %s: by the hop schema, and by the checker before any fetch', async (_label, statusSize) => {
    const c = cast();
    const chain = chainWith(c, { statusSize });
    expect(DelegationCredentialSchema.safeParse(chain[1]).success).toBe(false);
    const request = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: leafInvokerOf(chain) ?? '', action: 'orders.place' },
      {
        resource: RESOURCE,
        verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
        checkRevocation: async () => ({ revoked: false, fresh: true }),
        now,
      },
    );
    expect(request).toMatchObject({ ok: false, code: 'delegation_invalid' });

    // A chain that reaches the checker unparsed is refused there, at hop 1, with no fetch of its list.
    const fetched: string[] = [];
    const serve = serveAt(lists(c, []));
    const checker = createRevocationChecker({
      fetch: (url) => {
        fetched.push(url);
        return serve(url);
      },
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver: createDidKeyResolver() }),
    });
    const evaluated = await evaluateDelegationChain(chain, checker, { resource: RESOURCE, now });
    expect(evaluated.ok).toBe(false);
    expect(evaluated.reasons).toEqual([expect.stringMatching(/^revocation: hop 1 /)]);
    expect(fetched).toEqual([listUrlOf(c.acme)]);
  });
});

describe('the schemas of a status entry', () => {
  const entry = { statusListCredential: 'https://status.example/1', statusListIndex: '7' };
  const hopEntry = { ...entry, type: 'BitstringStatusListEntry', statusPurpose: 'revocation' };

  it('keep statusSize and statusMessage, on a hop and on a Card', () => {
    const c = cast();
    const parsed = DelegationCredentialSchema.parse(chainWith(c, TWO_BITS)[1]);
    expect(parsed.credentialStatus).toMatchObject(TWO_BITS);
    expect(revocationEntriesOf([parsed])[0]?.entry).toMatchObject({ statusListIndex: '7', statusSize: 2 });
    expect(BitstringStatusListEntrySchema.parse({ ...entry, ...TWO_BITS })).toEqual({ ...entry, ...TWO_BITS });
    expect(BitstringStatusListEntrySchema.parse({ ...entry, statusSize: 1 })).toEqual({ ...entry, statusSize: 1 });
    expect(BitstringStatusListEntrySchema.parse(entry)).toEqual(entry);
  });

  it('leave a hop that states no statusSize without one', () => {
    const c = cast();
    const [parsed] = revocationEntriesOf([DelegationCredentialSchema.parse(chainWith(c, {})[1])]);
    expect(parsed?.entry).toStrictEqual({ statusListCredential: listUrlOf(c.agent), statusListIndex: '7', statusPurpose: 'revocation' });
  });

  it.each(MALFORMED_STATUS_SIZES)('refuse a statusSize of %s', (_label, statusSize) => {
    expect(BitstringStatusListEntrySchema.safeParse({ ...entry, statusSize }).success).toBe(false);
    expect(DelegationCredentialStatusSchema.safeParse({ ...hopEntry, statusSize }).success).toBe(false);
  });

  it.each([
    ['a string', 'revoked'],
    ['an object', { status: '0x0', message: 'valid' }],
    ['an array with a string in it', ['valid']],
    ['an array with a message that states no status', [{ message: 'valid' }]],
    ['an array with a message whose status is a number', [{ status: 0, message: 'valid' }]],
    ['an array with a status that states no message', [{ status: '0x0' }]],
    ['an array with a status whose message is not a string', [{ status: '0x0', message: 1 }]],
    ['null', null],
  ])('refuse a statusMessage that is %s', (_label, statusMessage) => {
    expect(BitstringStatusListEntrySchema.safeParse({ ...entry, statusMessage }).success).toBe(false);
    expect(DelegationCredentialStatusSchema.safeParse({ ...hopEntry, statusMessage }).success).toBe(false);
  });

  it('keep the other members of a status message', () => {
    const statusMessage = [{ status: '0x0', message: 'valid', note: 'kept' }, { status: '0x1', message: 'revoked' }];
    expect(BitstringStatusListEntrySchema.parse({ ...entry, statusMessage })).toEqual({ ...entry, statusMessage });
    expect(DelegationCredentialStatusSchema.parse({ ...hopEntry, statusMessage })).toEqual({ ...hopEntry, statusMessage });
  });

  it.each(['kya-os-card.schema.json', 'card-delegation-credential.json', 'delegation-credential.json'])(
    'are described by the published schemas/%s, which states both members as the zod schemas take them',
    (file) => {
      const published = JSON.parse(readFileSync(new URL(`../../../schemas/${file}`, import.meta.url), 'utf8')) as {
        $defs?: Record<string, { properties: Record<string, unknown> }>;
        definitions?: Record<string, { properties: Record<string, unknown> }>;
      };
      const definitions = published.$defs ?? published.definitions ?? {};
      const stated = (definitions.BitstringStatusListEntry ?? definitions.CredentialStatus)?.properties;
      expect(stated?.statusSize).toMatchObject({ type: 'integer', minimum: 1 });
      expect(stated?.statusMessage).toMatchObject({
        type: 'array',
        items: { type: 'object', required: ['status', 'message'], properties: { status: { type: 'string' }, message: { type: 'string' } } },
      });
    },
  );

  it('still refuse a member of a Card entry the schema does not name', () => {
    expect(BitstringStatusListEntrySchema.safeParse({ ...entry, statusBits: 2 }).success).toBe(false);
  });
});

describe('a Card whose revocation entry is two bits wide', () => {
  it.each([
    ['its value is set and bit 7 is clear', [14, 15]],
    ['only bit 7 is set', [7]],
  ])('reads as revoked, and its list is not fetched, when %s', async (_label, bits) => {
    const owner = identity();
    const url = 'https://status.example/card';
    const card = EntityCardSchema.parse({
      id: owner.did,
      entityType: 'agent',
      name: 'Acme',
      capabilities: ['orders.place'],
      revocation: { statusListCredential: url, statusListIndex: '7', ...TWO_BITS },
    });
    const run = async (revocation: typeof card.revocation) => {
      let fetches = 0;
      const serve = serveAt({ [url]: statusList(owner, bits, { id: url, credentialSubject: { id: `${url}#list` } }) });
      const statusListChecker = createRevocationChecker({
        fetch: (asked) => {
          fetches += 1;
          return serve(asked);
        },
        now,
        verifyStatusList: createStatusListProofVerifier({ didResolver: createDidKeyResolver() }),
      });
      const result = await verifyCard({ ...card, revocation }, { statusListChecker });
      return { revocation: result.revocation, fetches };
    };
    expect(await run(card.revocation)).toEqual({
      revocation: { revoked: true, fresh: false, reason: wideSizeReason(2), code: 'delegation_malformed', transient: false },
      fetches: 0,
    });
    // The same entry of one bit is read from the list, which shows the size alone refused it.
    const { statusSize: _size, statusMessage: _message, ...oneBit } = card.revocation!;
    expect(await run(oneBit)).toEqual({
      revocation: { revoked: bits.includes(7), fresh: true, ...(bits.includes(7) ? { code: 'delegation_revoked', transient: false } : {}) },
      fetches: 1,
    });
  });
});
