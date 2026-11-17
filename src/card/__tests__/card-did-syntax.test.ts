/**
 * The Card's DID members, `id`, `responsibleParty`, `principal` and an attestation's `subject` and
 * `issuer`, each held to the DID rule (`utils/did-syntax.ts`) for the methods a Card takes, alike
 * through `Did`, `EntityCardSchema` and the published JSON Schema, and refused by the Zod schemas
 * with the rule's own reason. A value too long for the rule is refused for its length alone, there
 * and where a request proof and a carried delegation credential read a DID. `resolveCard` refuses a
 * did:web DID that breaks the rule with the same reason, before it fetches anything.
 */

import { readFileSync } from 'node:fs';
import Ajv2020, { type AnySchema } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { DID_MAX_LENGTH, didPattern, whyNotDid } from '../../utils/did-syntax.js';
import type { SafeFetch } from '../../utils/safe-fetch.js';
import { parseCredentials } from '../carried-chain.js';
import { DELEGATION_CONTEXT_V2, KYA_OS_DELEGATION_CONTEXT, ZCAP_CONTEXT } from '../delegation.js';
import { buildCardProof, verifyCardProof } from '../index.js';
import { KYA_OS_CARD_META_KEY, resolveCard } from '../resolve.js';
import { CARD_DID_METHODS, Did, EntityCardSchema } from '../schema.js';
import { AUD, NONCE, PROOF_KEY, REQ, clock, deps, keypair } from './proof-helpers.js';

/** A member of the published schema, as far as these tests read it. */
interface PublishedMember {
  readonly pattern?: string;
  readonly maxLength?: number;
}

/** The published Card schema, as far as these tests read it. */
interface PublishedCardSchema {
  readonly $id: string;
  readonly properties: Readonly<Record<string, PublishedMember>>;
  readonly $defs: { readonly Attestation: { readonly properties: Readonly<Record<string, PublishedMember>> } };
  readonly examples: readonly unknown[];
}

const PUBLISHED = JSON.parse(
  readFileSync(new URL('../../../schemas/kya-os-card.schema.json', import.meta.url), 'utf8'),
) as PublishedCardSchema;

/**
 * The published schema, compiled as the repository's other schema tests compile theirs. Ajv here has
 * no `format` validators, so formats are left unchecked, as they would be anyway, and unannounced.
 */
const conforms = new Ajv2020({ allErrors: true, strict: false, validateFormats: false }).compile(
  PUBLISHED as unknown as AnySchema,
);

/** Every DID value a Card member may be given, and what it gives: `undefined` for a DID a Card takes, else the reason. */
const TABLE: ReadonlyArray<readonly [string, string | undefined]> = [
  ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', undefined],
  ['did:web:example.com', undefined],
  ['did:web:example.com:agents:pay-1', undefined],
  ['did:web:localhost%3A8443', undefined],
  ['did:web:example.com#key-1', 'is a DID URL: drop the "#key-1" fragment'],
  ['did:web:example.com?v=1', 'is a DID URL: drop the "?v=1" query'],
  ['did:web:example.com/agents', 'is a DID URL: drop the "/agents" path'],
  ['did:web:has space', 'contains a space'],
  ['did:web:exämple.com', 'contains "ä", which a DID writes percent-encoded'],
  ['did:web:example.com:', 'ends with ":", so its last part is empty'],
  ['did:web:', 'has no method-specific id'],
  ['did:ion:abc', 'uses "did:ion", not did:key or did:web'],
  [
    'did:webvh:QmWboSTA2BJ9CJEXqS881Q6nxSmjEksR5MUorrTfzRcUtD:example.com:e:1',
    'uses "did:webvh", not did:key or did:web',
  ],
  ['DID:web:example.com', 'starts with "DID:"; the scheme is written in lower case: "did:"'],
  ['did:web:ex%2', 'has a "%" not followed by two hex digits'],
];

/** A Card valid but for the member a test gives it. */
const CARD = { id: 'did:web:example.com:agents:acme', entityType: 'agent', name: 'Acme' } as const;

/** A VC-JWT that only has to be a string here. */
const VC = 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.sig';

/** Each Card member that holds a DID: a Card with `did` in it, and the member's path in the Card. */
const MEMBERS = [
  { member: 'id', card: (did: string) => ({ ...CARD, id: did }), path: ['id'] },
  { member: 'responsibleParty', card: (did: string) => ({ ...CARD, responsibleParty: did }), path: ['responsibleParty'] },
  { member: 'principal', card: (did: string) => ({ ...CARD, principal: did }), path: ['principal'] },
  {
    member: 'attestations[0].subject',
    card: (did: string) => ({ ...CARD, attestations: [{ type: 'IdentityVerification', vc: VC, subject: did }] }),
    path: ['attestations', 0, 'subject'],
  },
  {
    member: 'attestations[0].issuer',
    card: (did: string) => ({ ...CARD, attestations: [{ type: 'IdentityVerification', vc: VC, issuer: did }] }),
    path: ['attestations', 0, 'issuer'],
  },
] as const;

/** The published value of `keyword` for each Card member that holds a DID. */
function published(keyword: keyof PublishedMember): Record<string, string | number | undefined> {
  const attestation = PUBLISHED.$defs.Attestation.properties;
  return {
    id: PUBLISHED.properties.id?.[keyword],
    responsibleParty: PUBLISHED.properties.responsibleParty?.[keyword],
    principal: PUBLISHED.properties.principal?.[keyword],
    'attestations[0].subject': attestation.subject?.[keyword],
    'attestations[0].issuer': attestation.issuer?.[keyword],
  };
}

describe('Did', () => {
  it.each(TABLE)('%s', (value, reason) => {
    const parsed = Did.safeParse(value);
    expect(parsed.success).toBe(reason === undefined);
    expect(parsed.error?.issues.map((issue) => issue.message)).toEqual(reason === undefined ? undefined : [reason]);
    expect(whyNotDid(value, CARD_DID_METHODS)).toBe(reason);
  });
});

describe.each(MEMBERS)('the Card member $member', ({ card, path }) => {
  const pointer = `/${path.join('/')}`;

  it.each(TABLE)('%s', (value, reason) => {
    const parsed = EntityCardSchema.safeParse(card(value));
    expect(parsed.success).toBe(reason === undefined);
    expect(parsed.error?.issues.map(({ path: at, message }) => ({ at, message }))).toEqual(
      reason === undefined ? undefined : [{ at: path, message: reason }],
    );
    expect(conforms(card(value))).toBe(reason === undefined);
    expect(conforms.errors?.map(({ instancePath, keyword }) => ({ instancePath, keyword }))).toEqual(
      reason === undefined ? undefined : [{ instancePath: pointer, keyword: 'pattern' }],
    );
  });
});

describe('the published Card schema', () => {
  it('is published at identity/card/v1.2.0', () => {
    expect(PUBLISHED.$id).toBe('https://schema.kya-os.org/v1/protocol/identity/card/v1.2.0');
  });

  it('publishes for each DID member the pattern of Did', () => {
    const pattern = z.toJSONSchema(Did).pattern;
    expect(pattern).toBe(didPattern(CARD_DID_METHODS).source);
    expect(published('pattern')).toEqual(Object.fromEntries(MEMBERS.map(({ member }) => [member, pattern])));
  });

  it('states no bound on the length of a DID member, which Did alone holds', () => {
    expect(z.toJSONSchema(Did).maxLength).toBe(DID_MAX_LENGTH);
    expect(published('maxLength')).toEqual(Object.fromEntries(MEMBERS.map(({ member }) => [member, undefined])));
  });

  it('holds every example of its own', () => {
    expect(PUBLISHED.examples.length).toBeGreaterThan(0);
    for (const example of PUBLISHED.examples) {
      expect(conforms(example), JSON.stringify(conforms.errors)).toBe(true);
    }
  });
});

/** A value of `length` characters that is a did:web DID but for its length. */
const tooLong = (length: number): string => `did:web:${'a'.repeat(length - 'did:web:'.length)}`;

/** The reason the DID rule gives a value longer than DID_MAX_LENGTH. */
const TOO_LONG = `is longer than ${DID_MAX_LENGTH} UTF-16 code units`;

/** A carried delegation credential that parses, for a test to give a DID too long. */
const CREDENTIAL = {
  '@context': [DELEGATION_CONTEXT_V2, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT],
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:acme.example',
  credentialSubject: {
    id: 'urn:zcap:acme-root',
    invoker: 'did:web:acme.example:agents:pay-1',
    parentCapability: 'https://acme.example/orders',
    invocationTarget: 'https://acme.example/orders',
    allowedAction: ['orders.place'],
  },
} as const;

// The pattern throws a RangeError on a value of these lengths (`utils/__tests__/did-syntax.test.ts`),
// so each case below would throw, or reject, had the pattern been tested.
describe.each([9_000_000, 10_000_000])('a DID of %i characters', (length) => {
  it('is refused by Did, and in each Card member, for its length', () => {
    const value = tooLong(length);
    expect(Did.safeParse(value).error?.issues.map((issue) => issue.message)).toEqual([TOO_LONG]);
    for (const { card, path } of MEMBERS) {
      const parsed = EntityCardSchema.safeParse(card(value));
      expect(parsed.error?.issues.map(({ path: at, message }) => ({ at, message }))).toEqual([{ at: path, message: TOO_LONG }]);
    }
  });

  it('makes a request proof malformed, as its did or its audience', async () => {
    const { signer, publicJwk } = await keypair();
    const proof = (await buildCardProof(REQ, signer, { audience: AUD, nonce: NONCE, now: clock }))[PROOF_KEY];
    expect((await verifyCardProof(proof, REQ, deps(publicJwk))).ok).toBe(true);
    const value = tooLong(length);
    for (const malformed of [{ ...proof, did: value }, { ...proof, audience: value }]) {
      expect(await verifyCardProof(malformed, REQ, deps(publicJwk))).toEqual({ ok: false, reasons: ['malformed_proof'] });
    }
  });

  it('makes a carried delegation credential malformed, as its issuer or its invoker', () => {
    expect(parseCredentials([CREDENTIAL]).ok).toBe(true);
    const value = tooLong(length);
    const malformed: ReadonlyArray<readonly [Record<string, unknown>, string]> = [
      [{ ...CREDENTIAL, issuer: value }, 'issuer'],
      [{ ...CREDENTIAL, credentialSubject: { ...CREDENTIAL.credentialSubject, invoker: value } }, 'credentialSubject.invoker'],
    ];
    for (const [credential, at] of malformed) {
      expect(parseCredentials([credential])).toEqual({
        ok: false,
        reasons: [expect.stringContaining(`hop 0: not a DelegationCredential at ${at}: `)],
        refusalCode: 'delegation_malformed',
        transient: false,
      });
    }
  });
});

/** A did:web DID with a Card to resolve. */
const RESOLVABLE = 'did:web:acme.example';

/** DID URLs made of {@link RESOLVABLE}, each with the refusal `resolveCard` gives it. */
const DID_URLS: ReadonlyArray<readonly [string, string]> = [
  ['did:web:acme.example#key-1', 'resolveCard: "did:web:acme.example#key-1" is a DID URL: drop the "#key-1" fragment'],
  ['did:web:acme.example?v=1', 'resolveCard: "did:web:acme.example?v=1" is a DID URL: drop the "?v=1" query'],
  ['did:web:acme.example/agents', 'resolveCard: "did:web:acme.example/agents" is a DID URL: drop the "/agents" path'],
];

/**
 * did:web values made of {@link RESOLVABLE} that are not DID URLs but break the DID rule, each with
 * the refusal `resolveCard` gives it. The did:web parser reads the first as naming a URL, so the rule
 * alone keeps it from being fetched.
 */
const MALFORMED_DIDS: ReadonlyArray<readonly [string, string]> = [
  ['did:web:acme.example:a+b', 'resolveCard: "did:web:acme.example:a+b" contains "+", which a DID writes percent-encoded'],
  ['did:web:acme.example:a%2', 'resolveCard: "did:web:acme.example:a%2" has a "%" not followed by two hex digits'],
];

/** A SafeFetch that records each URL it is asked for, and answers with the body `bodies` holds for it, or a 404. */
function recordingFetch(bodies: Readonly<Record<string, unknown>> = {}): { fetch: SafeFetch; requested: string[] } {
  const requested: string[] = [];
  const fetch: SafeFetch = async (url) => {
    requested.push(url);
    const body = bodies[url];
    return { ok: body !== undefined, status: body === undefined ? 404 : 200, json: async () => body };
  };
  return { fetch, requested };
}

describe('resolveCard', () => {
  it.each([...DID_URLS, ...MALFORMED_DIDS])('refuses %s, as a DID and as an inline summary id, before it fetches anything', async (did, refusal) => {
    const { fetch, requested } = recordingFetch();
    await expect(resolveCard(did, { fetch })).rejects.toThrow(new Error(refusal));
    await expect(resolveCard({ serverMeta: { [KYA_OS_CARD_META_KEY]: { ...CARD, id: did } } }, { fetch })).rejects.toThrow(
      new Error(refusal),
    );
    expect(requested).toEqual([]);
  });

  it('resolves a did:web DID, and an inline summary id, as before', async () => {
    const card = { ...CARD, id: RESOLVABLE };
    const { fetch, requested } = recordingFetch({
      'https://acme.example/.well-known/did.json': {
        id: RESOLVABLE,
        service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://acme.example/card.json' }],
      },
      'https://acme.example/card.json': card,
      'https://acme.example/.well-known/kya-os-card.json': card,
    });
    expect(await resolveCard(RESOLVABLE, { fetch })).toEqual(card);
    expect(await resolveCard({ serverMeta: { [KYA_OS_CARD_META_KEY]: card } }, { fetch })).toEqual(card);
    expect(requested).toEqual([
      'https://acme.example/.well-known/did.json',
      'https://acme.example/card.json',
      'https://acme.example/.well-known/kya-os-card.json',
    ]);
  });
});
