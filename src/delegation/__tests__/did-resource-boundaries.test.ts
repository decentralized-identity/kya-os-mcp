/**
 * Each DID resolution limit of SPEC.md §4.4.2, one under, at and one over its value: a document or
 * identifier at a limit is accepted, and one over it is refused, never cut to fit. The built-in
 * network resolvers hold what they fetch to the limits that only the document walk measures.
 */

import { describe, it, expect, vi } from 'vitest';
import { measureDidDocument, resolveBoundedDid } from '../did-resource-limits.js';
import { DidWebResolver } from '../did-web-resolver.js';
import { DidCheqdResolver } from '../../integrations/cheqd/resolver.js';
import type { DIDDocument } from '../vc-verifier.types.js';
import type { FetchProvider } from '../../providers/base.js';

const did = 'did:web:limits.example';
const utf8Length = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;
const accepted = (document: unknown) => measureDidDocument(document).ok;

/** A document of `containers` nested containers, the document itself included. */
function nested(containers: number): unknown {
  let value: unknown = 0;
  for (let i = 1; i < containers; i++) value = [value];
  return { id: did, value };
}

const method = (id: string, controller: string) => ({ id, type: 'JsonWebKey', controller });

/** `verificationMethod` and the five verification relationships, as SPEC §4.4.2 names them. */
const RELATIONSHIPS = [
  'verificationMethod', 'authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation',
] as const;
type Relationship = (typeof RELATIONSHIPS)[number];

/** `n` verification entries: one in each of the six lists, and the rest in `crowded`. */
const entries = (crowded: Relationship, n: number) =>
  ({ id: did, ...Object.fromEntries(RELATIONSHIPS.map(name => [name, Array(name === crowded ? n - 5 : 1).fill('#k')])) });

const limits: [string, number, (n: number) => unknown][] = [
  ['nesting, in containers', 64, nested],
  ['a member name, in UTF-16 code units', 256, n => ({ id: did, ['k'.repeat(n)]: 0 })],
  ['members in all, id included', 8_192, n => ({ id: did, ...Object.fromEntries(Array.from({ length: n - 1 }, (_, i) => [`m${i}`, 0])) })],
  ['compact JSON, in UTF-8 bytes', 1_048_576, n => ({ id: did, pad: 'x'.repeat(n - utf8Length({ id: did, pad: '' })) })],
  ["the document's id, in UTF-16 code units", 2_048, n => ({ id: `did:${'d'.repeat(n - 4)}` })],
  ...RELATIONSHIPS.flatMap((name): [string, number, (n: number) => unknown][] => [
    [`verification entries, most in ${name} and one in each other list`, 8_192, n => entries(name, n)],
    [`the controller of a method in ${name}`, 2_048, n => ({ id: did, [name]: [method('#k', 'd'.repeat(n))] })],
    [`the id of a method in ${name}`, 4_096, n => ({ id: did, [name]: [method('#'.repeat(n), did)] })],
    [`a reference in ${name}`, 4_096, n => ({ id: did, [name]: ['#'.repeat(n)] })],
  ]),
];

describe('the DID document walk', () => {
  it.each(limits)('%s: accepts %i and one under, and refuses one over', (_name, limit, document) => {
    expect(accepted(document(limit - 1))).toBe(true);
    expect(accepted(document(limit))).toBe(true);
    expect(accepted(document(limit + 1))).toBe(false);
  });

  it('leaves every identifier outside the six lists to the overall limits', () => {
    const long = 'd'.repeat(4_097);
    const service = { id: long, type: 'LinkedDomains', serviceEndpoint: long, controller: long };
    expect(accepted({ id: did, controller: long, alsoKnownAs: [long], service: [service] })).toBe(true);
  });

  it('measures every string as compact JSON writes it in UTF-8', () => {
    for (const text of ['\u0000\u0001\u001f', '"\\\b\f\n\r\t', '\u007f\u0080\u07ff\u0800\uffff', '\u{1F600}', '\uD800', '\uDC00x']) {
      const document = { id: did, text };
      expect(measureDidDocument(document)).toEqual({ ok: true, bytes: utf8Length(document) });
    }
  });
});

describe('identifiers a resolver is asked for', () => {
  it('resolves a DID of 1 to 2,048 units and a key id of up to 4,096, and asks the resolver for nothing longer', async () => {
    const asked: string[] = [];
    const resolver = { resolve: async (requested: string) => (asked.push(requested), { id: did } as DIDDocument) };
    const cases: [string, string | undefined, boolean][] = [
      ['', undefined, false], ['d', undefined, true], ['d'.repeat(2_047), undefined, true],
      ['d'.repeat(2_048), undefined, true], ['d'.repeat(2_049), undefined, false],
      [did, '#'.repeat(4_095), true], [did, '#'.repeat(4_096), true], [did, '#'.repeat(4_097), false],
    ];
    for (const [requested, key, resolves] of cases) {
      asked.length = 0;
      expect(await resolveBoundedDid(resolver, requested, key)).toEqual(resolves ? { id: did } : null);
      expect(asked).toEqual(resolves ? [requested] : []);
    }
  });
});

describe('the built-in network resolvers', () => {
  const provider = (fetch: () => Promise<Response>) => ({ fetch }) as unknown as FetchProvider;
  const serving = (body: unknown) => vi.fn(async () => new Response(JSON.stringify(body)));
  const cheqd = 'did:cheqd:testnet:limits';
  const resolverUrl = 'https://resolver.example';

  it('refuse a fetched document with more verification entries than the limit, which only the walk counts', async () => {
    for (const [count, resolves] of [[8_192, true], [8_193, false]] as const) {
      const entries = { assertionMethod: Array(count).fill('#key') };
      const web = await new DidWebResolver(provider(serving({ id: did, ...entries }))).resolve(did);
      const envelope = serving({ didDocument: { id: cheqd, ...entries } });
      const onChain = await new DidCheqdResolver(provider(envelope), { resolverUrl }).resolve(cheqd);
      expect([web === null, onChain === null]).toEqual([!resolves, !resolves]);
    }
  });

  it('do not fetch a DID over 2,048 units', async () => {
    const prefix = 'did:cheqd:testnet:';
    for (const [length, fetches] of [[2_048, 1], [2_049, 0]] as const) {
      const fetch = serving({});
      await new DidCheqdResolver(provider(fetch), { resolverUrl }).resolve(`${prefix}${'x'.repeat(length - prefix.length)}`);
      expect(fetch).toHaveBeenCalledTimes(fetches);
    }
  });
});
