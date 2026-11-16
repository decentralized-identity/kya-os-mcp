/**
 * Each DID resolution limit of SPEC.md §4.4.2, one under, at and one over its value: a document or
 * identifier at a limit is accepted, and one over it is refused, never cut to fit. The built-in
 * network resolvers hold what they fetch to the limits that only the document walk measures.
 */

import { describe, it, expect, vi } from 'vitest';
import { measureDidDocument, resolveBoundedDid } from '../did-resource-limits.js';
import { DidWebResolver } from '../did-web-resolver.js';
import { DidCheqdResolver } from '../../integrations/cheqd/resolver.js';
import type { FetchProvider } from '../../providers/base.js';
import { documentOf, keylessMethod } from '../../__tests__/utils/did-documents.js';

const did = 'did:web:limits.example';
const utf8Length = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;
const accepted = (document: unknown) => measureDidDocument(document).ok;

/** A document of `containers` nested containers, the document itself included. */
function nested(containers: number): unknown {
  let value: unknown = 0;
  for (let i = 1; i < containers; i++) value = [value];
  return documentOf({ value }, did);
}

/** `verificationMethod` and the five verification relationships, as SPEC §4.4.2 names them. */
const RELATIONSHIPS = [
  'verificationMethod', 'authentication', 'assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation',
] as const;
type Relationship = (typeof RELATIONSHIPS)[number];

/** `n` verification entries: one in each of the six lists, and the rest in `crowded`. */
const entries = (crowded: Relationship, n: number) =>
  documentOf(Object.fromEntries(RELATIONSHIPS.map(name => [name, Array(name === crowded ? n - 5 : 1).fill('#k')])), did);

const limits: [string, number, (n: number) => unknown][] = [
  ['nesting, in containers', 64, nested],
  ['a member name, in UTF-16 code units', 256, n => documentOf({ ['k'.repeat(n)]: 0 }, did)],
  ['members in all, id included', 8_192, n => documentOf(Object.fromEntries(Array.from({ length: n - 1 }, (_, i) => [`m${i}`, 0])), did)],
  ['compact JSON, in UTF-8 bytes', 1_048_576, n => documentOf({ pad: 'x'.repeat(n - utf8Length(documentOf({ pad: '' }, did))) }, did)],
  ["the document's id, in UTF-16 code units", 2_048, n => documentOf({}, `did:${'d'.repeat(n - 4)}`)],
  ...RELATIONSHIPS.flatMap((name): [string, number, (n: number) => unknown][] => [
    [`verification entries, most in ${name} and one in each other list`, 8_192, n => entries(name, n)],
    [`the controller of a method in ${name}`, 2_048, n => documentOf({ [name]: [keylessMethod('#k', 'd'.repeat(n))] }, did)],
    [`the id of a method in ${name}`, 4_096, n => documentOf({ [name]: [keylessMethod('#'.repeat(n), did)] }, did)],
    [`a reference in ${name}`, 4_096, n => documentOf({ [name]: ['#'.repeat(n)] }, did)],
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
    expect(accepted(documentOf({ controller: long, alsoKnownAs: [long], service: [service] }, did))).toBe(true);
  });

  it('measures every string as compact JSON writes it in UTF-8', () => {
    for (const text of ['\u0000\u0001\u001f', '"\\\b\f\n\r\t', '\u007f\u0080\u07ff\u0800\uffff', '\u{1F600}', '\uD800', '\uDC00x']) {
      const document = documentOf({ text }, did);
      expect(measureDidDocument(document)).toMatchObject({ ok: true, bytes: utf8Length(document) });
    }
  });
});

describe('identifiers a resolver is asked for', () => {
  it('resolves a DID of 1 to 2,048 units and a key id of up to 4,096, and asks the resolver for nothing longer', async () => {
    const asked: string[] = [];
    const resolver = { resolve: async (requested: string) => (asked.push(requested), documentOf({}, did)) };
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
      const web = await new DidWebResolver(provider(serving(documentOf(entries, did)))).resolve(did);
      const envelope = serving({ didDocument: documentOf(entries, cheqd) });
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
