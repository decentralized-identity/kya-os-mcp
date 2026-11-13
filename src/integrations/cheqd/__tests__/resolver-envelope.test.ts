/**
 * The cheqd resolver asks for the DID document alone, and reads a DID Resolution Result sent anyway
 * within the envelope's own limits (4 MiB, nesting 65, 131,072 members), so a DID that has
 * published hundreds or thousands of resources still resolves. The document inside the envelope
 * meets every document limit.
 */

import { describe, expect, it, vi } from 'vitest';
import { DidCheqdResolver } from '../resolver.js';
import type { FetchProvider } from '../../../providers/base.js';

const did = 'did:cheqd:mainnet:zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY';
const resolverUrl = 'https://resolver.example';
const document = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
  id: did, controller: [did],
  verificationMethod: [{
    id: `${did}#key-1`, type: 'Ed25519VerificationKey2020', controller: did,
    publicKeyMultibase: 'z6MkkVbyHJLLjdjU5B62DaJ4mkdMdUeQUG6vVYH3yiUJ8Gk4',
  }],
  authentication: [`${did}#key-1`], assertionMethod: [`${did}#key-1`],
};

/** A resolution result as the cheqd resolver writes it, for a DID that published `resources` resources. */
function envelope(resources: number, didDocument: unknown = document) {
  const resource = (i: number) => `${String(i).padStart(8, '0')}-5d18-4867-83e3-b47f5a756f02`;
  return {
    '@context': 'https://w3id.org/did-resolution/v1',
    didResolutionMetadata: {
      contentType: 'application/did+ld+json', retrieved: '2026-11-13T00:00:00Z',
      did: { didString: did, methodSpecificId: 'zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY', method: 'cheqd' },
    },
    didDocument,
    didDocumentMetadata: {
      created: '2023-01-25T11:58:10.390039347Z', versionId: 'e5615fc2-6f13-42b1-989c-49576a574cef', deactivated: false,
      linkedResourceMetadata: Array.from({ length: resources }, (_, i) => ({
        resourceURI: `${did}/resources/${resource(i)}`, resourceCollectionId: 'zF7rhDBfUt9d1gJPjx7s1JXfUY7oVWkY',
        resourceId: resource(i), resourceName: 'IssuerStatusList', resourceType: 'StatusList2021Revocation',
        mediaType: 'application/json', resourceVersion: '', alsoKnownAs: [], checksum: 'a'.repeat(64),
        created: '2023-01-30T12:15:22Z', nextVersionId: resource(i + 1), previousVersionId: resource(i - 1),
      })),
    },
  };
}

function serving(body: string) {
  const fetch = vi.fn(async (_url: string, _init?: RequestInit) => new Response(body));
  return { fetch, resolver: new DidCheqdResolver({ fetch } as unknown as FetchProvider, { resolverUrl }) };
}

const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

describe('DidCheqdResolver and the resolution envelope', () => {
  it('asks for the document alone, and resolves a bare document', async () => {
    const { fetch, resolver } = serving(JSON.stringify(document));
    expect(await resolver.resolve(did)).toEqual(document);
    expect(fetch.mock.calls.map(([url, init]) => [url, new Headers((init as RequestInit).headers).get('accept')]))
      .toEqual([[`${resolverUrl}/1.0/identifiers/${did}`, 'application/did+ld+json']]);
  });

  it.each([681, 2_000, 6_000])('resolves an envelope listing %i resources', async resources => {
    expect(await serving(JSON.stringify(envelope(resources))).resolver.resolve(did)).toEqual(document);
  });

  it('refuses an envelope one byte over 4 MiB, and reads one of exactly 4 MiB', async () => {
    const body = JSON.stringify(envelope(6_000));
    const atCap = body + ' '.repeat(4 * 1_048_576 - bytes(envelope(6_000)));
    expect(await serving(atCap).resolver.resolve(did)).toEqual(document);
    expect(await serving(`${atCap} `).resolver.resolve(did)).toBeNull();
  });

  it('refuses an envelope nested 66 deep, and reads one nested 65 deep', async () => {
    const nested = (containers: number) => {
      let value: unknown = 0;
      for (let i = 1; i < containers; i++) value = [value];
      return JSON.stringify({ ...envelope(1), deep: value });
    };
    expect(await serving(nested(65)).resolver.resolve(did)).toEqual(document);
    expect(await serving(nested(66)).resolver.resolve(did)).toBeNull();
  });

  it('holds the document inside an envelope to every document limit', async () => {
    const over = { ...document, assertionMethod: Array(8_193).fill(`${did}#key-1`) };
    expect(await serving(JSON.stringify(envelope(10, over))).resolver.resolve(did)).toBeNull();
    const big = { ...document, pad: 'x'.repeat(1_048_576 - bytes({ ...document, pad: '' }) + 1) };
    expect(await serving(JSON.stringify(envelope(10, big))).resolver.resolve(did)).toBeNull();
  });
});
