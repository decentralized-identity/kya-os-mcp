/**
 * A fetch provider whose responses have no stream body, as on 1.22.0, where the readers called
 * `json()`. The library's own `createSafeFetch` answers `{ ok, status, json, text }`, and adopters hand
 * that to the did:web resolver as their `FetchProvider`'s answer. Such a response is read through its
 * `text()`, or else its `json()`, under the read's one deadline, its byte cap counted in UTF-8 and its
 * JSON shape limits, so what a stream body may not hold, a response read this way may not either.
 * Every test uses the package's public exports, as an adopter would.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import {
  buildDidWebDocument,
  createDidWebResolver,
  DelegationCredentialVerifier,
  NodeCryptoProvider,
  RuntimeFetchProvider,
  statusListGzipCodec,
  type AgentIdentity,
  type CredentialStatus,
  type DIDDocument,
} from '../../index.js';
import { CheqdStatusListResolver, createDidCheqdResolver } from '../../integrations/cheqd/index.js';
import { AnsweringFetchProvider, safeFetchProvider, safeFetchServing } from '../../__tests__/utils/adopter-providers.js';
import { credentialJwt, delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';

const ISSUER = 'did:web:issuer.example';
const DOCUMENT_URL = 'https://issuer.example/.well-known/did.json';
const LIST_URL = 'https://status.example/lists/1';

let key: AgentIdentity;
let document: DIDDocument;
beforeAll(async () => {
  key = await keyOf(ISSUER, 'key-1');
  document = buildDidWebDocument(key);
});

describe('a FetchProvider that answers with what createSafeFetch returns', () => {
  it('resolves a did:web document', async () => {
    const provider = safeFetchProvider(safeFetchServing({ [DOCUMENT_URL]: document }));
    expect(await createDidWebResolver(provider).resolve(ISSUER)).toEqual(document);
    expect(provider.requested).toEqual([DOCUMENT_URL]);
  });

  it('answers text() with the exact text SafeFetch read, so that text is what is measured and parsed', async () => {
    const written = `{ "id" : ${JSON.stringify(ISSUER)} }\n`;
    const response = await safeFetchServing({ [DOCUMENT_URL]: written })(DOCUMENT_URL);
    expect(await response.text?.()).toBe(written);
    expect(await response.json()).toEqual({ id: ISSUER });
  });

  it('verifies a credential that DID issued', async () => {
    const provider = safeFetchProvider(safeFetchServing({ [DOCUMENT_URL]: document }));
    const credential = await signedCredential(key, { record: delegationRecord(ISSUER) });
    const verifier = new DelegationCredentialVerifier({ didResolver: createDidWebResolver(provider) });
    expect(await verifier.verifyDelegationJwt(await credentialJwt(credential, key))).toMatchObject({ valid: true });
  });

  it('reads a status list through a RuntimeFetchProvider whose fetch answers so', async () => {
    const list = {
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      credentialSubject: { type: 'StatusList2021', encodedList: 'H4sIAAAAAAAAA2NgAAAAAP__AwAAAAAAAAA' },
    };
    const safeFetch = safeFetchServing({ [LIST_URL]: list });
    class SafeFetchRuntimeProvider extends RuntimeFetchProvider {
      override async fetch(url: string): Promise<Response> {
        return (await safeFetch(url)) as unknown as Response;
      }
    }
    expect(await new SafeFetchRuntimeProvider().fetchStatusList(LIST_URL)).toEqual(list);
  });

  it('resolves a did:cheqd document through the cheqd resolver', async () => {
    const did = 'did:cheqd:testnet:abc123';
    const cheqdDocument = { ...document, id: did };
    const provider = safeFetchProvider(
      safeFetchServing({ [`https://resolver.example/1.0/identifiers/${did}`]: { didDocument: cheqdDocument } }),
    );
    const resolver = createDidCheqdResolver(provider, { resolverUrl: 'https://resolver.example' });
    expect(await resolver.resolve(did)).toEqual(cheqdDocument);
  });
});

/** A status entry on the list at {@link LIST_URL}. */
const ENTRY: CredentialStatus = {
  id: `${LIST_URL}#7`,
  type: 'StatusList2021Entry',
  statusPurpose: 'revocation',
  statusListIndex: '7',
  statusListCredential: LIST_URL,
};

/** Why the cheqd status-list resolver could not read its list from a provider that answers `response`. */
async function refusalOf(response: unknown, dependencyTimeoutMs?: number): Promise<string> {
  const resolver = new CheqdStatusListResolver({
    fetchProvider: new AnsweringFetchProvider(() => response),
    didResolver: { resolve: async () => null },
    cryptoProvider: new NodeCryptoProvider(),
    expectedIssuerDid: ISSUER,
    decompressor: statusListGzipCodec,
    ...(dependencyTimeoutMs === undefined ? {} : { dependencyTimeoutMs }),
  });
  const error: unknown = await resolver.checkStatus(ENTRY).then(() => undefined, (thrown: unknown) => thrown);
  return error instanceof Error ? error.message : `no refusal: ${String(error)}`;
}

/** A response with no body that answers `text()` with `text`. */
const textResponse = (text: unknown) => ({ ok: true, status: 200, text: async () => text });
/** A response with no body and no `text()` that answers `json()` with `value`. */
const jsonResponse = (value: unknown) => ({ ok: true, status: 200, json: async () => value });
/** A promise that never settles. */
const never = (): Promise<never> => new Promise<never>(() => undefined);

/** JSON text of arrays nested `depth` levels deep. */
const nested = (depth: number): string => `${'['.repeat(depth)}${']'.repeat(depth)}`;

describe('a response read through text() or json()', () => {
  it('reads text() before json(), so the exact text is what is measured and parsed', async () => {
    const both = { ok: true, status: 200, text: async () => JSON.stringify(document), json: async () => ({ id: 'other' }) };
    const resolver = createDidWebResolver(new AnsweringFetchProvider(() => both));
    expect(await resolver.resolve(ISSUER)).toEqual(document);
  });

  it('reads json() when the response has no text()', async () => {
    const resolver = createDidWebResolver(new AnsweringFetchProvider(() => jsonResponse(document)));
    expect(await resolver.resolve(ISSUER)).toEqual(document);
  });

  it('ends the read at the deadline when text() or json() never answers', async () => {
    for (const response of [{ ok: true, status: 200, text: never }, { ok: true, status: 200, json: never }]) {
      const started = Date.now();
      expect(await refusalOf(response, 50)).toBe('Status list fetch deadline exceeded');
      expect(Date.now() - started).toBeLessThan(2_000);
      const resolver = createDidWebResolver(new AnsweringFetchProvider(() => response), { dependencyTimeoutMs: 50 });
      expect(await resolver.resolve(ISSUER)).toBeNull();
    }
  });

  it('refuses text over the byte cap, counted in UTF-8, though its UTF-16 length is under it', async () => {
    // Three UTF-8 bytes each: 349,525 of them and two quote marks are 1,048,577 bytes, one over 1 MiB.
    const text = `"${'€'.repeat(349_525)}"`;
    expect(text.length).toBeLessThan(1_048_576);
    expect(await refusalOf(textResponse(text))).toBe('Status list fetch byte limit exceeded');
    expect(await refusalOf(textResponse(text.slice(0, -2) + '"'))).not.toBe('Status list fetch byte limit exceeded');
  });

  it('counts a two-byte character as two, a surrogate pair as four and a lone surrogate as three, as UTF-8 writes them', async () => {
    const LIMIT = 'Status list fetch byte limit exceeded';
    // Each set fills 1 MiB, two quote marks included, to within a character, and one more is over it.
    for (const [character, fitting] of [['é', 524_287], ['\u{1F600}', 262_143], ['\uD800', 349_524]] as const) {
      const text = (count: number) => `"${character.repeat(count)}"`;
      expect(await refusalOf(textResponse(text(fitting))), `${fitting} of U+${character.codePointAt(0)!.toString(16)}`).not.toBe(LIMIT);
      expect(await refusalOf(textResponse(text(fitting + 1))), `${fitting + 1} of U+${character.codePointAt(0)!.toString(16)}`).toBe(LIMIT);
    }
  });

  it('refuses a json() value whose JSON text is over the byte cap', async () => {
    expect(await refusalOf(jsonResponse('x'.repeat(1_048_575)))).toBe('Status list fetch byte limit exceeded');
  });

  it('holds text() and json() alike to the JSON shape limits', async () => {
    expect(await refusalOf(textResponse(nested(65)))).toBe('JSON nesting limit exceeded');
    expect(await refusalOf(jsonResponse(JSON.parse(nested(65))))).toBe('JSON nesting limit exceeded');
    const members = Object.fromEntries(Array.from({ length: 8_193 }, (_, i) => [`m${i}`, i]));
    expect(await refusalOf(jsonResponse(members))).toBe('JSON member limit exceeded');
  });

  it('refuses a text() that answers no string, and a json() value that has no JSON text', async () => {
    expect(await refusalOf(textResponse({ id: ISSUER }))).toBe('Status list fetch response text() did not answer a string');
    for (const value of [undefined, () => 1, 10n]) {
      expect(await refusalOf(jsonResponse(value))).toBe('Status list fetch response json() answered a value with no JSON text');
    }
  });

  it('refuses a response with none of body, text() and json(), saying what a provider must return', async () => {
    expect(await refusalOf({ ok: true, status: 200 })).toBe(
      'Status list fetch response has no body to read: a FetchProvider must return a Response whose body is a ' +
        'ReadableStream, or a response with a text() or json() method',
    );
  });

  it('still refuses a response that is not ok, whatever it would read as', async () => {
    expect(await refusalOf({ ok: false, status: 503, text: async () => '{}' })).toBe(
      `Status list fetch failed: HTTP 503 for "${LIST_URL}"`,
    );
  });
});
