/**
 * A refusal asking again cannot lift is coded as a verdict, never as transient: a did:key that does
 * not decode, a did:web DID that names no URL, a did:cheqd DID the cheqd resolver cannot ask for, a
 * DID whose method no resolver of the verifier serves, a DID document over the byte cap, and a status entry whose index is past the
 * end of its list. Each was coded as though the
 * DID or the list could not be read just now, inviting a retry that can only fail again. Every test
 * uses the package's public exports.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildDidWebDocument,
  createDidKeyResolver,
  createDidWebResolver,
  DelegationCredentialVerifier,
  logger,
  type DIDResolver,
} from '../../index.js';
import { createRevocationChecker } from '../../card/index.js';
import { createDidCheqdResolver } from '../../integrations/cheqd/index.js';
import { AnsweringFetchProvider, safeFetchProvider, safeFetchServing } from '../../__tests__/utils/adopter-providers.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { codedAs } from '../../__tests__/utils/refusal-coding.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** How a credential `did` issues is refused by a verifier over `didResolver`, which resolves the DID before anything else. */
async function refusalOf(did: string, didResolver: DIDResolver) {
  const verifier = new DelegationCredentialVerifier({ didResolver, signatureVerifier: async () => ({ valid: true }) });
  const credential = await signedCredential(await keyOf(did, 'key-1'), { record: delegationRecord(did) });
  const { valid, reason, code, transient } = await verifier.verifyDelegationCredential(credential, { skipCache: true });
  return { valid, reason, code, transient };
}

describe('a DID the verifier can never resolve', () => {
  it.each([
    ['a did:key whose key does not decode', 'did:key:zNotAKey'],
    ['a did:key cut short', 'did:key:z6MkhaXgBZDvotDkL5257f'],
  ])('is did_invalid when it is %s, and says so', async (_name, did) => {
    expect(await refusalOf(did, createDidKeyResolver())).toEqual({
      valid: false,
      reason: `Could not resolve issuer DID: "${did}" (the DID is not an Ed25519 did:key whose public key decodes)`,
      ...codedAs('did_invalid'),
    });
  });

  it.each([
    ['whose host decodes to more than a host', 'did:web:issuer.example%40elsewhere.example'],
    ['with an empty path segment', 'did:web:issuer.example::doc'],
    ['with a dot segment', 'did:web:issuer.example:..'],
  ])('is did_invalid, with no request, when it is a did:web DID %s, and says so', async (_name, did) => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(new AnsweringFetchProvider(() => {
      throw new Error('no request expected');
    }));
    expect(await refusalOf(did, resolver)).toEqual({
      valid: false,
      reason: `Could not resolve issuer DID: "${did}" (the DID is not a did:web DID whose host and path make a URL)`,
      ...codedAs('did_invalid'),
    });
  });

  it.each([
    ['a did:cheqd DID whose identifier the method does not allow', 'did:cheqd:mainnet:not.an.id', 'the DID is not a did:cheqd DID of mainnet or testnet'],
    ['a did:cheqd DID of another network', 'did:cheqd:devnet:zAbc', 'the DID is not a did:cheqd DID of mainnet or testnet'],
  ])('is did_invalid, with no request, when the cheqd resolver is given %s', async (_name, did, why) => {
    const endpoint = new AnsweringFetchProvider(() => {
      throw new Error('no request expected');
    });
    const resolver = createDidCheqdResolver(endpoint, { resolverUrl: 'https://resolver.example/1.0/identifiers' });
    expect(await refusalOf(did, resolver)).toEqual({
      valid: false,
      reason: `Could not resolve issuer DID: "${did}" (${why})`,
      ...codedAs('did_invalid'),
    });
  });

  it('is did_invalid when its document is over the byte cap, read directly or through SafeFetch, with the cap logged and not shown', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const did = 'did:web:large.example';
    const url = 'https://large.example/.well-known/did.json';
    const document = { ...buildDidWebDocument(await keyOf(did, 'key-1')), padding: 'x'.repeat(2 * 1024 * 1024) };
    const direct = createDidWebResolver(new AnsweringFetchProvider(() => Response.json(document)));
    const safe = createDidWebResolver(safeFetchProvider(safeFetchServing({ [url]: document })));
    for (const [resolver, detail] of [
      [direct, 'DID resolution byte limit exceeded'],
      [safe, 'safe-fetch: response body exceeds size cap 1048576'],
    ] as const) {
      expect(await refusalOf(did, resolver)).toEqual({ valid: false, reason: `Could not resolve issuer DID: "${did}"`, ...codedAs('did_invalid') });
      expect(warn.mock.calls.flat().join(' ')).toContain(`${did}: ${detail}`);
    }
  });

  it('is still did_unavailable, transient, where a resolver that serves its method found nothing and says no more', async () => {
    expect(await refusalOf('did:ion:EiAbc', { resolve: async () => null })).toMatchObject(codedAs('did_unavailable'));
  });
});

describe('a DID of a method a resolver does not serve', () => {
  it.each<[string, () => DIDResolver]>([
    ['the did:key resolver', () => createDidKeyResolver()],
    ['the did:web resolver', () => createDidWebResolver(new AnsweringFetchProvider(() => new Response('busy', { status: 503 })))],
    ['the did:cheqd resolver', () => createDidCheqdResolver(new AnsweringFetchProvider(() => new Response('busy', { status: 503 })), { resolverUrl: 'https://resolver.example/1.0/identifiers' })],
  ])('records nothing in %s, which cannot know whether another resolver serves it', async (_name, resolver) => {
    const asked = resolver();
    expect(await asked.resolve('did:ion:EiAbc')).toBeNull();
    expect(asked.lastFailure?.('did:ion:EiAbc')).toBeUndefined();
  });

  it.each<[string, () => DIDResolver, string, string]>([
    ['the did:key resolver given a did:web DID', () => createDidKeyResolver(), 'did:web:issuer.example', 'did:web'],
    [
      'the did:web resolver given a did:key DID',
      () => createDidWebResolver(new AnsweringFetchProvider(() => { throw new Error('no request expected'); })),
      'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      'did:key',
    ],
  ])('is did_unavailable where %s alone, and tells the operator it may not serve the method', async (_name, resolver, did, method) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    expect(await refusalOf(did, resolver())).toEqual({ valid: false, reason: `Could not resolve issuer DID: "${did}"`, ...codedAs('did_unavailable') });
    expect(warn).toHaveBeenCalledWith(
      `[kya-os] the DID resolver found no document for "${did}" and gave no cause: it may not serve the ${method} method; ` +
        'if it does not, give the verifier a resolver that does',
    );
  });

  it("leaves a resolver that composes several to report the failure of the one that serves the DID, so a did:web outage stays transient", async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const key = createDidKeyResolver();
    const web = createDidWebResolver(new AnsweringFetchProvider(() => new Response('busy', { status: 503 })));
    const composite: DIDResolver = {
      resolve: async (did) => (await key.resolve(did)) ?? web.resolve(did),
      lastFailure: (did) => key.lastFailure?.(did) ?? web.lastFailure?.(did),
    };
    expect(await refusalOf('did:web:busy.example', composite)).toEqual({
      valid: false,
      reason: 'Could not resolve issuer DID: "did:web:busy.example"',
      ...codedAs('did_unavailable'),
    });
  });
});

describe('a status entry whose index is past the end of its list', () => {
  it('is delegation_malformed, which asking again does not change', async () => {
    const url = 'https://issuer.example/status/1';
    const list = {
      id: url,
      issuer: 'did:key:z',
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      credentialSubject: { statusPurpose: 'revocation', encodedList: 'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA' },
    };
    const check = createRevocationChecker({ fetch: async () => ({ ok: true, status: 200, json: async () => list }) });
    expect(await check({ statusListCredential: url, statusListIndex: '999999999' })).toEqual({
      revoked: true,
      fresh: false,
      reason: 'Bit index 999999999 out of range for the status list',
      ...codedAs('delegation_malformed'),
    });
  });
});
