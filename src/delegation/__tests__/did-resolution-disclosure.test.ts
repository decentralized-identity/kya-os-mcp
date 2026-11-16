/**
 * Whoever presents a credential chooses its issuer's DID, and a did:web DID names a host the
 * verifier then reads. Behind split-horizon DNS, or a SafeFetch that resolves names, that host may
 * be an internal one, so a refusal must not tell the presenter what the verifier's network answered:
 * no resolved address, no HTTP status, no byte cap, no redirect target and no transport text. The
 * refusal says why only where that tells the presenter nothing it does not already know: the host
 * it named was refused, with how to admit it, the deadline passed, or the document is not the DID's.
 * Otherwise it says only that the DID could not be resolved, and the operator's log has the rest.
 * The code and whether it is transient are as before. Every test uses the package's public exports.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  buildDidWebDocument,
  createDidWebResolver,
  DelegationCredentialVerifier,
  logger,
  NodeCryptoProvider,
  statusListGzipCodec,
  type AgentIdentity,
  type CredentialStatus,
  type DIDResolver,
} from '../../index.js';
import { createSafeFetch } from '../../card/index.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/index.js';
import { AnsweringFetchProvider, safeFetchProvider, safeFetchServing } from '../../__tests__/utils/adopter-providers.js';
import { credentialJwt, delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { codedAs } from '../../__tests__/utils/refusal-coding.js';

const INTERNAL = 'did:web:jenkins.corp.example';
const INTERNAL_URL = 'https://jenkins.corp.example/.well-known/did.json';
const PRIVATE_ADDRESS = '10.20.30.40';

let key: AgentIdentity;
beforeAll(async () => {
  key = await keyOf(INTERNAL, 'key-1');
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** The refusals of a credential the internal DID issues, as a Data Integrity credential and as a VC-JWT, with what was logged. */
async function refusals(didResolver: DIDResolver) {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const verifier = new DelegationCredentialVerifier({ didResolver, signatureVerifier: async () => ({ valid: true }) });
  const credential = await signedCredential(key, { record: delegationRecord(INTERNAL) });
  const embedded = await verifier.verifyDelegationCredential(credential, { skipCache: true });
  const jwt = await verifier.verifyDelegationJwt(await credentialJwt(credential, key), { skipCache: true });
  return { results: [embedded, jwt], logged: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
}

/** A did:web resolver whose provider answers the internal host's document URL with `answer`. */
const answering = (answer: () => unknown) => createDidWebResolver(new AnsweringFetchProvider(answer));

/** A document of more bytes than any DID document may hold. */
const OVERSIZED = { id: INTERNAL, padding: 'x'.repeat(2 * 1024 * 1024) };

/** The internal DID's document over the byte cap, read directly and through SafeFetch, with what each logs of it. */
const OVERSIZED_READS: [string, () => DIDResolver, string][] = [
  ['directly', () => answering(() => Response.json(OVERSIZED)), 'DID resolution byte limit exceeded'],
  [
    'through SafeFetch',
    () => createDidWebResolver(safeFetchProvider(safeFetchServing({ [INTERNAL_URL]: OVERSIZED }))),
    'safe-fetch: response body exceeds size cap 1048576',
  ],
];

describe('the refusal of a credential whose did:web issuer an internal host answers for', () => {
  it.each<[string, () => unknown, string]>([
    ['an HTTP status', () => new Response('forbidden', { status: 403 }), 'HTTP 403'],
    ['a body that is not JSON', () => new Response('<html>sign in</html>', { status: 200 }), 'not JSON'],
    ['a transport error', () => Promise.reject(new TypeError('connect ECONNREFUSED 10.20.30.40:443')), 'ECONNREFUSED'],
  ])('says only that the DID could not be resolved, and logs %s', async (_name, answer, detail) => {
    const { results, logged } = await refusals(answering(answer));
    for (const result of results) {
      expect(result).toMatchObject({ valid: false, reason: `Could not resolve issuer DID: "${INTERNAL}"`, code: 'did_unavailable', transient: true });
    }
    expect(logged).toContain(detail);
  });

  it.each(OVERSIZED_READS)('says only that the DID could not be resolved, as did_invalid, when its document read %s is over the byte cap, and logs the cap', async (_how, resolver, detail) => {
    const { results, logged } = await refusals(resolver());
    for (const result of results) {
      expect(result).toMatchObject({ valid: false, reason: `Could not resolve issuer DID: "${INTERNAL}"`, ...codedAs('did_invalid') });
    }
    expect(logged).toContain(`${INTERNAL}: ${detail}`);
  });

  it('names no redirect target, and logs it', async () => {
    const { results, logged } = await refusals(
      answering(() => new Response(null, { status: 302, headers: { location: `https://${PRIVATE_ADDRESS}/login` } })),
    );
    for (const result of results) {
      expect(result).toMatchObject({
        valid: false,
        reason:
          `Could not resolve issuer DID: "${INTERNAL}" (Redirect to a private or local host refused. In local development, ` +
          'set development: true; to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.)',
        code: 'host_refused',
        transient: false,
      });
    }
    expect(logged).toContain(PRIVATE_ADDRESS);
  });

  it('says what was refused, and how to admit it, where the host the DID names was refused', async () => {
    const local = 'did:web:issuer.localhost%3A4101';
    const resolver = createDidWebResolver(new AnsweringFetchProvider(() => Response.json(buildDidWebDocument(key))));
    const verifier = new DelegationCredentialVerifier({ didResolver: resolver, signatureVerifier: async () => ({ valid: true }) });
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const result = await verifier.verifyDelegationCredential(
      await signedCredential(await keyOf(local, 'key-1'), { record: delegationRecord(local) }),
      { skipCache: true },
    );
    expect(result.reason).toBe(
      `Could not resolve issuer DID: "${local}" (Request to "issuer.localhost:4101" refused: a private or local host. In local ` +
        'development, set development: true; to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.)',
    );
  });
});

describe('a did:web issuer read through a SafeFetch provider', () => {
  it('whose host resolves to a private address, is refused naming the host and the fix, never the address, which is logged', async () => {
    const safeFetch = createSafeFetch({
      lookup: async () => [{ address: PRIVATE_ADDRESS, family: 4 }],
      transport: async () => {
        throw new Error('never reached');
      },
    });
    const { results, logged } = await refusals(createDidWebResolver(safeFetchProvider(safeFetch)));
    for (const result of results) {
      expect(result).toMatchObject({
        valid: false,
        reason:
          `Could not resolve issuer DID: "${INTERNAL}" (safe-fetch: refusing host "jenkins.corp.example", which resolves to a ` +
          'non-public address: in local development, set development: true; to read a host you own in production, list each ' +
          "origin you own in SafeFetch's allowOrigins)",
        code: 'host_refused',
        transient: false,
      });
      expect(result.reason).not.toContain(PRIVATE_ADDRESS);
    }
    expect(logged).toContain(PRIVATE_ADDRESS);
  });

  it('that redirects to another origin, is refused naming no target, which is logged', async () => {
    const safeFetch = createSafeFetch({
      lookup: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: async () => ({ status: 302, headers: { get: (name: string) => (name === 'location' ? 'https://vault.corp.example/x' : null) }, text: async () => '' }),
    });
    const { results, logged } = await refusals(createDidWebResolver(safeFetchProvider(safeFetch)));
    for (const result of results) {
      expect(result).toMatchObject({ valid: false, code: 'host_refused' });
      expect(result.reason).toBe(`Could not resolve issuer DID: "${INTERNAL}" (safe-fetch: cross-origin redirect from https://jenkins.corp.example blocked)`);
    }
    expect(logged).toContain('https://vault.corp.example');
  });
});

describe("the cheqd status-list resolver, when its list issuer's DID cannot be resolved", () => {
  const LIST_URL = 'https://status.example/lists/1';
  const entry: CredentialStatus = {
    id: `${LIST_URL}#7`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: LIST_URL,
  };
  const list = {
    id: LIST_URL, type: ['VerifiableCredential', 'StatusList2021Credential'], issuer: INTERNAL,
    credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAAA2NgAAAAAP__AwAAAAAAAAA' },
    proof: { type: 'Ed25519Signature2020', verificationMethod: `${INTERNAL}#key-1`, proofPurpose: 'assertionMethod', proofValue: 'z1' },
  };

  /** The status of the entry, its list signed by the internal DID, which `didResolver` resolves, with what was logged. */
  const statusOver = async (didResolver: DIDResolver) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = new CheqdStatusListResolver({
      fetchProvider: new AnsweringFetchProvider((url) => (url === LIST_URL ? Response.json(list) : new Response('forbidden', { status: 403 }))),
      didResolver,
      cryptoProvider: new NodeCryptoProvider(),
      expectedIssuerDid: INTERNAL,
      decompressor: statusListGzipCodec,
    });
    const refusal = await resolver.checkStatus(entry).then(() => undefined, (error: unknown) => error);
    return { refusal, logged: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
  };

  it('says only that it could not be resolved', async () => {
    const { refusal } = await statusOver(answering(() => new Response('forbidden', { status: 403 })));
    expect(refusal).toEqual(new Error(`Could not resolve issuer DID ${INTERNAL}`));
    expect(refusal).toHaveProperty('code', 'did_unavailable');
  });

  it.each(OVERSIZED_READS)('says only that it could not be resolved, as did_invalid, when its document read %s is over the byte cap, and logs the cap', async (_how, didResolver, detail) => {
    const { refusal, logged } = await statusOver(didResolver());
    expect(refusal).toEqual(new Error(`Could not resolve issuer DID ${INTERNAL}`));
    expect(refusal).toHaveProperty('code', 'did_invalid');
    expect(logged).toContain(`${INTERNAL}: ${detail}`);
  });
});

describe("a resolver of the host's own that reports why it found no document", () => {
  it('has the detail shown only where it tells the presenter nothing new', async () => {
    const reporting = (cause: string): DIDResolver =>
      ({ resolve: async () => null, lastFailure: () => ({ cause, detail: 'registry answered 503 from 10.0.0.9' }) }) as DIDResolver;
    const shown = `Could not resolve issuer DID: "${INTERNAL}" (registry answered 503 from 10.0.0.9)`;
    const bare = `Could not resolve issuer DID: "${INTERNAL}"`;
    for (const [cause, reason, code] of [
      ['unavailable', bare, 'did_unavailable'],
      ['too_large', bare, 'did_invalid'],
      ['host_refused', shown, 'host_refused'],
      ['deadline_exceeded', shown, 'deadline_exceeded'],
      ['invalid_document', shown, 'did_invalid'],
    ] as const) {
      const { results } = await refusals(reporting(cause));
      expect(results.map((result) => [result.reason, result.code]), cause).toEqual([[reason, code], [reason, code]]);
    }
  });
});
