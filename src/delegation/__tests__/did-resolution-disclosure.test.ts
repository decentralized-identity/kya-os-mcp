/**
 * Whoever presents a credential chooses its issuer's DID, and a did:web DID names a host the
 * verifier then reads. Behind split-horizon DNS, or a SafeFetch that resolves names, that host may
 * be an internal one, so a refusal tells the presenter nothing the verifier learned from its
 * network: no HTTP status, no byte cap, no redirect, nothing of a document read, no transport text,
 * and not even that a name resolves to a private address. A refusal says why only where that was
 * decided from the DID alone, before any request or DNS lookup (the private-network rule refusing
 * the local name the DID names, a did:key that does not decode), or where the resolution ran out of
 * time, which the presenter sees anyway. Otherwise it says only that the DID could not be resolved,
 * and that the operator's log has the rest, which it does, once. The code and whether it is transient are as before. The
 * delegation verifier's Data Integrity and VC-JWT credentials and the cheqd status-list resolver are
 * checked here, the Card proof verifiers in `card/__tests__/signer-did-outage.test.ts`. Every test
 * uses the package's public exports.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildDidWebDocument,
  createDidKeyResolver,
  createDidWebResolver,
  DelegationCredentialVerifier,
  logger,
  NodeCryptoProvider,
  statusListGzipCodec,
  type CredentialStatus,
  type DIDResolver,
  type RefusalCode,
} from '../../index.js';
import { createSafeFetch, type SafeFetch, type SafeFetchTransport } from '../../card/index.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/index.js';
import { AnsweringFetchProvider, safeFetchProvider, safeFetchServing } from '../../__tests__/utils/adopter-providers.js';
import { credentialJwt, delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { codedAs } from '../../__tests__/utils/refusal-coding.js';

const INTERNAL = 'did:web:jenkins.corp.example';
const INTERNAL_URL = 'https://jenkins.corp.example/.well-known/did.json';
const LOCAL = 'did:web:issuer.localhost%3A4101';
const PRIVATE_ADDRESS = '10.20.30.40';
/** What a refusal ends with where the operator's log has what it withholds. */
const LOG_SAYS_WHY = "; the verifier's log says why";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Everything logged as a warning since `warn` began spying, as one text. */
const loggedBy = (warn: { mock: { calls: unknown[][] } }): string => warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n');

/** The refusals of a credential `issuer` issues, as a Data Integrity credential and as a VC-JWT, with what was logged. */
async function refusals(didResolver: DIDResolver, issuer = INTERNAL) {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const key = await keyOf(issuer, 'key-1');
  const verifier = new DelegationCredentialVerifier({ didResolver, signatureVerifier: async () => ({ valid: true }) });
  const credential = await signedCredential(key, { record: delegationRecord(issuer) });
  const embedded = await verifier.verifyDelegationCredential(credential, { skipCache: true });
  const jwt = await verifier.verifyDelegationJwt(await credentialJwt(credential, key), { skipCache: true });
  return { results: [embedded, jwt], logged: loggedBy(warn) };
}

/** A did:web resolver whose provider answers every URL with `answer`. */
const answering = (answer: () => unknown, dependencyTimeoutMs?: number) =>
  createDidWebResolver(new AnsweringFetchProvider(answer), { dependencyTimeoutMs });

/** A did:web resolver that reads through `safeFetch`. */
const reading = (safeFetch: SafeFetch) => createDidWebResolver(safeFetchProvider(safeFetch));

/** A SafeFetch whose names resolve to `address`, over `transport`. */
const safeFetchAt = (address: string, transport: SafeFetchTransport) => createSafeFetch({ lookup: async () => [{ address, family: 4 }], transport });

/** A document of more bytes than any DID document may hold. */
const OVERSIZED = { id: INTERNAL, padding: 'x'.repeat(2 * 1024 * 1024) };

/** A document of the internal DID's host that names another DID as its id. */
const ANOTHER_DIDS = async () => buildDidWebDocument(await keyOf('did:web:other.example', 'key-1'));

/**
 * What the internal DID's host, or the network on the way to it, may answer: how its resolver reads
 * it, the code the refusal carries, and what the operator's log says of it.
 */
const NETWORK_ANSWERS: [string, () => Promise<DIDResolver>, RefusalCode, string][] = [
  ['an HTTP status', async () => answering(() => new Response('forbidden', { status: 403 })), 'did_unavailable', 'HTTP 403'],
  ['a body that is not JSON', async () => answering(() => new Response('<html>sign in</html>', { status: 200 })), 'did_unavailable', 'not JSON'],
  ['a transport error', async () => answering(() => Promise.reject(new TypeError(`connect ECONNREFUSED ${PRIVATE_ADDRESS}:443`))), 'did_unavailable', 'ECONNREFUSED'],
  [
    'a redirect to a private address',
    async () => answering(() => new Response(null, { status: 302, headers: { location: `https://${PRIVATE_ADDRESS}/login` } })),
    'host_refused',
    PRIVATE_ADDRESS,
  ],
  ['a document over the byte cap', async () => answering(() => Response.json(OVERSIZED)), 'did_invalid', `${INTERNAL}: DID resolution byte limit exceeded`],
  ['a document that is not a JSON object', async () => answering(() => Response.json([INTERNAL])), 'did_invalid', 'refused: document is not a JSON object'],
  [
    'a document with a verification method of no id',
    async () => answering(() => Response.json({ id: INTERNAL, verificationMethod: [{ type: 'JsonWebKey2020', controller: INTERNAL }] })),
    'did_invalid',
    'Invalid DID Document structure',
  ],
  [
    'a document naming another DID as its id',
    async () => {
      const document = await ANOTHER_DIDS();
      return answering(() => Response.json(document));
    },
    'did_invalid',
    'got did:web:other.example',
  ],
  [
    'through SafeFetch, a name that resolves to a private address',
    async () => reading(safeFetchAt(PRIVATE_ADDRESS, async () => { throw new Error('never reached'); })),
    'did_unavailable',
    `resolves to the non-public address ${PRIVATE_ADDRESS}`,
  ],
  [
    'through SafeFetch, a redirect to another origin',
    async () => reading(safeFetchAt('93.184.216.34', async () => ({ status: 302, headers: { get: (name: string) => (name === 'location' ? 'https://vault.corp.example/x' : null) }, text: async () => '' }))),
    'host_refused',
    'https://vault.corp.example',
  ],
  [
    'through SafeFetch, a document over the byte cap',
    async () => reading(safeFetchServing({ [INTERNAL_URL]: OVERSIZED })),
    'did_invalid',
    'safe-fetch: response body exceeds size cap 1048576',
  ],
  [
    'through SafeFetch, a document naming another DID as its id',
    async () => reading(safeFetchServing({ [INTERNAL_URL]: await ANOTHER_DIDS() })),
    'did_invalid',
    'got did:web:other.example',
  ],
];

/** The remedy the private-network rule gives for the local host the local DID names. */
const LOCAL_REFUSED =
  'Request to "issuer.localhost:4101" refused: a private or local host. In local development, set development: true; ' +
  'to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.';

describe('the refusal of a credential whose did:web issuer an internal host answers for', () => {
  it.each(NETWORK_ANSWERS)('says only that the DID could not be resolved, and that the log has the rest, for %s', async (_name, resolver, code, logged) => {
    const outcome = await refusals(await resolver());
    for (const result of outcome.results) {
      expect(result).toMatchObject({ valid: false, reason: `Could not resolve issuer DID: "${INTERNAL}"${LOG_SAYS_WHY}`, ...codedAs(code) });
    }
    expect(outcome.logged).toContain(logged);
    // The library's resolver logged it as it read, so no refusal logs it again.
    expect(outcome.logged).not.toContain('the DID resolver could not resolve');
  });
});

describe('the refusal of a credential whose issuer is refused from its DID alone, or in time', () => {
  it('says what was refused, and how to admit it, where the private-network rule refuses the local host the DID names', async () => {
    const { results } = await refusals(answering(() => Response.json({})), LOCAL);
    for (const result of results) {
      expect(result).toMatchObject({ valid: false, reason: `Could not resolve issuer DID: "${LOCAL}" (${LOCAL_REFUSED})`, ...codedAs('host_refused') });
    }
  });

  it('says why where a did:key does not decode', async () => {
    const { results } = await refusals(createDidKeyResolver(), 'did:key:zNotAKey');
    for (const result of results) {
      expect(result).toMatchObject({
        reason: 'Could not resolve issuer DID: "did:key:zNotAKey" (the DID is not an Ed25519 did:key whose public key decodes)',
        ...codedAs('did_invalid'),
      });
    }
  });

  it("says why where the resolver's deadline passed", async () => {
    const { results } = await refusals(answering(() => new Promise(() => undefined), 20));
    for (const result of results) {
      expect(result).toMatchObject({
        reason: `Could not resolve issuer DID: "${INTERNAL}" (DID resolution deadline exceeded: no document arrived within 20 ms)`,
        ...codedAs('deadline_exceeded'),
      });
    }
  });
});

describe("the cheqd status-list resolver, when its list issuer's DID cannot be resolved", () => {
  const LIST_URL = 'https://status.example/lists/1';
  const entry: CredentialStatus = {
    id: `${LIST_URL}#7`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: LIST_URL,
  };

  /** How the entry's status is refused, its list signed by `issuer`, which `didResolver` resolves, with what was logged. */
  const statusOver = async (didResolver: DIDResolver, issuer = INTERNAL) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const list = {
      id: LIST_URL, type: ['VerifiableCredential', 'StatusList2021Credential'], issuer,
      credentialSubject: { type: 'StatusList2021', statusPurpose: 'revocation', encodedList: 'H4sIAAAAAAAAA2NgAAAAAP__AwAAAAAAAAA' },
      proof: { type: 'Ed25519Signature2020', verificationMethod: `${issuer}#key-1`, proofPurpose: 'assertionMethod', proofValue: 'z1' },
    };
    const resolver = new CheqdStatusListResolver({
      fetchProvider: new AnsweringFetchProvider((url) => (url === LIST_URL ? Response.json(list) : new Response('forbidden', { status: 403 }))),
      didResolver,
      cryptoProvider: new NodeCryptoProvider(),
      expectedIssuerDid: issuer,
      decompressor: statusListGzipCodec,
    });
    const refusal: unknown = await resolver.checkStatus(entry).then(() => undefined, (error: unknown) => error);
    return { refusal, logged: loggedBy(warn) };
  };

  it.each(NETWORK_ANSWERS)('says only that it could not be resolved, and logs the rest, for %s', async (_name, didResolver, code, logged) => {
    const outcome = await statusOver(await didResolver());
    expect(outcome.refusal).toEqual(new Error(`Could not resolve issuer DID ${INTERNAL}${LOG_SAYS_WHY}`));
    expect(outcome.refusal).toHaveProperty('code', code);
    expect(outcome.logged).toContain(logged);
  });

  it('says what was refused where the private-network rule refuses the local host its DID names', async () => {
    const { refusal } = await statusOver(answering(() => Response.json({})), LOCAL);
    expect(refusal).toEqual(new Error(`Could not resolve issuer DID ${LOCAL} (${LOCAL_REFUSED})`));
    expect(refusal).toHaveProperty('code', 'host_refused');
  });
});

describe("a resolver of the host's own that reports why it found no document", () => {
  const DETAIL = 'registry answered 503 from 10.0.0.9';

  it('has its detail shown only where the deadline passed, and logged where it is not, since the library cannot tell what else it learned from its network', async () => {
    const reporting = (cause: string): DIDResolver => ({ resolve: async () => null, lastFailure: () => ({ cause, detail: DETAIL }) }) as DIDResolver;
    const bare = `Could not resolve issuer DID: "${INTERNAL}"`;
    for (const [cause, reason, code, loggedLines] of [
      ['unavailable', `${bare}${LOG_SAYS_WHY}`, 'did_unavailable', 2],
      ['too_large', `${bare}${LOG_SAYS_WHY}`, 'did_invalid', 2],
      ['host_refused', `${bare}${LOG_SAYS_WHY}`, 'host_refused', 2],
      ['invalid_document', `${bare}${LOG_SAYS_WHY}`, 'did_invalid', 2],
      ['deadline_exceeded', `${bare} (${DETAIL})`, 'deadline_exceeded', 0],
    ] as const) {
      vi.restoreAllMocks();
      const { results, logged } = await refusals(reporting(cause));
      expect(results.map((result) => [result.reason, result.code]), cause).toEqual([[reason, code], [reason, code]]);
      // One line for each refusal, the embedded credential's and the VC-JWT's.
      expect(logged.split('\n').filter((line) => line.includes(DETAIL)), cause).toEqual(
        Array.from({ length: loggedLines }, () => `[kya-os] the DID resolver could not resolve "${INTERNAL}": ${DETAIL}`),
      );
    }
  });

  it('says the log has why where it gives no cause, and the log says it gave none', async () => {
    const { results, logged } = await refusals({ resolve: async () => null } as DIDResolver);
    for (const result of results) {
      expect(result).toMatchObject({ valid: false, reason: `Could not resolve issuer DID: "${INTERNAL}"${LOG_SAYS_WHY}`, ...codedAs('did_unavailable') });
    }
    expect(logged).toContain(`the DID resolver found no document for "${INTERNAL}" and gave no cause`);
  });
});
