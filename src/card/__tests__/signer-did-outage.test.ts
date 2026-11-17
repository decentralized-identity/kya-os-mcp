/**
 * When the DID document of a status list's signer, or of a delegation hop's issuer, cannot be read,
 * the Card verifiers refuse as the delegation verifier does: with the code of why, so an outage is
 * `did_unavailable` or `deadline_exceeded`, both transient, and never a verdict on the signer
 * (`status_signer_untrusted`, `invalid_proof`) that asking again could not lift. The reason says
 * why only where that was decided from the DID alone, before any request; what the resolver learned
 * from its network, read directly or through SafeFetch, or what a host's resolver reports, is
 * logged, and the reason says only that the DID could not be resolved. Every accept and refuse
 * decision is as before. The proof verifiers an adopter is given still resolve `false` on every
 * failure when the adopter calls them, as on 1.22.0; the library asks them for the code of why.
 * Every test uses `@kya-os/mcp/card` as an adopter calls it, over real signed hops and lists.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildDidWebDocument, createDidKeyResolver, createDidWebResolver, logger, type DIDResolver } from '../../index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createSafeFetch,
  createStatusListProofVerifier,
  isTransientRefusal,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RefusalCode,
  type RevocationStatusEntry,
} from '../index.js';
import { AnsweringFetchProvider, safeFetchProvider, safeFetchServing } from '../../__tests__/utils/adopter-providers.js';
import { keyOf } from '../../__tests__/utils/delegation-credentials.js';
import { NOW_MS, RESOURCE, now, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const p = parties();
const chain = twoHopChain(p);
const keys = createDidKeyResolver();
const ADDRESS = '10.0.0.9';
const INTERNAL = 'did:web:jenkins.corp.example';
const INTERNAL_URL = 'https://jenkins.corp.example/.well-known/did.json';
const LOCAL = 'did:web:issuer.localhost%3A4101';

/** The did:key resolver, but with `fail` answering for `did`. */
const failingFor = (did: string, fail: DIDResolver): DIDResolver => ({
  resolve: (asked) => (asked === did ? fail.resolve(asked) : keys.resolve(asked)),
  lastFailure: (asked) => (asked === did ? fail.lastFailure?.(asked) : keys.lastFailure?.(asked)),
});

/** `resolver` reading `did`'s document whatever DID it is asked for, as a signer's resolver that reads it from that host. */
const readingAs = (did: string, resolver: DIDResolver): DIDResolver => ({
  resolve: () => resolver.resolve(did),
  lastFailure: () => resolver.lastFailure?.(did),
});

/** A did:web resolver whose provider answers every URL with `answer`. */
const answering = (answer: () => unknown) => createDidWebResolver(new AnsweringFetchProvider(answer));

/** A document of the internal host that names another DID as its id. */
const anotherDids = async () => buildDidWebDocument(await keyOf('did:web:other.example', 'key-1'));

/**
 * Each way a signer's DID document may not be read: how it is resolved, the code it is refused
 * with, what its reason ends with, and what the log says of it, where the test checks.
 */
const OUTAGES: [string, () => Promise<DIDResolver>, RefusalCode, string, string][] = [
  [
    'reports its host unavailable',
    async () => ({ resolve: async () => null, lastFailure: () => ({ cause: 'unavailable', detail: `HTTP 503 from ${ADDRESS}` }) }),
    'did_unavailable',
    '',
    '',
  ],
  ['finds nothing and says no more', async () => ({ resolve: async () => null }), 'did_unavailable', '', ''],
  [
    'throws',
    async () => ({
      resolve: async () => {
        throw new Error(`getaddrinfo EAI_AGAIN ${ADDRESS}`);
      },
    }),
    'did_unavailable',
    '',
    ADDRESS,
  ],
  [
    'reports its host refused',
    async () => ({ resolve: async () => null, lastFailure: () => ({ cause: 'host_refused', detail: `${ADDRESS} refused` }) }),
    'host_refused',
    '',
    '',
  ],
  [
    "reports a document that is not the DID's",
    async () => ({ resolve: async () => null, lastFailure: () => ({ cause: 'invalid_document', detail: 'names another DID as its id' }) }),
    'did_invalid',
    '',
    '',
  ],
  [
    'reads a document over the byte cap from an internal host',
    async () => readingAs(INTERNAL, answering(() => Response.json({ id: INTERNAL, padding: 'x'.repeat(2 * 1024 * 1024) }))),
    'did_invalid',
    '',
    `${INTERNAL}: DID resolution byte limit exceeded`,
  ],
  [
    'reads a document naming another DID from an internal host',
    async () => {
      const document = await anotherDids();
      return readingAs(INTERNAL, answering(() => Response.json(document)));
    },
    'did_invalid',
    '',
    'got did:web:other.example',
  ],
  [
    'reads, through SafeFetch, a name that resolves to a private address',
    async () => {
      const safeFetch = createSafeFetch({
        lookup: async () => [{ address: ADDRESS, family: 4 }],
        transport: async () => {
          throw new Error('never reached');
        },
      });
      return readingAs(INTERNAL, createDidWebResolver(safeFetchProvider(safeFetch)));
    },
    'host_refused',
    '',
    `resolves to the non-public address ${ADDRESS}`,
  ],
  [
    'reads, through SafeFetch, a document naming another DID from an internal host',
    async () => readingAs(INTERNAL, createDidWebResolver(safeFetchProvider(safeFetchServing({ [INTERNAL_URL]: await anotherDids() })))),
    'did_invalid',
    '',
    'got did:web:other.example',
  ],
  [
    'refuses, before any request, the local host the DID names',
    async () => readingAs(LOCAL, answering(() => Response.json({}))),
    'host_refused',
    ' (Request to "issuer.localhost:4101" refused: a private or local host. In local development, set development: true; ' +
      'to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.)',
    '',
  ],
];

/** A resolver that never answers. */
const stalled: DIDResolver = { resolve: () => new Promise(() => undefined) };

/** A resolver whose document for a DID lists no key at all. */
const keyless: DIDResolver = { resolve: async (did) => ({ id: did, verificationMethod: [] }) };

/** The code and transient flag of `code`. */
const coded = (code: RefusalCode) => ({ code, transient: isTransientRefusal(code) });

describe("a status list whose signer's DID document cannot be read", () => {
  const entry = chain[0].credentialStatus as RevocationStatusEntry;
  const checkWith = (didResolver: DIDResolver) =>
    createRevocationChecker({
      fetch: serve(statusList(p.acme)),
      now,
      verifyStatusList: createStatusListProofVerifier({ didResolver: failingFor(p.acme.did, didResolver), dependencyTimeoutMs: 20 }),
    })(entry, { credentialIssuer: p.acme.did });

  it.each(OUTAGES)('is refused with the code of why, when its resolver %s', async (_name, resolver, code, suffix, logged) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const answer = await checkWith(await resolver());
    expect(answer).toEqual({ revoked: true, fresh: false, reason: `Could not resolve issuer DID: "${p.acme.did}"${suffix}`, ...coded(code) });
    expect(answer.reason).not.toContain(ADDRESS);
    expect(warn.mock.calls.flat().join(' ')).toContain(logged);
  });

  it('is refused as deadline_exceeded when its resolver does not answer in time', async () => {
    expect(await checkWith(stalled)).toEqual({ revoked: true, fresh: false, reason: 'DID resolution deadline exceeded', ...coded('deadline_exceeded') });
  });

  it('is still refused as status_signer_untrusted when the document it reads lists no key for the proof', async () => {
    expect(await checkWith(keyless)).toMatchObject({ revoked: true, fresh: false, ...coded('status_signer_untrusted') });
  });

  it('is still read when the document is found', async () => {
    expect(await checkWith(keys)).toEqual({ revoked: false, fresh: true });
  });
});

describe("a delegation hop whose issuer's DID document cannot be read", () => {
  const verifyWith = (didResolver: DIDResolver) =>
    verifyRequestDelegation(
      { meta: toDelegationChainMeta(chain), proofDid: p.subAgent.did, action: 'orders.place' },
      {
        resource: RESOURCE,
        trustedRootIssuers: [p.acme.did],
        verifyHopProof: createDelegationProofVerifier({ didResolver: failingFor(p.agent.did, didResolver), dependencyTimeoutMs: 20 }),
        checkRevocation: createRevocationChecker({
          fetch: serve(statusList(p.acme)),
          now,
          verifyStatusList: createStatusListProofVerifier({ didResolver: keys }),
        }),
        now: () => NOW_MS,
      },
    );

  /** The parts of a refusal these tests pin. */
  const refusalOf = async (didResolver: DIDResolver) => {
    const result = await verifyWith(didResolver);
    return result.ok ? result : { code: result.code, refusalCode: result.refusalCode, transient: result.transient, reasons: result.reasons };
  };

  it.each(OUTAGES)('is refused with the code of why, when its resolver %s', async (_name, resolver, code, suffix, logged) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    expect(await refusalOf(await resolver())).toEqual({
      code: 'delegation_invalid',
      refusalCode: code,
      transient: isTransientRefusal(code),
      reasons: [`hop 1: Could not resolve issuer DID: "${p.agent.did}"${suffix}`],
    });
    expect(warn.mock.calls.flat().join(' ')).toContain(logged);
  });

  it('is refused as deadline_exceeded when its resolver does not answer in time', async () => {
    expect(await refusalOf(stalled)).toEqual({
      code: 'delegation_invalid',
      refusalCode: 'deadline_exceeded',
      transient: true,
      reasons: ['hop 1: DID resolution deadline exceeded'],
    });
  });

  it('is still refused as invalid_proof when the document it reads lists no key for the proof', async () => {
    expect(await refusalOf(keyless)).toEqual({
      code: 'delegation_invalid',
      refusalCode: 'invalid_proof',
      transient: false,
      reasons: ['hop 1: proof did not verify'],
    });
  });

  it('is still accepted when the document is found', async () => {
    expect((await verifyWith(keys)).ok).toBe(true);
  });
});

describe('the proof verifiers an adopter is given, called by the adopter', () => {
  it.each(OUTAGES)('resolve false, as on 1.22.0, when the resolver %s', async (_name, resolver) => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const failing = await resolver();
    const verifyList = createStatusListProofVerifier({ didResolver: failingFor(p.acme.did, failing), dependencyTimeoutMs: 20 });
    const verifyHop = createDelegationProofVerifier({ didResolver: failingFor(p.agent.did, failing), dependencyTimeoutMs: 20 });
    expect(await verifyList(statusList(p.acme))).toBe(false);
    expect(await verifyHop(chain[1])).toBe(false);
  });

  it('resolve false, as on 1.22.0, when the resolver does not answer in time', async () => {
    expect(await createStatusListProofVerifier({ didResolver: failingFor(p.acme.did, stalled), dependencyTimeoutMs: 20 })(statusList(p.acme))).toBe(false);
    expect(await createDelegationProofVerifier({ didResolver: failingFor(p.agent.did, stalled), dependencyTimeoutMs: 20 })(chain[1])).toBe(false);
  });

  it("leave an outage a verdict on the proof, as on 1.22.0, where the adopter's own function wraps them", async () => {
    const verify = createStatusListProofVerifier({ didResolver: failingFor(p.acme.did, stalled), dependencyTimeoutMs: 20 });
    const answer = await createRevocationChecker({ fetch: serve(statusList(p.acme)), now, verifyStatusList: (list) => verify(list) })(
      chain[0].credentialStatus as RevocationStatusEntry,
      { credentialIssuer: p.acme.did },
    );
    expect(answer).toEqual({ revoked: true, fresh: false, reason: 'status-list proof rejected', ...coded('status_signer_untrusted') });
  });
});
