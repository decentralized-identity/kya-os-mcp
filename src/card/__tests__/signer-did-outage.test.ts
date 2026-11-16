/**
 * When the DID document of a status list's signer, or of a delegation hop's issuer, cannot be read,
 * the Card verifiers refuse as the delegation verifier does: with the code of why, so an outage is
 * `did_unavailable` or `deadline_exceeded`, both transient, and never a verdict on the signer
 * (`status_signer_untrusted`, `invalid_proof`) that asking again could not lift. The reason says
 * the DID could not be resolved, and never what the resolver's network answered, which is logged.
 * Every accept and refuse decision is as before. Every test uses `@kya-os/mcp/card` as an adopter
 * calls it, over real signed hops and lists.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDidKeyResolver, logger, type DIDResolver } from '../../index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createStatusListProofVerifier,
  isTransientRefusal,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RefusalCode,
  type RevocationStatusEntry,
} from '../index.js';
import { NOW_MS, RESOURCE, now, parties, serve, statusList, twoHopChain } from './signed-chain-helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const p = parties();
const chain = twoHopChain(p);
const keys = createDidKeyResolver();
const ADDRESS = '10.0.0.9';

/** The did:key resolver, but with `fail` answering for `did`. */
const failingFor = (did: string, fail: DIDResolver): DIDResolver => ({
  resolve: (asked) => (asked === did ? fail.resolve(asked) : keys.resolve(asked)),
  lastFailure: (asked) => (asked === did ? fail.lastFailure?.(asked) : keys.lastFailure?.(asked)),
});

/** Each way a signer's DID document may not be read, the code it is refused with, and what its reason ends with. */
const OUTAGES: [string, DIDResolver, RefusalCode, string][] = [
  [
    'reports its host unavailable',
    { resolve: async () => null, lastFailure: () => ({ cause: 'unavailable', detail: `HTTP 503 from ${ADDRESS}` }) },
    'did_unavailable',
    '',
  ],
  ['finds nothing and says no more', { resolve: async () => null }, 'did_unavailable', ''],
  [
    'throws',
    {
      resolve: async () => {
        throw new Error(`getaddrinfo EAI_AGAIN ${ADDRESS}`);
      },
    },
    'did_unavailable',
    '',
  ],
  [
    'reports its host refused',
    { resolve: async () => null, lastFailure: () => ({ cause: 'host_refused', detail: 'Request to "issuer.localhost" refused' }) },
    'host_refused',
    ' (Request to "issuer.localhost" refused)',
  ],
  [
    'reports a document that is not the DID\'s',
    { resolve: async () => null, lastFailure: () => ({ cause: 'invalid_document', detail: 'names another DID as its id' }) },
    'did_invalid',
    ' (names another DID as its id)',
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

  it.each(OUTAGES)('is refused with the code of why, when its resolver %s', async (_name, resolver, code, suffix) => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const answer = await checkWith(resolver);
    expect(answer).toEqual({ revoked: true, fresh: false, reason: `Could not resolve issuer DID: "${p.acme.did}"${suffix}`, ...coded(code) });
    expect(answer.reason).not.toContain(ADDRESS);
    if (_name === 'throws') expect(warn.mock.calls.flat().join(' ')).toContain(ADDRESS);
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

  it.each(OUTAGES)('is refused with the code of why, when its resolver %s', async (_name, resolver, code, suffix) => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    expect(await refusalOf(resolver)).toEqual({
      code: 'delegation_invalid',
      refusalCode: code,
      transient: isTransientRefusal(code),
      reasons: [`hop 1: Could not resolve issuer DID: "${p.agent.did}"${suffix}`],
    });
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
