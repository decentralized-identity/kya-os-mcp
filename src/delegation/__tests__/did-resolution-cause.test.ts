/**
 * A credential whose issuer's DID document cannot be read is refused with `Could not resolve issuer
 * DID: "<did>"`, and the developer needs to know why: a host the private-network rule refused, a
 * host too slow to answer, one that could not be reached, or a document that is not the DID's. The
 * library's resolvers report the cause of their last failure for a DID through `lastFailure`, as an
 * object a caller can branch on, and the verifier codes the refusal by it. It appends what the
 * failure says, in parentheses, only where that was decided from the DID alone, before any request,
 * or the deadline passed; what the network answered is left to the log and `lastFailure`, and the
 * refusal says the log has it. A resolver of the host's own, without `lastFailure`, is refused so
 * too, the log saying it gave no cause. Every test uses the package's public exports, as an
 * adopter would.
 */

import { beforeAll, describe, expect, it, vi } from 'vitest';
import {
  buildDidWebDocument,
  createDidWebResolver,
  DelegationCredentialVerifier,
  logger,
  type AgentIdentity,
  type DelegationCredential,
  type DIDResolver,
  type DidResolutionFailure,
  type DidResolutionFailureCause,
} from '../../index.js';
import { createDidCheqdResolver } from '../../integrations/cheqd/index.js';
import { AnsweringFetchProvider } from '../../__tests__/utils/adopter-providers.js';
import { credentialJwt, delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

/** A did:web DID on `host`, with the URL of its document. */
const webDid = (host: string) => ({ did: `did:web:${encodeURIComponent(host)}`, url: `https://${host}/.well-known/did.json` });

const LOCAL = webDid('issuer.localhost:4101');
const SLOW = webDid('slow.example');
const DOWN = webDid('down.example');
const GONE = webDid('gone.example');
const ELSEWHERE = webDid('elsewhere.example');
const HOPPING = webDid('hopping.example');
const FOUND = webDid('found.example');

const HOST_REFUSED: DidResolutionFailure = {
  cause: 'host_refused',
  detail:
    'Request to "issuer.localhost:4101" refused: a private or local host. In local development, set development: true; ' +
    'to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.',
};

const keys = new Map<string, AgentIdentity>();
beforeAll(async () => {
  for (const { did } of [LOCAL, SLOW, DOWN, GONE, ELSEWHERE, HOPPING, FOUND]) keys.set(did, await keyOf(did, 'key-1'));
});

/**
 * A provider as a developer's network looks to the resolver: the slow host never answers, the down
 * host cannot be reached, the gone host answers 404, the elsewhere host serves another DID's
 * document, the hopping host redirects to a `file:` URL, and the found host serves its own document.
 */
function network(): AnsweringFetchProvider {
  return new AnsweringFetchProvider((url) => {
    switch (url) {
      case SLOW.url: return new Promise(() => undefined);
      case DOWN.url: return Promise.reject(new TypeError('fetch failed'));
      case ELSEWHERE.url: return Response.json(buildDidWebDocument(keys.get(FOUND.did)!));
      case HOPPING.url: return new Response(null, { status: 302, headers: { location: 'file:///etc/passwd' } });
      case FOUND.url: return Response.json(buildDidWebDocument(keys.get(FOUND.did)!));
      default: return new Response('not found', { status: 404 });
    }
  });
}

/** A credential `did` issues, signed with a Data Integrity proof. */
const credentialOf = (did: string): Promise<DelegationCredential> =>
  signedCredential(keys.get(did)!, { record: delegationRecord(did) });

/** A verifier over `didResolver`; the issuer's DID is resolved before any signature is checked. */
const verifierOver = (didResolver: DIDResolver) =>
  new DelegationCredentialVerifier({ didResolver, signatureVerifier: async () => ({ valid: true }) });

/** The reasons a credential `did` issues is refused for, as a Data Integrity credential and as a VC-JWT. */
async function refusals(didResolver: DIDResolver, did: string): Promise<string[]> {
  const verifier = verifierOver(didResolver);
  const credential = await credentialOf(did);
  const embedded = await verifier.verifyDelegationCredential(credential, { skipCache: true });
  const jwt = await verifier.verifyDelegationJwt(await credentialJwt(credential, keys.get(did)!), { skipCache: true });
  return [embedded.reason ?? 'accepted', jwt.reason ?? 'accepted'];
}

describe("the refusal of a credential whose issuer's did:web document cannot be read", () => {
  it('says the host was refused, and how to admit it, and the resolver reports host_refused', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network());
    const reason = `Could not resolve issuer DID: "${LOCAL.did}" (${HOST_REFUSED.detail})`;
    expect(await refusals(resolver, LOCAL.did)).toEqual([reason, reason]);
    const failure = resolver.lastFailure?.(LOCAL.did);
    expect(failure).toEqual(HOST_REFUSED);
    const cause: DidResolutionFailureCause | undefined = failure?.cause;
    expect(cause).toBe('host_refused');
  });

  it('leaves a redirect the scheme rule refuses, which the host answered, to the log and lastFailure, as host_refused', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network());
    const [reason] = await refusals(resolver, HOPPING.did);
    expect(reason).toBe(`Could not resolve issuer DID: "${HOPPING.did}"${WITHHELD_SUFFIX}`);
    expect(resolver.lastFailure?.(HOPPING.did)).toEqual({ cause: 'host_refused', detail: 'Redirect to a "file:" URL refused' });
    expect(warn).toHaveBeenCalledWith(`[DidWebResolver] Error resolving ${HOPPING.did}: Redirect to a "file:" URL refused`);
  });

  it("says the document did not arrive within the resolver's deadline, as deadline_exceeded", async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network(), { dependencyTimeoutMs: 50 });
    const reason = `Could not resolve issuer DID: "${SLOW.did}" (DID resolution deadline exceeded: no document arrived within 50 ms)`;
    expect(await refusals(resolver, SLOW.did)).toEqual([reason, reason]);
    expect(resolver.lastFailure?.(SLOW.did)?.cause).toBe('deadline_exceeded');
  });

  it('says only that the DID could not be resolved when the provider could not reach the host, leaving its error to the log, as unavailable', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network());
    const reason = `Could not resolve issuer DID: "${DOWN.did}"${WITHHELD_SUFFIX}`;
    expect(await refusals(resolver, DOWN.did)).toEqual([reason, reason]);
    expect(resolver.lastFailure?.(DOWN.did)?.cause).toBe('unavailable');
    expect(warn).toHaveBeenCalledWith(`[DidWebResolver] Error resolving ${DOWN.did}: fetch failed`);
  });

  it('leaves what the host answered when it is not a document to the log and lastFailure, as unavailable', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network());
    const [reason] = await refusals(resolver, GONE.did);
    expect(reason).toBe(`Could not resolve issuer DID: "${GONE.did}"${WITHHELD_SUFFIX}`);
    const detail = `DID resolution failed: HTTP 404 for "${GONE.url}"`;
    expect(resolver.lastFailure?.(GONE.did)).toEqual({ cause: 'unavailable', detail });
    expect(warn).toHaveBeenCalledWith(`[DidWebResolver] Error resolving ${GONE.did}: ${detail}`);
  });

  it("leaves a document that is another DID's to the log and lastFailure, as invalid_document", async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network());
    const [reason] = await refusals(resolver, ELSEWHERE.did);
    expect(reason).toBe(`Could not resolve issuer DID: "${ELSEWHERE.did}"${WITHHELD_SUFFIX}`);
    expect(resolver.lastFailure?.(ELSEWHERE.did)).toEqual({
      cause: 'invalid_document',
      detail: `The document at "${ELSEWHERE.url}" names another DID as its id`,
    });
    expect(warn).toHaveBeenCalledWith(`[DidWebResolver] DID Document id mismatch: expected ${ELSEWHERE.did}, got ${FOUND.did}`);
  });

  it('keeps the failures of the last 256 DIDs alone, so a counterparty that names many makes it hold little', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const resolver = createDidWebResolver(network());
    const dids = Array.from({ length: 257 }, (_, n) => webDid(`host${n}.localhost`).did);
    for (const did of dids) expect(await resolver.resolve(did)).toBeNull();
    expect(resolver.lastFailure?.(dids[0]!)).toBeUndefined();
    expect(dids.slice(1).every((did) => resolver.lastFailure?.(did)?.cause === 'host_refused')).toBe(true);
  });

  it('reports no failure for a DID it has since resolved, nor for one it was never asked', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    let answers = 0;
    const recovering = new AnsweringFetchProvider(() =>
      ++answers === 1 ? new Response('busy', { status: 503 }) : Response.json(buildDidWebDocument(keys.get(FOUND.did)!)),
    );
    const resolver = createDidWebResolver(recovering);
    expect(await resolver.resolve(FOUND.did)).toBeNull();
    expect(resolver.lastFailure?.(FOUND.did)?.cause).toBe('unavailable');
    expect(await refusals(resolver, FOUND.did)).toEqual(['accepted', 'accepted']);
    expect(resolver.lastFailure?.(FOUND.did)).toBeUndefined();
    expect(resolver.lastFailure?.(GONE.did)).toBeUndefined();
  });
});

describe("a resolver of the host's own", () => {
  it('without lastFailure, is refused saying the log has why, and the log that it gave no cause', async () => {
    const own: DIDResolver = { resolve: async () => null };
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const reason = `Could not resolve issuer DID: "${GONE.did}"${WITHHELD_SUFFIX}`;
    expect(await refusals(own, GONE.did)).toEqual([reason, reason]);
    expect(warn.mock.calls.flat().join('\n')).toContain(`found no document for "${GONE.did}" and gave no cause`);
  });

  it('whose lastFailure throws or answers something else, is refused as one without it is', async () => {
    const answers: unknown[] = [{ cause: 'unknown_cause', detail: 'x' }, { cause: 'unavailable' }, 'unavailable', null];
    const reason = `Could not resolve issuer DID: "${GONE.did}"${WITHHELD_SUFFIX}`;
    const throwing: DIDResolver = { resolve: async () => null, lastFailure: () => { throw new Error('no record'); } };
    expect(await refusals(throwing, GONE.did)).toEqual([reason, reason]);
    for (const answer of answers) {
      const odd = { resolve: async () => null, lastFailure: () => answer } as unknown as DIDResolver;
      expect(await refusals(odd, GONE.did), JSON.stringify(answer)).toEqual([reason, reason]);
    }
  });

  it('that reports a deadline it let pass, the one failure of its own a refusal shows, has it appended, sanitized and cut as any reason is', async () => {
    const own: DIDResolver = {
      resolve: async () => null,
      lastFailure: () => ({ cause: 'deadline_exceeded', detail: `the registry did not answer in time\n${'x'.repeat(400)}` }),
    };
    const shown = `the registry did not answer in time\uFFFD${'x'.repeat(220)}\u2026`;
    expect(await refusals(own, GONE.did)).toEqual(Array(2).fill(`Could not resolve issuer DID: "${GONE.did}" (${shown})`));
  });
});

describe('the did:cheqd resolver', () => {
  const CHEQD = 'did:cheqd:testnet:z1';

  it('reports why its configured endpoint did not answer with a document', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const endpoint = new AnsweringFetchProvider(() => new Response('unavailable', { status: 503 }));
    const resolver = createDidCheqdResolver(endpoint, { resolverUrl: 'https://r.example/1.0/identifiers' });
    expect(await resolver.resolve(CHEQD)).toBeNull();
    expect(resolver.lastFailure?.(CHEQD)).toEqual({
      cause: 'unavailable',
      detail: `DID resolution failed: HTTP 503 for "https://r.example/1.0/identifiers/${CHEQD}"`,
    });
  });
});
