/**
 * Whoever presents a delegation chooses the status-list URL its credential names, so a list read is
 * as much a probe of the verifier's network as a DID is. The gate's refusal of a delegation whose
 * list could not be read names the list and says only that: no HTTP status, no answer that is not
 * JSON, no byte cap, no redirect, no shape of what came back, no transport text and no refusal made
 * after a DNS lookup, all of which go to the operator's log. Its reason says why only where that was
 * decided from the URL alone, before any request (the private-network rule on the URL as written).
 * The code and whether it is transient are as before. Only the network is faked: the shipped
 * CheqdStatusListResolver reads the list, and a resolver of the host's own throws its transport's
 * words.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { KyaOsToolHandler } from '../with-kya-os.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/statuslist-resolver.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import type { StatusListResolver } from '../../delegation/vc-verifier.js';
import { logger } from '../../logging/index.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { createRealIdentity } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { delegationRecord, signedCredential } from '../../__tests__/utils/delegation-credentials.js';
import type { FetchProvider } from '../../providers/base.js';
import type { CredentialStatus } from '../../types/protocol.js';
import { createMiddleware, crypto, handshake, served } from './helpers/received-proof.js';

const SCOPE = 'vault:read';
const CONSENT = { scopeId: SCOPE, consentUrl: 'https://example.com/consent' };
const ran: KyaOsToolHandler = async () => ({ content: [{ type: 'text', text: 'ran' }] });
const INTERNAL_LIST = 'https://jenkins.corp.example/status/1';
const LOCAL_LIST = 'https://status.localhost/lists/1';

afterEach(() => {
  vi.restoreAllMocks();
});

/** A status entry of the list at `url`. */
const entryAt = (url: string): CredentialStatus => ({
  id: `${url}#7`, type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url,
});

/** The shipped cheqd status-list resolver, its list issuer a did:key, over a provider whose every request `answer` answers. */
const cheqdOver = (answer: () => unknown): StatusListResolver =>
  new CheqdStatusListResolver({
    fetchProvider: { fetch: async () => answer() } as unknown as FetchProvider,
    didResolver: createDidKeyResolver(),
    cryptoProvider: crypto,
    expectedIssuerDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    decompressor: statusListGzipCodec,
    cacheTtlMs: 0,
  });

/** The gate's client answer to a delegation whose status is the entry of `url`, read by `statusListResolver`, with what was logged. */
async function gateAnswer(statusListResolver: StatusListResolver, url: string) {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const kyaos = await served(await createMiddleware({ delegation: { statusListResolver } }));
  const sessionId = await handshake(kyaos);
  const [grantor, agent] = await Promise.all([createRealIdentity(crypto), createRealIdentity(crypto)]);
  const delegation = await signedCredential(grantor, {
    record: delegationRecord(grantor.did, {
      id: 'del-1',
      subjectDid: agent.did,
      vcId: 'urn:uuid:del-1',
      constraints: { scopes: [SCOPE], notAfter: Math.floor(Date.now() / 1000) + 3600 },
    }),
    credentialStatus: entryAt(url),
  });
  const result = (await kyaos.wrapWithDelegation('vault', CONSENT, ran)({ path: '/secret', _kyaos_delegation: delegation }, sessionId)) as {
    content: Array<{ text: string }>;
  };
  return { answer: JSON.parse(result.content[0]!.text) as unknown, logged: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
}

describe("the gate's refusal of a delegation whose status list could not be read", () => {
  it.each<[string, () => StatusListResolver, string]>([
    ['an HTTP status', () => cheqdOver(() => new Response('forbidden', { status: 403 })), 'HTTP 403'],
    ['a body that is not JSON', () => cheqdOver(() => new Response('<html>sign in</html>', { status: 200 })), 'not JSON'],
    ['a body over the byte cap', () => cheqdOver(() => new Response('x'.repeat(2 * 1024 * 1024), { status: 200 })), 'byte limit exceeded'],
    [
      'a redirect to a private address',
      () => cheqdOver(() => new Response(null, { status: 302, headers: { location: 'https://10.1.2.3/' } })),
      'Redirect to a private or local host refused',
    ],
    ['a resource that is no status list', () => cheqdOver(() => Response.json({ type: ['VerifiableCredential'] })), 'not a StatusList2021Credential'],
    [
      "a transport's error",
      () => cheqdOver(() => Promise.reject(new TypeError('connect ECONNREFUSED 93.184.216.34:443'))),
      'ECONNREFUSED 93.184.216.34:443',
    ],
    [
      "a resolver of the host's own that throws its transport's words",
      () => ({ checkStatus: async () => Promise.reject(new Error('getaddrinfo ENOTFOUND jenkins.corp.example')) }),
      'getaddrinfo ENOTFOUND jenkins.corp.example',
    ],
  ])('names the list and says only that it could not be read, logging the rest, for %s', async (_name, resolver, detail) => {
    const { answer, logged } = await gateAnswer(resolver(), INTERNAL_LIST);
    expect(answer).toEqual({ error: 'delegation_invalid', reason: `Delegation del-1 invalid: Status check error: the status list at "${INTERNAL_LIST}" could not be read or checked` });
    expect(logged).toContain(detail);
  });

  it('says what was refused, and how to admit it, where the private-network rule refuses the URL as written', async () => {
    const { answer } = await gateAnswer(cheqdOver(() => Response.json({})), LOCAL_LIST);
    expect(answer).toEqual({
      error: 'delegation_invalid',
      reason:
        'Delegation del-1 invalid: Status check error: Request to "status.localhost" refused: a private or local host. In local development, set ' +
        'development: true; to read private hosts in production, give the fetch provider allowPrivateNetworkHosts: true.',
    });
  });
});
