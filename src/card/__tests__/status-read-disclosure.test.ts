/**
 * A hop's issuer chooses the status-list URL the hop names, so a list read is as much a probe of
 * the verifier's network as a DID is. When the Card revocation checker could not read a list, its
 * reason, which `verifyRequestDelegation` and `requireDelegation` hand back to whoever presented the
 * chain, names the list and says only that it could not be read: no HTTP status, no JSON parse error
 * quoting the body, no byte cap, no redirect, no refusal made after a DNS lookup and no transport
 * text, all of which go to the operator's log. It says why only where that was decided from the URL
 * alone, before any request (SafeFetch's https rule, or its refusal of a private IP literal or a
 * localhost name), or a deadline passed. The code and whether it is transient are as before. A list
 * that was read is refused the same way where a rule refused it before its proof was checked (its
 * keeper, its purpose, its `id`, or the dates of a list no proof is checked for), since the rule
 * quotes what the host answered, which may be any JSON document the verifier can reach. Once the
 * list's proof has verified, what it says is its issuer's, and a verdict on it keeps its reason.
 * Every test uses `@kya-os/mcp/card` as an adopter calls it.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createSafeFetch,
  createStatusListProofVerifier,
  isTransientRefusal,
  requireDelegation,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RefusalCode,
  type SafeFetch,
  type SafeFetchTransport,
} from '../index.js';
import { createDidKeyResolver } from '../../index.js';
import { NOW_MS, RESOURCE, STATUS_URL, hop, now, parties, serveAt, statusList, twoHopChain } from './signed-chain-helpers.js';
import { WITHHELD_SUFFIX } from '../../utils/thrown-words.js';

const LIST = 'https://jenkins.corp.example/status/1';

afterEach(() => {
  vi.restoreAllMocks();
});

/** A SafeFetch whose names resolve to `address`, over `transport`. */
const safeFetchAt = (address: string, transport: SafeFetchTransport): SafeFetch =>
  createSafeFetch({ lookup: async () => [{ address, family: 4 }], transport });

/** The checker's answer for an entry of the list at `url`, read through `fetch`, with what was logged. */
async function answerFor(fetch: SafeFetch, url = LIST) {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  const answer = await createRevocationChecker({ fetch, now })({
    type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: url,
  });
  return { answer, logged: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
}

/** The code and transient flag of `code`. */
const coded = (code: RefusalCode) => ({ code, transient: isTransientRefusal(code) });

/** Each answer of an internal host, or of the network on the way to it, the code it is refused with, and what the log says of it. */
const UNREAD: [string, SafeFetch, RefusalCode, string][] = [
  ['an HTTP status', async () => ({ ok: false, status: 403, json: async () => ({}) }), 'status_unavailable', '403'],
  [
    'a body whose JSON parse error quotes it',
    async () => ({ ok: true, status: 200, json: async () => JSON.parse('<html>sign in</html>') as unknown }),
    'status_unavailable',
    '<html>sign in</html>',
  ],
  ['a body that is not an object', async () => ({ ok: true, status: 200, json: async () => [] }), 'status_unavailable', 'not an object'],
  [
    "a transport's error",
    async () => Promise.reject(new TypeError('getaddrinfo ENOTFOUND jenkins.corp.example')),
    'status_unavailable',
    'getaddrinfo ENOTFOUND jenkins.corp.example',
  ],
  [
    'through SafeFetch, a name that resolves to a private address',
    safeFetchAt('10.1.2.3', async () => {
      throw new Error('never reached');
    }),
    'status_unavailable',
    'resolves to the non-public address 10.1.2.3',
  ],
  [
    'through SafeFetch, a redirect to another origin',
    safeFetchAt('93.184.216.34', async () => ({
      status: 302, headers: { get: (name: string) => (name === 'location' ? 'https://vault.corp.example/x' : null) }, text: async () => '',
    })),
    'host_refused',
    'https://vault.corp.example',
  ],
  [
    'through SafeFetch, a declared length over the cap',
    safeFetchAt('93.184.216.34', async () => ({
      status: 200, headers: { get: (name: string) => (name === 'content-length' ? '9999999' : null) }, text: async () => '{}',
    })),
    'status_unavailable',
    'declared content-length 9999999 exceeds cap',
  ],
];

describe('the Card revocation checker, when it could not read a status list', () => {
  it.each(UNREAD)('names the list and says only that it could not be read, logging the rest, for %s', async (_name, fetch, code, logged) => {
    const outcome = await answerFor(fetch);
    expect(outcome.answer).toEqual({ revoked: true, fresh: false, reason: `the status list at "${LIST}" could not be read or checked${WITHHELD_SUFFIX}`, ...coded(code) });
    expect(outcome.logged).toContain(logged);
  });

  it.each([
    ['http://status.example/lists/1', 'safe-fetch: only https is allowed (got "http:")'],
    [
      'https://10.1.2.3/lists/1',
      'safe-fetch: refusing host "10.1.2.3", a private or local host: in local development, set development: true; ' +
        "to read a host you own in production, list each origin you own in SafeFetch's allowOrigins",
    ],
    [
      'https://status.localhost/lists/1',
      'safe-fetch: refusing host "status.localhost", a private or local host: in local development, set development: true; ' +
        "to read a host you own in production, list each origin you own in SafeFetch's allowOrigins",
    ],
  ])('says why where SafeFetch refused %s as written, before any request', async (url, reason) => {
    const { answer } = await answerFor(safeFetchAt('93.184.216.34', async () => { throw new Error('never reached'); }), url);
    expect(answer).toEqual({ revoked: true, fresh: false, reason, ...coded('host_refused') });
  });

  it.each<[unknown, string]>([
    [null, 'of type null'],
    [undefined, 'of type undefined'],
    ['x', '"x"'],
    [[], 'of type array'],
  ])('says the status entry %j is not an object, reading no list', async (entry, named) => {
    const fetch = vi.fn(async () => { throw new Error('no request expected'); });
    const answer = await createRevocationChecker({ fetch, now })(entry as never);
    expect(answer).toEqual({ revoked: true, fresh: false, reason: `the status entry (${named}) is not an object`, ...coded('delegation_malformed') });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('says why where its deadline passed', async () => {
    const { answer } = await answerFor(createSafeFetch({ lookup: async () => [{ address: '93.184.216.34', family: 4 }], transport: (_url, { signal }) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason))), timeoutMs: 20 }));
    expect(answer).toEqual({ revoked: true, fresh: false, reason: 'safe-fetch: request to jenkins.corp.example timed out after 20ms', ...coded('deadline_exceeded') });
  });
});

describe('a delegation hop whose status list could not be read', () => {
  it("is refused to whoever presented it naming only the list, in requireDelegation's reasons", async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const p = parties();
    const result = await verifyRequestDelegation(
      { meta: toDelegationChainMeta(twoHopChain(p)), proofDid: p.subAgent.did, action: 'orders.place' },
      {
        resource: RESOURCE,
        trustedRootIssuers: [p.acme.did],
        verifyHopProof: createDelegationProofVerifier({ didResolver: createDidKeyResolver() }),
        checkRevocation: createRevocationChecker({ fetch: async () => Promise.reject(new TypeError('connect ECONNREFUSED 10.1.2.3:443')), now }),
        now: () => NOW_MS,
      },
    );
    expect(result.ok).toBe(false);
    const { reasons } = result as { reasons: string[] };
    expect(reasons).toHaveLength(1);
    expect(reasons[0]).toContain(`the status list at "${STATUS_URL}" could not be read or checked`);
    expect(reasons[0]).not.toContain('10.1.2.3');
  });
});

/** A document only the verifier can read, whose `issuer` names an internal realm. */
const INTERNAL_DOCUMENT = {
  issuer: 'https://login.corp.internal/realms/tenant-7731-payments',
  jwks_uri: 'https://login.corp.internal/realms/tenant-7731-payments/certs',
};

describe('the Card revocation checker, when it refuses a list it read before checking its proof', () => {
  const p = parties();
  const didResolver = createDidKeyResolver();

  /** The checker's answer for the agent's entry at {@link LIST}, where `body` is served, with what was logged. */
  async function answerOfRead(body: Record<string, unknown>, { proofChecked = true } = {}) {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const check = createRevocationChecker({
      fetch: serveAt({ [LIST]: body }),
      now,
      ...(proofChecked ? { verifyStatusList: createStatusListProofVerifier({ didResolver }) } : {}),
    });
    const answer = await check({ statusListIndex: '7', statusListCredential: LIST }, { credentialIssuer: p.agent.did });
    return { answer, logged: warn.mock.calls.map((call) => call.map(String).join(' ')).join('\n') };
  }

  it.each<[string, () => Record<string, unknown>, RefusalCode, string, boolean]>([
    ['an OpenID configuration, quoting its issuer', () => INTERNAL_DOCUMENT, 'status_signer_untrusted', 'login.corp.internal/realms/tenant-7731', true],
    ['a document that names no issuer', () => ({ jwks_uri: INTERNAL_DOCUMENT.jwks_uri }), 'status_signer_untrusted', 'status list names no issuer', true],
    ["the issuer's own list stating another id", () => statusList(p.agent, [], { id: 'https://elsewhere.example/1' }), 'status_signer_untrusted', '"https://elsewhere.example/1" is not the URL', true],
    [
      "the issuer's own list of another purpose",
      () => statusList(p.agent, [], { id: LIST, credentialSubject: { statusPurpose: 'suspension' } }),
      'status_signer_untrusted',
      `the list's is "suspension"`,
      true,
    ],
    ['a list past its validUntil, where no proof is checked', () => statusList(p.agent, [], { id: LIST, validUntil: '2020-01-01T00:00:00Z' }), 'status_unavailable', 'expired at "2020-01-01T00:00:00Z"', false],
  ])('names the list and says only that it could not be read or checked, logging the rest, for %s', async (_name, body, code, said, proofChecked) => {
    const { answer, logged } = await answerOfRead(body(), { proofChecked });
    expect(answer).toEqual({ revoked: true, fresh: false, reason: `the status list at "${LIST}" could not be read or checked${WITHHELD_SUFFIX}`, ...coded(code) });
    expect(logged).toContain(said);
  });

  it("says why it refuses a list whose proof verified, since the list's words are then its issuer's", async () => {
    const { answer } = await answerOfRead(statusList(p.agent, [], { id: LIST, validUntil: '2020-01-01T00:00:00Z' }));
    expect(answer).toEqual({ revoked: true, fresh: false, reason: 'status list expired at "2020-01-01T00:00:00Z" (its validUntil)', ...coded('status_unavailable') });
  });
});

describe('a delegation hop whose status entry names a document that is no status list', () => {
  it('is refused to whoever presented it telling nothing the document said, which the log is told', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const p = parties();
    const [root] = twoHopChain(p);
    // The agent signs the leaf itself, so the status-list URL in it is the agent's to choose.
    const leaf = hop({
      issuer: p.agent,
      invoker: p.subAgent.did,
      id: 'urn:zcap:agent-leaf',
      parentCapability: 'urn:zcap:acme-root',
      allowedAction: ['orders.place'],
      caveats: [{ type: 'MaxAmount', limit: '100.00', currency: 'USD' }],
      statusIndex: 7,
      statusListCredential: LIST,
    });
    const didResolver = createDidKeyResolver();
    const verdict = await requireDelegation({
      resource: RESOURCE,
      trustedRootIssuers: [p.acme.did],
      verifyHopProof: createDelegationProofVerifier({ didResolver }),
      checkRevocation: createRevocationChecker({
        fetch: serveAt({ [STATUS_URL]: statusList(p.acme), [LIST]: INTERNAL_DOCUMENT }),
        now,
        verifyStatusList: createStatusListProofVerifier({ didResolver }),
      }),
      now: () => NOW_MS,
    })({ meta: toDelegationChainMeta([root, leaf]), proofDid: p.subAgent.did, action: 'orders.place' });
    if (verdict.ok) throw new Error('a hop whose status list is no status list was accepted');
    expect(verdict.error.code).toBe('delegation_revoked');
    expect(verdict.error.reasons?.[0]?.endsWith(`subtree invalidated: the status list at "${LIST}" could not be read or checked${WITHHELD_SUFFIX}`)).toBe(true);
    const told = JSON.stringify(verdict);
    expect(told).not.toContain('login.corp.internal');
    expect(told).not.toContain('tenant-7731');
    expect(warn.mock.calls.flat().join('\n')).toContain('login.corp.internal/realms/tenant-7731-payments');
  });
});
