/**
 * A hop's issuer chooses the status-list URL the hop names, so a list read is as much a probe of
 * the verifier's network as a DID is. When the Card revocation checker could not read a list, its
 * reason, which `verifyRequestDelegation` and `requireDelegation` hand back to whoever presented the
 * chain, names the list and says only that it could not be read: no HTTP status, no JSON parse error
 * quoting the body, no byte cap, no redirect, no refusal made after a DNS lookup and no transport
 * text, all of which go to the operator's log. It says why only where that was decided from the URL
 * alone, before any request (SafeFetch's https rule, or its refusal of a private IP literal or a
 * localhost name), or a deadline passed. The code and whether it is transient are as before, and a
 * verdict on a list that was read keeps its reason. Every test uses `@kya-os/mcp/card` as an
 * adopter calls it.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../index.js';
import {
  createDelegationProofVerifier,
  createRevocationChecker,
  createSafeFetch,
  isTransientRefusal,
  toDelegationChainMeta,
  verifyRequestDelegation,
  type RefusalCode,
  type SafeFetch,
  type SafeFetchTransport,
} from '../index.js';
import { createDidKeyResolver } from '../../index.js';
import { NOW_MS, RESOURCE, STATUS_URL, now, parties, twoHopChain } from './signed-chain-helpers.js';

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
    'host_refused',
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
    expect(outcome.answer).toEqual({ revoked: true, fresh: false, reason: `the status list at "${LIST}" could not be read`, ...coded(code) });
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
    expect(reasons[0]).toContain(`the status list at "${STATUS_URL}" could not be read`);
    expect(reasons[0]).not.toContain('10.1.2.3');
  });
});
