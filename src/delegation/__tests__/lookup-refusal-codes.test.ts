/**
 * Whoever presents a credential chooses the DIDs and status-list URLs the verifier reads, so what
 * the verifier's DNS answered must not reach them. A name that resolves to a private address is
 * refused, and so is a name that does not resolve, and the two must be refused alike: the same code,
 * and so the same `transient`, as well as the same reason. Otherwise the code tells the presenter
 * which internal names exist, under split-horizon DNS a map of the verifier's network. The log, the
 * operator's, says `host_refused` and names the host and the address. A refusal the URL decides by
 * itself, such as an IP literal, keeps `host_refused`, since the presenter wrote that much.
 *
 * Each path codes its refusal as an adopter sees it: a did:web issuer through
 * `DelegationCredentialVerifier`, a status list through `createRevocationChecker` over `SafeFetch`,
 * and a status list through `RuntimeFetchProvider`'s read, coded as the verifier codes a status-list
 * resolver's failure. No connection is made: each name is refused, or does not resolve.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidWebResolver, DelegationCredentialVerifier, isTransientRefusal, logger, RuntimeFetchProvider } from '../../index.js';
import type { DnsLookup, SafeFetchTransport } from '../../index.js';
import { createRevocationChecker, createSafeFetch } from '../../card/index.js';
import { refusalCodeOf } from '../../utils/refusal.js';
import { fetchStatusListJson } from '../status-list-fetch.js';
import { delegationRecord, keyOf, signedCredential } from '../../__tests__/utils/delegation-credentials.js';

const INTERNAL = 'vault.corp.example';
const ABSENT = 'nothing.corp.example';

const lookup: DnsLookup = async (name) => {
  if (name === INTERNAL) return [{ address: '10.1.2.3', family: 4 }];
  throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${name}`), { code: 'ENOTFOUND' });
};
const transport: SafeFetchTransport = async () => {
  throw new Error('no connection expected');
};

let warned: string[];
beforeEach(() => {
  const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  warned = [];
  warn.mockImplementation((line: unknown) => void warned.push(String(line)));
});
afterEach(() => vi.restoreAllMocks());

/** How the verifier refuses a credential whose issuer is `did`, read through the provider. */
async function issuerRefusal(did: string) {
  const verifier = new DelegationCredentialVerifier({
    didResolver: createDidWebResolver(new RuntimeFetchProvider({ lookup, transport })),
    signatureVerifier: async () => ({ valid: true }),
  });
  const key = await keyOf(did, 'key-1');
  const vc = await signedCredential({ ...key, kid: `${did}#key-1` }, { record: delegationRecord(did) });
  const { reason, code } = await verifier.verifyDelegationCredential(vc, { skipCache: true });
  return { reason: reason?.replace(did, '<did>'), code, transient: isTransientRefusal(code) };
}

/** How the checker refuses an entry whose list is at `url`. */
async function checkerRefusal(url: string) {
  const checker = createRevocationChecker({ fetch: createSafeFetch({ lookup, transport }) });
  const entry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '1', statusListCredential: url };
  const { code, transient, reason } = await checker(entry as never);
  return { code, transient, reason: reason?.replace(url, '<url>') };
}

/** The code the verifier gives a status-list resolver that fails as the provider's read of `url` fails. */
async function providerReadCode(url: string) {
  const failure = await fetchStatusListJson(new RuntimeFetchProvider({ lookup, transport }), url).then(() => undefined, (error: unknown) => error);
  const code = refusalCodeOf(failure, 'status_unavailable');
  return { code, transient: isTransientRefusal(code) };
}

describe('a name that resolves to a private address, beside one that does not resolve', () => {
  it('refuses a did:web issuer alike: did_unavailable, transient, the same reason', async () => {
    const internal = await issuerRefusal(`did:web:${INTERNAL}`);
    expect(internal).toEqual(await issuerRefusal(`did:web:${ABSENT}`));
    expect(internal).toMatchObject({ code: 'did_unavailable', transient: true });
  });

  it('refuses a status list alike through the checker: status_unavailable, transient, the same reason', async () => {
    const internal = await checkerRefusal(`https://${INTERNAL}/list`);
    expect(internal).toEqual(await checkerRefusal(`https://${ABSENT}/list`));
    expect(internal).toMatchObject({ code: 'status_unavailable', transient: true });
  });

  it("refuses a status list alike through the provider's read: status_unavailable, transient", async () => {
    const internal = await providerReadCode(`https://${INTERNAL}/list`);
    expect(internal).toEqual(await providerReadCode(`https://${ABSENT}/list`));
    expect(internal).toEqual({ code: 'status_unavailable', transient: true });
  });

  it('tells the operator, and only the operator, host_refused, with the name and the address', async () => {
    await issuerRefusal(`did:web:${INTERNAL}`);
    await checkerRefusal(`https://${INTERNAL}/list`);
    const said = warned.filter((line) => line.includes('10.1.2.3'));
    expect(said).toEqual([
      `[kya-os] Request to "${INTERNAL}" refused (host_refused): it resolves to the non-public address 10.1.2.3, ` +
        'and whoever named it is told only that it could not be read',
      `[kya-os] safe-fetch: host "${INTERNAL}" refused (host_refused): it resolves to the non-public address 10.1.2.3, ` +
        'and whoever named it is told only that it could not be read',
    ]);
  });
});

describe('a refusal the URL decides by itself', () => {
  it('keeps host_refused, which is no verdict of the network', async () => {
    expect(await issuerRefusal('did:web:10.0.0.7')).toMatchObject({ code: 'host_refused', transient: false });
    expect(await checkerRefusal('https://10.0.0.7/list')).toMatchObject({ code: 'host_refused', transient: false });
    expect(await providerReadCode('https://10.0.0.7/list')).toEqual({ code: 'host_refused', transient: false });
  });
});
