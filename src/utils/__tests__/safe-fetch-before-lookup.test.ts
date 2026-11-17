/**
 * SafeFetch refuses a host whose address no resolver could make public by the URL alone, before
 * any DNS lookup or request: a non-public IP literal, IPv4 or IPv6, and `localhost` or a name under
 * it, which RFC 6761 §6.3 has every resolver answer with the loopback, with or without the trailing
 * dots a resolver ignores. Such a refusal says so (`refusedBeforeRequest`), since whoever named the
 * URL learns nothing the network answered, so a verifier may tell them why. Any other name is
 * looked up, and a refusal of what it resolves to is made after the lookup and does not say so.
 * `development: true` and `allowOrigins` admit what they admitted before.
 */
import { describe, expect, it, vi } from 'vitest';
import { createSafeFetch, type DnsLookup, type SafeFetchTransport } from '../safe-fetch.js';
import { readFailureKind, refusedBeforeRequest } from '../read-failure.js';

/** A lookup that answers every name with a public address, and records the names it was asked. */
const publicLookup = () => vi.fn<DnsLookup>(async () => [{ address: '93.184.216.34', family: 4 }]);

/** A transport that answers every request with an empty JSON object. */
const answering = () =>
  vi.fn<SafeFetchTransport>(async () => ({ status: 200, headers: { get: () => null }, text: async () => '{}' }));

/** What `fetch` threw for `url`, with its kind and whether it was refused before any request. */
async function refusalOf(fetch: (url: string) => Promise<unknown>, url: string) {
  const error = await fetch(url).then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
  return { message: (error as Error | undefined)?.message, kind: readFailureKind(error), beforeRequest: refusedBeforeRequest(error) };
}

const REMEDY =
  "a private or local host: in local development, set development: true; to read a host you own in production, list each origin you own in SafeFetch's allowOrigins";

describe('SafeFetch, before any DNS lookup', () => {
  it.each([
    ['https://10.1.2.3/status/1', '10.1.2.3'],
    ['https://127.0.0.1./status/1', '127.0.0.1'],
    ['https://169.254.169.254/latest/meta-data', '169.254.169.254'],
    ['https://[::1]/status/1', '[::1]'],
    ['https://[::ffff:10.0.0.1]/status/1', '[::ffff:a00:1]'],
    ['https://[fd00::1]/status/1', '[fd00::1]'],
    ['https://localhost/status/1', 'localhost'],
    ['https://LOCALHOST./status/1', 'localhost.'],
    ['https://status.localhost/status/1', 'status.localhost'],
    ['https://status.localhost../status/1', 'status.localhost..'],
  ])('refuses %s by the URL alone, and says it refused it before any request', async (url, host) => {
    const lookup = publicLookup();
    const transport = answering();
    expect(await refusalOf(createSafeFetch({ lookup, transport }), url)).toEqual({
      message: `safe-fetch: refusing host "${host}", ${REMEDY}`,
      kind: 'host_refused',
      beforeRequest: true,
    });
    expect(lookup).not.toHaveBeenCalled();
    expect(transport).not.toHaveBeenCalled();
  });

  it.each([
    ['a public IPv4 literal', 'https://93.184.216.34/status/1'],
    ['a name that only ends in localhost', 'https://notlocalhost/status/1'],
    ['a name under a local domain other than localhost', 'https://status.internal/status/1'],
  ])('looks up %s, and reads it when it resolves to a public address', async (_name, url) => {
    const lookup = publicLookup();
    const transport = answering();
    const response = await createSafeFetch({ lookup, transport })(url);
    expect(response.ok).toBe(true);
    expect(lookup).toHaveBeenCalledOnce();
  });

  it('refuses a name that resolves to a private address only after the lookup, and does not say it refused it before any request', async () => {
    const lookup = vi.fn<DnsLookup>(async () => [{ address: '10.1.2.3', family: 4 }]);
    const outcome = await refusalOf(createSafeFetch({ lookup, transport: answering() }), 'https://jenkins.corp.example/status/1');
    expect(outcome).toMatchObject({ kind: 'host_refused', beforeRequest: false });
    expect(outcome.message).not.toContain('10.1.2.3');
    expect(lookup).toHaveBeenCalledOnce();
  });

  it('admits a private literal and localhost under development: true, as before', async () => {
    const lookup = vi.fn<DnsLookup>(async () => [{ address: '127.0.0.1', family: 4 }]);
    const fetch = createSafeFetch({ lookup, transport: answering(), development: true });
    expect((await fetch('https://10.1.2.3/status/1')).ok).toBe(true);
    expect((await fetch('https://localhost/status/1')).ok).toBe(true);
  });
});
