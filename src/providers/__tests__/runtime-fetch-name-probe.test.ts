/**
 * Whether the runtime resolves names is asked once, of `localhost`, before a read resolves and pins
 * the host a presenter names. Only a runtime with no resolver answers no: one where `node:dns` does
 * not load, or whose `lookup` says it is not implemented, as a Worker's does, and that answer is kept.
 * Any other failure of that one lookup, such as a resolver busy for a moment, must not turn every
 * later read in the process into one held to the URL alone: the read resolves its own host, and
 * fails if that fails too. Every fall back to the URL alone is said once, the subclass whose `fetch`
 * is its own included. `node:dns` is replaced in each case, and the runtime's `fetch` is stubbed,
 * standing for the network, so a read that reaches it is one that was not held.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/** A name that looks public and resolves to the cloud metadata address, as nip.io answers it. */
const METADATA_DID = 'did:web:169.254.169.254.nip.io';
const METADATA_LIST = 'https://169.254.169.254.nip.io/list';

/** Every URL the runtime's own `fetch` was asked for. */
const fetched: string[] = [];
/** Every name `node:dns` was asked to look up. */
const asked: string[] = [];

/** `node:dns/promises` whose `lookup` throws `failure` the first `times` times, then answers as DNS does. */
function dnsFailing(failure: () => unknown, times: number) {
  let failures = 0;
  return {
    lookup: async (hostname: string) => {
      asked.push(hostname);
      if (failures++ < times) throw failure();
      if (hostname === 'localhost') return [{ address: '127.0.0.1', family: 4 }];
      return [{ address: hostname.startsWith('169.254.169.254') ? '169.254.169.254' : '93.184.216.34', family: 4 }];
    },
  };
}

/** The package as a fresh process loads it, over `dns`, and the warnings it gives. */
async function freshPackage(dns: () => unknown) {
  vi.resetModules();
  vi.doMock('node:dns/promises', dns);
  const loaded = await import('../../index.js');
  const warn = vi.spyOn(loaded.logger, 'warn').mockImplementation(() => undefined);
  const said = () => warn.mock.calls.map((call) => String(call[0])).filter((line) => line.includes('by its URL alone'));
  return { ...loaded, said };
}

beforeEach(() => {
  fetched.length = 0;
  asked.length = 0;
  vi.stubGlobal('fetch', async (url: string) => {
    fetched.push(url);
    return new Response('{}', { status: 404 });
  });
});

afterEach(() => {
  vi.doUnmock('node:dns/promises');
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const busy = () => Object.assign(new Error('getaddrinfo EAI_AGAIN localhost'), { code: 'EAI_AGAIN' });

describe('one failed lookup of localhost', () => {
  it('leaves every read resolving and refusing a name that resolves to a private address, now and later', async () => {
    const { RuntimeFetchProvider, said } = await freshPackage(() => dnsFailing(busy, 1));
    expect(await new RuntimeFetchProvider().resolveDID(METADATA_DID)).toBeNull();
    expect(await new RuntimeFetchProvider().resolveDID(METADATA_DID)).toBeNull();
    expect(await new RuntimeFetchProvider().fetchStatusList(METADATA_LIST)).toBeNull();
    expect(fetched).toEqual([]);
    expect(asked.filter((name) => name !== 'localhost')).toEqual(Array(3).fill('169.254.169.254.nip.io'));
    expect(said()).toEqual([]);
  });

  it('asks again on the next read, and keeps the answer once it is had', async () => {
    const { RuntimeFetchProvider } = await freshPackage(() => dnsFailing(busy, 1));
    await new RuntimeFetchProvider().resolveDID(METADATA_DID);
    await new RuntimeFetchProvider().resolveDID(METADATA_DID);
    await new RuntimeFetchProvider().resolveDID(METADATA_DID);
    expect(asked.filter((name) => name === 'localhost')).toHaveLength(2);
  });
});

describe('a runtime with no resolver', () => {
  it.each<[string, () => unknown]>([
    ["a Worker's lookup, which says it is not implemented", () => dnsFailing(() => new Error('Not implemented'), Infinity)],
    ['a lookup coded as not implemented', () => dnsFailing(() => Object.assign(new Error('lookup'), { code: 'ERR_METHOD_NOT_IMPLEMENTED' }), Infinity)],
    ['a node:dns that does not load', () => { throw new Error('No such built-in module: node:dns/promises'); }],
  ])('holds reads to the URL alone for %s, asks once, and says so once', async (_case, dns) => {
    const { RuntimeFetchProvider, said } = await freshPackage(dns);
    await new RuntimeFetchProvider().resolveDID(METADATA_DID);
    await new RuntimeFetchProvider().fetchStatusList(METADATA_LIST);
    expect(await new RuntimeFetchProvider().resolveDID('did:web:10.0.0.5')).toBeNull();
    expect(fetched).toEqual(['https://169.254.169.254.nip.io/.well-known/did.json', METADATA_LIST]);
    expect(asked.length).toBeLessThanOrEqual(1);
    expect(said()).toEqual([
      '[kya-os] this runtime resolves no host name, as its node:dns is missing or not implemented, so a host a presenter ' +
        'names is held to the private-network rule by its URL alone and is not resolved or pinned here: the egress must ' +
        'refuse private and local addresses itself.',
    ]);
  });
});

describe('a provider that makes its own connections', () => {
  it('says once, naming its class, that its reads are held to the URL alone', async () => {
    const { RuntimeFetchProvider, createDidWebResolver, said } = await freshPackage(() => dnsFailing(busy, 0));
    class Proxied extends RuntimeFetchProvider {
      override fetch(url: string, init?: RequestInit): Promise<Response> {
        return globalThis.fetch(url, init);
      }
    }
    await new Proxied().resolveDID(METADATA_DID);
    await new Proxied().resolveDID(METADATA_DID);
    const own = { fetch: (url: string, init?: RequestInit) => globalThis.fetch(url, init) };
    await createDidWebResolver(own).resolve(METADATA_DID);
    expect(said()).toEqual([
      '[kya-os] Proxied has a fetch of its own, which makes its own connections, so a host a presenter names is held to ' +
        'the private-network rule by its URL alone and is not resolved or pinned here: the egress must refuse private ' +
        'and local addresses itself.',
      '[kya-os] A FetchProvider has a fetch of its own, which makes its own connections, so a host a presenter names is ' +
        'held to the private-network rule by its URL alone and is not resolved or pinned here: the egress must refuse ' +
        'private and local addresses itself.',
    ]);
  });
});
