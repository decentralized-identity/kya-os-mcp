/**
 * An application on a network whose only way out is a proxy routes the runtime's `fetch` through it:
 * with undici's `setGlobalDispatcher(new ProxyAgent(...))` on Node 20 and 22, or with
 * `NODE_USE_ENV_PROXY=1` and `HTTPS_PROXY` on Node 24, which installs an `EnvHttpProxyAgent` itself.
 * The proxy resolves each host, and the verifier often cannot. So where Node's `fetch` goes through a
 * dispatcher other than undici's plain `Agent`, `RuntimeFetchProvider` reads a host a presenter names
 * through `fetch`, as 1.23.0 did, held to the private-network rule by its URL alone, and says once
 * that the proxy must refuse private addresses itself. The runtime's `fetch` is stubbed here, standing
 * for the proxy, and the global dispatcher is an object of the class each case names.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidWebResolver, logger, RuntimeFetchProvider } from '../../index.js';
import type { DnsLookup } from '../../card/index.js';
import { ADDRESS_PINNING } from '../../utils/fetch-port.js';

const GLOBAL_DISPATCHER = Symbol.for('undici.globalDispatcher.1');
const globals = globalThis as Record<symbol, unknown>;
const DID = 'did:web:did.proxied.example';
const URL_OF_DID = 'https://did.proxied.example/.well-known/did.json';

/** An object whose class is named `name`, as undici's dispatchers are. */
function dispatcherNamed(name: string): object {
  const named = { [name]: class {} }[name] as new () => object;
  return new named();
}

/** Every URL the runtime's own `fetch` was asked for. */
const runtimeFetched: string[] = [];
let before: { had: boolean; value: unknown };

beforeEach(() => {
  runtimeFetched.length = 0;
  before = { had: Object.prototype.hasOwnProperty.call(globals, GLOBAL_DISPATCHER), value: globals[GLOBAL_DISPATCHER] };
  vi.stubGlobal('fetch', async (url: string) => {
    runtimeFetched.push(url);
    return Response.json({ '@context': ['https://www.w3.org/ns/did/v1'], id: DID });
  });
});

afterEach(() => {
  if (before.had) globals[GLOBAL_DISPATCHER] = before.value;
  else delete globals[GLOBAL_DISPATCHER];
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('a runtime whose fetch the application routes through a proxy', () => {
  it.each(['ProxyAgent', 'EnvHttpProxyAgent', 'MockAgent'])(
    'reads a host a presenter names through fetch under the %s dispatcher, as 1.23.0 did, without resolving it',
    async (name) => {
      vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
      globals[GLOBAL_DISPATCHER] = dispatcherNamed(name);
      const resolver = createDidWebResolver(new RuntimeFetchProvider());
      expect((await resolver.resolve(DID))?.id).toBe(DID);
      expect(runtimeFetched).toEqual([URL_OF_DID]);
    },
  );

  it('still refuses, before any request, a host whose URL alone names a private or local address', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    globals[GLOBAL_DISPATCHER] = dispatcherNamed('ProxyAgent');
    const resolver = createDidWebResolver(new RuntimeFetchProvider());
    for (const did of ['did:web:169.254.169.254', 'did:web:localhost', 'did:web:metadata.google.internal']) {
      expect(await resolver.resolve(did)).toBeNull();
      expect(resolver.lastFailure?.(did)?.cause).toBe('host_refused');
    }
    expect(runtimeFetched).toEqual([]);
  });

  it('says once, through logger.warn, that the proxy must refuse private addresses itself', async () => {
    vi.resetModules();
    const { RuntimeFetchProvider: Fresh, logger: freshLogger } = await import('../../index.js');
    const warn = vi.spyOn(freshLogger, 'warn').mockImplementation(() => undefined);
    globals[GLOBAL_DISPATCHER] = dispatcherNamed('ProxyAgent');
    const provider = new Fresh();
    await provider.resolveDID(DID);
    await provider.resolveDID(DID);
    const told = warn.mock.calls.map((call) => call.map(String).join(' ')).filter((line) => line.includes('dispatcher'));
    expect(told).toEqual([
      '[kya-os] fetch goes through the global ProxyAgent dispatcher, not straight to each host, so a host a presenter names ' +
        'is held to the private-network rule by its URL alone and is not resolved or pinned here: the proxy, or ' +
        'whatever that dispatcher connects through, must refuse private and local addresses itself.',
    ]);
  });
});

describe('a runtime whose fetch connects to the host it is asked for', () => {
  it.each([['no dispatcher yet', undefined], ["undici's plain Agent", 'Agent']])(
    'resolves and pins a host a presenter names, with %s',
    async (_case, name) => {
      if (name === undefined) delete globals[GLOBAL_DISPATCHER];
      else globals[GLOBAL_DISPATCHER] = dispatcherNamed(name);
      expect(await new RuntimeFetchProvider()[ADDRESS_PINNING]()).toMatchObject({ lookup: expect.any(Function) });
    },
  );

  it('keeps a lookup the provider is given, proxy or not', async () => {
    globals[GLOBAL_DISPATCHER] = dispatcherNamed('ProxyAgent');
    const lookup: DnsLookup = async () => [{ address: '93.184.216.34', family: 4 }];
    expect(await new RuntimeFetchProvider({ lookup })[ADDRESS_PINNING]()).toMatchObject({ lookup });
  });
});
