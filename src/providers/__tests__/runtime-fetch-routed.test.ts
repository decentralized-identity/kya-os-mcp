/**
 * An application on a network whose only way out is a proxy routes the runtime's `fetch` through it:
 * with undici's `setGlobalDispatcher(new ProxyAgent(...))`, or with `NODE_USE_ENV_PROXY=1` and
 * `HTTPS_PROXY`, under which Node installs an `EnvHttpProxyAgent` itself. The proxy resolves each
 * host, and the verifier often cannot. So where Node's `fetch` sends a request through a proxy,
 * `RuntimeFetchProvider` reads a host a presenter names through `fetch`, as 1.23.0 did, held to the
 * private-network rule by its URL alone, and says once that the proxy must refuse private addresses
 * itself. Any other dispatcher, and an `EnvHttpProxyAgent` for a host it sends straight to the host,
 * keeps the read resolved, checked and pinned: a dispatcher the provider cannot read never turns the
 * check off, and neither does one composed with interceptors, which the provider never dispatches
 * through to decide. The runtime's `fetch` is stubbed here, standing for the proxy, and the global
 * dispatcher is an object of the class each case names, built as undici builds it where its shape
 * matters. `./runtime-fetch-env-proxy.test.ts` asks Node's own undici.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDidWebResolver, logger, RuntimeFetchProvider } from '../../index.js';
import type { DnsLookup } from '../../card/index.js';
import { ADDRESS_PINNING } from '../../utils/fetch-port.js';

const GLOBAL_DISPATCHER = Symbol.for('undici.globalDispatcher.1');
const globals = globalThis as Record<symbol, unknown>;
const DID = 'did:web:did.proxied.example';
const URL_OF_DID = 'https://did.proxied.example/.well-known/did.json';
const PROXIED = 'https://lists.proxied.example/list';
const NOT_PROXIED = 'https://lists.internal.example/list';

/** An object whose class is named `name`, as undici's dispatchers are; it never sends a request. */
function dispatcherNamed(name: string, base: new () => object = Object): object {
  const named = { [name]: class extends base {} }[name] as new () => object;
  return new named();
}

/** The origin of every request a stand-in agent was dispatched, which on undici's would be sent. */
const sent: string[] = [];

/** A stand-in for undici's `Agent`, whose every dispatch would send a request. */
class Agent {
  dispatch(options: { origin: string }): boolean {
    sent.push(options.origin);
    return true;
  }
}
/** A stand-in for undici's `ProxyAgent`. */
class ProxyAgent extends Agent {}

/**
 * A stand-in for undici's `EnvHttpProxyAgent`, built as undici 6 and 7 build it: the agents it picks
 * between under symbols with these descriptions, the proxy agents the direct one where no proxy is
 * set, and a `dispatch` that hands each request to the one `NO_PROXY`, private to it, picks.
 */
function envHttpProxyAgent(settings: { proxy: boolean; noProxy: string }): object {
  const direct = new Agent();
  const proxied = settings.proxy ? new ProxyAgent() : direct;
  class EnvHttpProxyAgent {
    readonly #noProxy = settings.noProxy;
    dispatch(options: { origin: string }): unknown {
      const host = new URL(options.origin).hostname;
      const agent = this.#noProxy !== '' && host.endsWith(this.#noProxy) ? direct : proxied;
      return agent.dispatch(options);
    }
  }
  return Object.assign(new EnvHttpProxyAgent(), {
    [Symbol('no proxy agent')]: direct,
    [Symbol('http proxy agent')]: proxied,
    [Symbol('https proxy agent')]: proxied,
  });
}

/**
 * `dispatcher` composed with an interceptor that dispatches later, as undici's `interceptors.dns()`
 * does once it has resolved the host: undici 7 composes into a proxy of the dispatcher whose
 * `dispatch` alone is the interceptor's, so it keeps the dispatcher's class and members.
 */
function composedLater(dispatcher: object): object {
  const later = (options: { origin: string }) => {
    setTimeout(() => (dispatcher as Agent).dispatch(options), 0);
    return true;
  };
  return new Proxy(dispatcher, { get: (target, key) => (key === 'dispatch' ? later : Reflect.get(target, key)) });
}

/** Every URL the runtime's own `fetch` was asked for. */
const runtimeFetched: string[] = [];
let before: { had: boolean; value: unknown };

beforeEach(() => {
  runtimeFetched.length = 0;
  sent.length = 0;
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

/** Whether the provider resolves, checks and pins a request for `url`, rather than reading it through `fetch`. */
async function pins(url: string): Promise<boolean> {
  return (await new RuntimeFetchProvider()[ADDRESS_PINNING](url)) !== undefined;
}

describe('a runtime whose fetch sends the request through a proxy', () => {
  it('reads a host a presenter names through fetch under a ProxyAgent, as 1.23.0 did, without resolving it', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    globals[GLOBAL_DISPATCHER] = new ProxyAgent();
    const resolver = createDidWebResolver(new RuntimeFetchProvider());
    expect((await resolver.resolve(DID))?.id).toBe(DID);
    expect(runtimeFetched).toEqual([URL_OF_DID]);
  });

  it('reads through fetch under an EnvHttpProxyAgent for a host it sends through its proxy, and pins a host NO_PROXY names', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    const dispatcher = envHttpProxyAgent({ proxy: true, noProxy: '.internal.example' });
    globals[GLOBAL_DISPATCHER] = dispatcher;
    expect(await pins(PROXIED)).toBe(false);
    expect(await pins(NOT_PROXIED)).toBe(true);
    // Each agent's own dispatch is back once the dispatcher is asked, and none sent a request.
    for (const key of Object.getOwnPropertySymbols(dispatcher)) {
      expect(Object.hasOwn((dispatcher as Record<symbol, object>)[key]!, 'dispatch')).toBe(false);
    }
    expect(sent).toEqual([]);
  });

  it('still refuses, before any request, a host whose URL alone names a private or local address', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    globals[GLOBAL_DISPATCHER] = new ProxyAgent();
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
    globals[GLOBAL_DISPATCHER] = new ProxyAgent();
    const provider = new Fresh();
    await provider.resolveDID(DID);
    await provider.resolveDID(DID);
    const told = warn.mock.calls.map((call) => call.map(String).join(' ')).filter((line) => line.includes('dispatcher'));
    expect(told).toEqual([
      '[kya-os] the global ProxyAgent dispatcher sends fetch requests through a proxy, not straight to each host, so a host ' +
        'a presenter names is held to the private-network rule by its URL alone and is not resolved or pinned here: the ' +
        'proxy must refuse private and local addresses itself.',
    ]);
  });
});

describe('a runtime whose fetch connects to the host it is asked for', () => {
  it.each<[string, () => object | undefined]>([
    ['no dispatcher yet', () => undefined],
    ["undici's plain Agent", () => new Agent()],
    ['an Agent subclass the application names', () => dispatcherNamed('TracingAgent', Agent)],
    ['a RetryAgent', () => dispatcherNamed('RetryAgent')],
    ['a MockAgent', () => dispatcherNamed('MockAgent')],
    ['a dispatcher composed with interceptors', () => dispatcherNamed('ComposedDispatcher')],
    ['a dispatcher of no name', () => Object.create(null) as object],
    ['an EnvHttpProxyAgent with no proxy set', () => envHttpProxyAgent({ proxy: false, noProxy: '' })],
    ['an EnvHttpProxyAgent whose agents cannot be found', () => dispatcherNamed('EnvHttpProxyAgent')],
    ['an EnvHttpProxyAgent composed with an interceptor, for a host it proxies', () => composedLater(envHttpProxyAgent({ proxy: true, noProxy: '' }))],
    ['an EnvHttpProxyAgent composed with an interceptor, for a host NO_PROXY names', () => composedLater(envHttpProxyAgent({ proxy: true, noProxy: '.proxied.example' }))],
    ['a ProxyAgent composed with an interceptor', () => composedLater(new ProxyAgent())],
  ])('resolves, checks and pins a host a presenter names, under %s, and sends nothing to decide', async (_case, dispatcher) => {
    const installed = dispatcher();
    if (installed === undefined) delete globals[GLOBAL_DISPATCHER];
    else globals[GLOBAL_DISPATCHER] = installed;
    expect(await new RuntimeFetchProvider()[ADDRESS_PINNING](PROXIED)).toMatchObject({ lookup: expect.any(Function) });
    // Long enough for anything an interceptor put off to have been dispatched.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sent).toEqual([]);
  });

  it('keeps a lookup the provider is given, proxy or not', async () => {
    globals[GLOBAL_DISPATCHER] = new ProxyAgent();
    const lookup: DnsLookup = async () => [{ address: '93.184.216.34', family: 4 }];
    expect(await new RuntimeFetchProvider({ lookup })[ADDRESS_PINNING](PROXIED)).toMatchObject({ lookup });
  });
});
