/**
 * Whether the runtime's `fetch` sends a request through a proxy, rather than straight to the host
 * its URL names. Node's `fetch` makes every connection through the dispatcher at
 * `Symbol.for('undici.globalDispatcher.1')`. A read that resolved the host itself and pinned its own
 * connection would go around a proxy there, and on a network whose only way out is that proxy, fail.
 * So a request the dispatcher sends through a proxy goes through `fetch`, held to its URL alone, and
 * the proxy must refuse private addresses itself.
 *
 * Only a dispatcher known to send the request through a proxy counts: undici's `ProxyAgent`, which
 * sends every request through its proxy, and its `EnvHttpProxyAgent`, which an application installs
 * or Node installs itself under `NODE_USE_ENV_PROXY=1` or `--use-env-proxy`, for a URL it sends
 * through the proxy set for the URL's scheme. It sends a URL straight to its host where no proxy is
 * set for that scheme or `NO_PROXY` names the host, and such a URL is read pinned. Any other
 * dispatcher, undici's `Agent` or a subclass of it, a `RetryAgent`, a `MockAgent`, one composed with
 * interceptors, or one of the application's own, is taken to connect to the host itself, and the read
 * pins its own connection: a dispatcher this module cannot read never turns the check off. An
 * application whose own dispatcher sends requests through a proxy gives the provider
 * `transport: fetchTransport`, which makes each checked request through `fetch` by the host's name.
 */

import { warnHeldToUrlAlone } from './url-only-reads.js';

/** Where Node's `fetch`, and undici's, find the dispatcher every request goes through. */
const GLOBAL_DISPATCHER = Symbol.for('undici.globalDispatcher.1');

/**
 * The descriptions of the symbols under which undici's `EnvHttpProxyAgent` keeps the agents it
 * picks between for each request: its own `Agent` and the `ProxyAgent` of each scheme.
 */
const PICKED_AGENTS: ReadonlySet<string> = new Set(['no proxy agent', 'http proxy agent', 'https proxy agent']);

/** A handler for a dispatch that is never made: one that ends whatever reaches it. */
const NO_REQUEST = {
  onConnect: (abort: (error?: Error) => void) => abort(new Error('not sent')),
  onRequestStart: (controller: { abort(error: Error): void }) => controller.abort(new Error('not sent')),
  onError: () => undefined,
  onHeaders: () => false,
  onData: () => false,
  onComplete: () => undefined,
};

/**
 * The name of the global dispatcher when it sends a request for `url` through a proxy, or
 * `undefined` when it sends it straight to its host or cannot be read. The first time it names one,
 * it warns through `logger.warn` that hosts a presenter names are then held to their URL alone, and
 * that the proxy must refuse private and local addresses.
 */
export function fetchRoutedThrough(url: string): string | undefined {
  const name = proxyingDispatcher(url);
  if (name !== undefined) {
    warnHeldToUrlAlone(`the global ${name} dispatcher sends fetch requests through a proxy, not straight to each host`, 'the proxy');
  }
  return name;
}

/** The name of the global dispatcher when it sends a request for `url` through a proxy, as this module opens by saying. */
function proxyingDispatcher(url: string): string | undefined {
  const dispatcher: unknown = (globalThis as Record<symbol, unknown>)[GLOBAL_DISPATCHER];
  if (typeof dispatcher !== 'object' || dispatcher === null) return undefined;
  const name = classNameOf(dispatcher);
  if (name === 'ProxyAgent') return name;
  if (name === 'EnvHttpProxyAgent' && classNameOf(agentPickedFor(dispatcher, url)) === 'ProxyAgent') return name;
  return undefined;
}

/**
 * The agent an `EnvHttpProxyAgent` picks for a request to `url`, asked of the dispatcher itself, so
 * its own reading of its proxy settings and `NO_PROXY`, from its options or the environment,
 * decides. For one synchronous dispatch, of no request, each agent it picks between answers its
 * `dispatch` by noting it was picked, and is then restored. `undefined` where those agents are not
 * all found, or the dispatch fails.
 */
function agentPickedFor(dispatcher: object, url: string): object | undefined {
  const keys = Object.getOwnPropertySymbols(dispatcher).filter((key) => PICKED_AGENTS.has(key.description ?? ''));
  const agents = new Set(keys.map((key) => (dispatcher as Record<symbol, unknown>)[key]));
  if (keys.length !== PICKED_AGENTS.size || ![...agents].every(isShadowable)) return undefined;
  let picked: object | undefined;
  const answering = [...agents] as object[];
  try {
    for (const agent of answering) {
      Object.defineProperty(agent, 'dispatch', {
        configurable: true,
        value: () => {
          picked = agent;
          return true;
        },
      });
    }
    (dispatcher as { dispatch(options: object, handler: object): unknown }).dispatch(
      { origin: new URL(url).origin, path: '/', method: 'GET' },
      NO_REQUEST,
    );
  } catch {
    return undefined;
  } finally {
    for (const agent of answering) delete (agent as { dispatch?: unknown }).dispatch;
  }
  return picked;
}

/** Whether `agent` is an object whose `dispatch` comes from its class, so an own one can stand in for it and be removed. */
function isShadowable(agent: unknown): agent is object {
  return typeof agent === 'object' && agent !== null && !Object.hasOwn(agent, 'dispatch') && Object.isExtensible(agent);
}

/** The name of `value`'s class, or `undefined` when it has none or cannot be read. */
function classNameOf(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  try {
    const name = (Object.getPrototypeOf(value) as { constructor?: { name?: unknown } } | null)?.constructor?.name;
    return typeof name === 'string' ? name : undefined;
  } catch {
    return undefined;
  }
}
