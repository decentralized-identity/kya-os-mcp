/**
 * Whether the runtime's `fetch` connects where the application routes it, rather than to the host a
 * URL names. Node's `fetch` makes every connection through the dispatcher at
 * `Symbol.for('undici.globalDispatcher.1')`. Node's own, undici's plain `Agent`, connects to the host
 * it is asked for, so a read can resolve that host itself and pin the connection to the address it
 * checked. Any other dispatcher there was put there to decide where each request goes: a `ProxyAgent`
 * the application installs with undici's `setGlobalDispatcher`, the `EnvHttpProxyAgent` Node 24
 * installs itself under `NODE_USE_ENV_PROXY=1` or `--use-env-proxy` with `HTTPS_PROXY`, a test's
 * `MockAgent`, or one of the application's own. A read that pinned its own connection would go around
 * it: past the proxy that is the only way out of a proxy-only network, or the mock a test serves.
 * So such a read goes through `fetch`, held to the URL alone, and the proxy must refuse private
 * addresses itself.
 */

import { warnHeldToUrlAlone } from './url-only-reads.js';

/** Where Node's `fetch`, and undici's, find the dispatcher every request goes through. */
const GLOBAL_DISPATCHER = Symbol.for('undici.globalDispatcher.1');

/**
 * The name of the dispatcher the application routes the runtime's `fetch` through, or `undefined`
 * when there is none and `fetch` connects to the host it is asked for. The first time it names one,
 * it warns through `logger.warn` that hosts a presenter names are then held to their URL alone, and
 * that the proxy must refuse private and local addresses.
 */
export function fetchRoutedThrough(): string | undefined {
  const name = routingDispatcherName();
  if (name !== undefined) {
    warnHeldToUrlAlone(
      `fetch goes through the global ${name} dispatcher, not straight to each host`,
      'the proxy, or whatever that dispatcher connects through,',
    );
  }
  return name;
}

/**
 * The name of the global dispatcher when it is not undici's plain `Agent`: its class's name, or a
 * description when it has none. A dispatcher that cannot be read counts as one that routes.
 */
function routingDispatcherName(): string | undefined {
  const dispatcher: unknown = (globalThis as Record<symbol, unknown>)[GLOBAL_DISPATCHER];
  if (typeof dispatcher !== 'object' || dispatcher === null) return undefined;
  let name: unknown;
  try {
    name = (Object.getPrototypeOf(dispatcher) as { constructor?: { name?: unknown } } | null)?.constructor?.name;
  } catch {
    name = undefined;
  }
  if (name === 'Agent') return undefined;
  return typeof name === 'string' && name !== '' ? name : 'unnamed';
}
