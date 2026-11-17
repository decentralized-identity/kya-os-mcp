/**
 * The warning that hosts a presenter names are held to the private-network rule by their URL alone
 * (`./private-network-rule`), not resolved, checked and pinned (`./private-network-read`). A read
 * falls back to the URL alone where the runtime resolves no name, as a Worker or a browser does,
 * where the application routes the runtime's `fetch` through a proxy (`./routed-fetch`), and where a
 * provider makes its own connections, as a `FetchProvider` whose `fetch` is its own does, a subclass
 * of `RuntimeFetchProvider` included. Each is said once per process for each reason, so an operator
 * learns that the egress must refuse private addresses without a line per read.
 */

import { logger } from '../logging/index.js';

/** The reasons this package copy has given. */
const given = new Set<string>();

/**
 * Warn through `logger.warn`, the first time `why` is given, that a host a presenter names is held
 * to the private-network rule by its URL alone, because `why`, and that `refuser` must refuse
 * private and local addresses itself.
 */
export function warnHeldToUrlAlone(why: string, refuser = 'the egress'): void {
  if (given.has(why)) return;
  given.add(why);
  logger.warn(
    `[kya-os] ${why}, so a host a presenter names is held to the private-network rule by its URL alone and is not ` +
      `resolved or pinned here: ${refuser} must refuse private and local addresses itself.`,
  );
}

/** How a provider is named in a warning: its class's name, or what it is when that has none. */
export function providerName(provider: object, otherwise: string): string {
  let name: unknown;
  try {
    name = (Object.getPrototypeOf(provider) as { constructor?: { name?: unknown } } | null)?.constructor?.name;
  } catch {
    name = undefined;
  }
  return typeof name === 'string' && name !== '' && name !== 'Object' ? name : otherwise;
}
