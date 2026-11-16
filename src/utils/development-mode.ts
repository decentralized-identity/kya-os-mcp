/**
 * The development switch, `development: true`. A did:web DID or a status list on `localhost`, a
 * `*.localhost` name, a private IP or another local name is refused by the private-network rule
 * (`./private-network-rule`), as it must be in production, and every local demo runs on such names.
 * The switch admits them for the reads of whatever it is set on, as `allowPrivateNetworkHosts: true`
 * does on a fetch provider, and changes nothing else: the scheme rule, checked redirects, byte caps
 * and deadlines all hold.
 *
 * It is for development alone. Set while `NODE_ENV` is `production`, it throws when what it is set
 * on is built, naming the setting, and the first time it is turned on in a process it warns that
 * private and local hosts are read. A production deployment that must read an intranet host keeps
 * the production opt-in, `allowPrivateNetworkHosts: true` on its fetch provider.
 */

import { logger } from '../logging/index.js';

/** Where the process records that the warning was given, shared by every copy of the package it loads. */
const WARNED = Symbol.for('@kya-os/mcp/development-warned');

/** The production opt-in the refusals and the production guard name beside `development: true`. */
export const PRODUCTION_PRIVATE_HOSTS = 'give the fetch provider allowPrivateNetworkHosts: true';

/**
 * Whether `value`, the `development` option of `setting`, turns development on. Absent or `false`
 * leaves it off. `true` turns it on, unless `NODE_ENV` is `production`, when it throws naming
 * `setting` and `productionOptIn`, the setting that reads private hosts in production instead; the
 * first time it is turned on in a process it warns once. Any other value throws a `TypeError`.
 */
export function developmentMode(value: unknown, setting: string, productionOptIn = PRODUCTION_PRIVATE_HOSTS): boolean {
  if (value === undefined || value === false) return false;
  if (value !== true) {
    throw new TypeError(`${setting} must be true or false`);
  }
  if (runsInProduction()) {
    throw new Error(
      `${setting} is true while NODE_ENV is "production": development: true reads private and local hosts and ` +
        `must never run in production. Remove it; to read private hosts in production, ${productionOptIn}.`,
    );
  }
  warnOnce(setting);
  return true;
}

/**
 * Whether `NODE_ENV` is `production`. The expression is written out whole, as a bundler that
 * defines `process.env.NODE_ENV` finds it, and nothing is asked of `process` before it, so a build
 * that inlines `"production"` here refuses development even where no `process` is left, as in a
 * Worker. A runtime with no `process`, or one that refuses to read the environment, is not
 * production as far as this can tell.
 */
function runsInProduction(): boolean {
  try {
    return process.env.NODE_ENV === 'production';
  } catch {
    return false;
  }
}

/** Warn that private and local hosts are read, the first time any setting turns development on. */
function warnOnce(setting: string): void {
  const registry = globalThis as { [WARNED]?: true };
  if (registry[WARNED]) return;
  registry[WARNED] = true;
  logger.warn(
    `[kya-os] development: true is on (${setting}), so private and local hosts such as *.localhost are read. ` +
      'Never use it in production.',
  );
}
