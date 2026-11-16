/**
 * KYA-OS Entity Card: whose authority a verifier of a request's delegation chain trusts.
 *
 * `requireDelegation` and `verifyRequestDelegation` accept a chain the caller presents, carried or
 * resolved by reference. `trustedRootIssuers` or `resourceOwner` pins the chain's root, the party
 * accountable for the call (SPEC-ENTITY-CARD §10.2); with neither, a chain from any root is
 * accepted, including one an agent signs for itself. So outside development they refuse to run
 * until one is set, unless `allowAnyRootIssuer: true` accepts any issuer by name, under the rule
 * the middleware follows too (`../delegation/root-issuer-rule.ts`). With the opt-out, or in
 * development, they run and warn once: once for each guard `requireDelegation` builds, and once
 * for each deps object `verifyRequestDelegation` is called with.
 */

import { rootIssuerDevelopment, rootIssuerPolicy, type RootIssuerOptionNames } from '../delegation/root-issuer-rule.js';
import { logger } from '../logging/index.js';

/** The Card's options of the rule: its own names, with `resourceOwner` beside the list. */
const OPTION_NAMES: RootIssuerOptionNames = { prefix: '', resourceOwner: true };

/** The options of `VerifyRequestDelegationDeps` the rule reads. */
export interface RootIssuerDeps {
  readonly trustedRootIssuers?: readonly string[];
  readonly resourceOwner?: string;
  readonly allowAnyRootIssuer?: boolean;
  readonly development?: boolean;
}

/** The deps objects already warned of, so a verifier called for every request warns once. */
const warned = new WeakSet<object>();

/**
 * Hold `entry`, about to accept a delegation chain under `deps`, to the rule. It returns silently
 * when the root is pinned. With nothing pinned, outside development and without the opt-out, it
 * throws an `Error` naming `entry` and every fix. Otherwise it logs the warning, once for `deps`,
 * or each time when `everyTime` is set, as each guard `requireDelegation` builds warns.
 *
 * Throws a `TypeError`, naming the option, for a `trustedRootIssuers` that is not an array of DIDs,
 * an `allowAnyRootIssuer` or a `development` that is not a boolean, and `allowAnyRootIssuer: true`
 * beside a pin; and an `Error` for `development: true` while `NODE_ENV` is `production`.
 */
export function admitRootIssuers(deps: RootIssuerDeps, entry: string, everyTime = false): void {
  const policy = rootIssuerPolicy(
    {
      trustedRootIssuers: deps.trustedRootIssuers,
      resourceOwner: deps.resourceOwner,
      allowAnyRootIssuer: deps.allowAnyRootIssuer,
      development: rootIssuerDevelopment(deps.development, 'VerifyRequestDelegationDeps.development', OPTION_NAMES),
    },
    OPTION_NAMES,
  );
  if (policy.kind === 'pinned') return;
  if (policy.kind === 'unpinned') throw new Error(policy.refusal(entry));
  if (!everyTime && warned.has(deps)) return;
  warned.add(deps);
  logger.warn(policy.warning(entry));
}
