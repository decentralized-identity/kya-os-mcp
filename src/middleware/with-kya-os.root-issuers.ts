/**
 * KYA-OS Middleware: whose authority a server that accepts delegations trusts.
 *
 * `delegation.trustedRootIssuers` names the DIDs allowed to issue the root of a delegation chain,
 * the chain's Responsible Party (SPEC §6). Without it the gate accepts a delegation from any
 * issuer, including one an agent signs for itself, and its check means nothing. So a server that
 * gates a tool on a delegation must name those DIDs, say it runs in local development, or accept
 * any issuer by name with `delegation.allowAnyRootIssuer: true`.
 *
 * A server that never gates a tool on a delegation depends on none of this, so it is asked where a
 * delegation becomes acceptable: when `wrapWithDelegation` wraps a tool, which is the only way into
 * the gate and into the grants it reuses. The options are read and checked once, when the
 * middleware is created.
 */

import { logger } from "../logging/index.js";
import { rootIssuerPolicy, type RootIssuerOptionNames } from "../delegation/root-issuer-rule.js";
import type { KyaOsDelegationConfig } from "./with-kya-os.config-types.js";
import type { KyaOsDelegationGate } from "./with-kya-os.types.js";

/** The `wrapWithDelegation` of a middleware. */
type WrapWithDelegation = KyaOsDelegationGate["wrapWithDelegation"];

/** The middleware's options of the rule, each under `delegation`. */
const OPTION_NAMES: RootIssuerOptionNames = { prefix: "delegation.", resourceOwner: false };

/**
 * The trust-root requirement of one middleware, built from its options by
 * {@link rootIssuerRequirement}.
 */
export interface RootIssuerRequirement {
  /**
   * Check, as `wrapWithDelegation` wraps `toolName`, that this server may accept a delegation.
   * With `trustedRootIssuers` set it may, silently. Without it, with `allowAnyRootIssuer: true`
   * or in development, it may, and the first call that finds so warns once. Otherwise it throws
   * an `Error` naming `toolName` and every setting that would let it, each time it is called.
   */
  admit(toolName: string): void;
}

/**
 * The trust-root requirement for a middleware whose `delegation` options are `delegation` and
 * whose development switch, already checked, is `development`, under the rule every API that
 * accepts a delegation chain follows (`../delegation/root-issuer-rule.ts`).
 *
 * Throws a `TypeError`, naming the option, for a `trustedRootIssuers` that is not an array of
 * DIDs, for an `allowAnyRootIssuer` that is not a boolean, and for `allowAnyRootIssuer: true`
 * beside a `trustedRootIssuers` list, an empty one included, since the two contradict each other.
 */
export function rootIssuerRequirement(
  delegation: KyaOsDelegationConfig | undefined,
  development: boolean,
): RootIssuerRequirement {
  const policy = rootIssuerPolicy(
    {
      trustedRootIssuers: delegation?.trustedRootIssuers,
      allowAnyRootIssuer: delegation?.allowAnyRootIssuer,
      development,
    },
    OPTION_NAMES,
  );
  // Settled once the root is pinned, or once the first wrap has warned that it is not.
  let settled = policy.kind === "pinned";
  return {
    admit(toolName) {
      if (settled) return;
      if (policy.kind === "unpinned") throw new Error(policy.refusal(`wrapWithDelegation("${toolName}")`));
      settled = true;
      logger.warn(policy.warning("wrapWithDelegation"));
    },
  };
}

/**
 * `gate`'s `wrapWithDelegation`, asking `requirement` before it wraps a tool, so a server that may
 * not accept a delegation never builds a handler that would.
 */
export function requiringRootIssuers(
  gate: { wrapWithDelegation: WrapWithDelegation },
  requirement: RootIssuerRequirement,
): { wrapWithDelegation: WrapWithDelegation } {
  return {
    wrapWithDelegation(toolName, config, handler) {
      requirement.admit(toolName);
      return gate.wrapWithDelegation(toolName, config, handler);
    },
  };
}
