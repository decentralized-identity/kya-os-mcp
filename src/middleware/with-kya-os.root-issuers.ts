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
import { assertTrustedRootIssuers } from "../delegation/root-admission.js";
import { describeValue } from "../utils/describe-value.js";
import type { KyaOsDelegationConfig } from "./with-kya-os.config-types.js";
import type { KyaOsDelegationGate } from "./with-kya-os.types.js";

/** The `wrapWithDelegation` of a middleware. */
type WrapWithDelegation = KyaOsDelegationGate["wrapWithDelegation"];

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
 * whose development switch, already checked, is `development`.
 *
 * Throws a `TypeError`, naming the option, for a `trustedRootIssuers` that is not an array of
 * DIDs, for an `allowAnyRootIssuer` that is not a boolean, and for `allowAnyRootIssuer: true`
 * beside a `trustedRootIssuers` list, an empty one included, since the two contradict each other.
 */
export function rootIssuerRequirement(
  delegation: KyaOsDelegationConfig | undefined,
  development: boolean,
): RootIssuerRequirement {
  const trustedRootIssuers: unknown = delegation?.trustedRootIssuers;
  assertTrustedRootIssuers(trustedRootIssuers, "delegation.");
  const allowAnyRootIssuer = readAllowAnyRootIssuer(delegation?.allowAnyRootIssuer);
  if (allowAnyRootIssuer && trustedRootIssuers !== undefined) {
    throw new TypeError(
      "[kya-os] delegation.allowAnyRootIssuer is true and delegation.trustedRootIssuers is set, and they " +
        "contradict each other: the list names the only issuers to trust, and allowAnyRootIssuer trusts " +
        "every issuer. Set one or the other.",
    );
  }
  // Settled once the list is set, or once the first wrap has warned that it is not.
  let settled = trustedRootIssuers !== undefined;
  return {
    admit(toolName) {
      if (settled) return;
      if (!allowAnyRootIssuer && !development) throw new Error(refusal(toolName));
      settled = true;
      logger.warn(acceptingAnyIssuer(allowAnyRootIssuer ? ALLOWED_BY_NAME : ALLOWED_IN_DEVELOPMENT));
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

/** Why a delegation from any issuer is accepted, when `allowAnyRootIssuer` is true. */
const ALLOWED_BY_NAME = "delegation.allowAnyRootIssuer is true";

/** Why a delegation from any issuer is accepted, in development. */
const ALLOWED_IN_DEVELOPMENT =
  "development is true; outside development, wrapWithDelegation throws without it";

/** `value`, the `allowAnyRootIssuer` option: absent reads as `false`, and any other value but a boolean throws. */
function readAllowAnyRootIssuer(value: unknown): boolean {
  if (value === undefined || typeof value === "boolean") return value === true;
  throw new TypeError(`[kya-os] delegation.allowAnyRootIssuer must be true or false (got a value ${describeValue(value)})`);
}

/** The refusal to wrap `toolName` outside development, naming every setting that would allow it. */
function refusal(toolName: string): string {
  return (
    `[kya-os] delegation.trustedRootIssuers is not set, so wrapWithDelegation("${toolName}") would accept a ` +
    "delegation from any issuer, including one an agent signs for itself. Set delegation.trustedRootIssuers " +
    "to the DIDs allowed to grant authority; in local development, set development: true; to accept any " +
    "issuer anyway, set delegation.allowAnyRootIssuer: true."
  );
}

/** The warning a server that accepts any issuer logs once, saying `why` it may. */
function acceptingAnyIssuer(why: string): string {
  return (
    "[kya-os] delegation.trustedRootIssuers is not set, so a delegation from any issuer is accepted, " +
    `including one an agent signs for itself, because ${why}. Set delegation.trustedRootIssuers to the DIDs ` +
    "allowed to grant authority."
  );
}
