/**
 * The rule every API that accepts a delegation chain from a caller holds its options to: it must
 * pin the chain's root, the issuer accountable for the authority (SPEC §6), or say why it need not.
 *
 * `trustedRootIssuers` names the DIDs allowed to grant authority, and, where an API takes it,
 * `resourceOwner` names the one DID that owns the resource. With neither, a delegation from any
 * issuer is accepted, including one an agent signs for itself, so the check means nothing. Outside
 * development such an API refuses to run, naming every fix; `development: true`, or
 * `allowAnyRootIssuer: true` by name, lets it run with one warning. The middleware
 * (`../middleware/with-kya-os.root-issuers.ts`) and the Entity Card guards
 * (`../card/request-root-issuers.ts`) both decide by {@link rootIssuerPolicy} and say so in the
 * words built here, each with its own option names, so the two never drift apart.
 */

import { describeValue } from '../utils/describe-value.js';
import { developmentSwitch } from '../utils/development-mode.js';
import { assertTrustedRootIssuers } from './root-admission.js';

/** How an API names the options of the rule in its messages. */
export interface RootIssuerOptionNames {
  /** What comes before each option's name: `"delegation."` on the middleware, `""` on the Card. */
  readonly prefix: string;
  /** Whether the API takes `resourceOwner`, which pins the root too, so its messages name it beside the list. */
  readonly resourceOwner: boolean;
}

/** An API's settings for the rule, as its caller gave them. */
export interface RootIssuerSettings {
  readonly trustedRootIssuers: unknown;
  readonly allowAnyRootIssuer: unknown;
  /** The `resourceOwner` option, for an API that takes one. */
  readonly resourceOwner?: unknown;
  /** Whether development is on, as the API's own switch has read it. */
  readonly development: boolean;
}

/** What an API may do with a delegation chain under its settings. */
export interface RootIssuerPolicy {
  /**
   * `pinned` when a setting pins the root, `any-issuer` when none does but `allowAnyRootIssuer`
   * or development lets the API run anyway, and `unpinned` when none does and nothing lets it.
   */
  readonly kind: 'pinned' | 'any-issuer' | 'unpinned';
  /** The message of the `Error` an `unpinned` API throws when `entry` is about to accept a chain. */
  refusal(entry: string): string;
  /** The warning an `any-issuer` API logs once, where `entry` names the API that would otherwise throw. */
  warning(entry: string): string;
}

/**
 * The policy of an API whose settings are `settings`, named in its messages as `names` says.
 *
 * Throws a `TypeError`, naming the option, for a `trustedRootIssuers` that is not an array of DIDs,
 * for an `allowAnyRootIssuer` that is not a boolean, and for `allowAnyRootIssuer: true` beside a
 * pin, an empty list included, since the two contradict each other.
 */
export function rootIssuerPolicy(settings: RootIssuerSettings, names: RootIssuerOptionNames): RootIssuerPolicy {
  const { prefix } = names;
  assertTrustedRootIssuers(settings.trustedRootIssuers, prefix);
  const allowAny = readAllowAnyRootIssuer(settings.allowAnyRootIssuer, prefix);
  const pin = pinOf(settings, names);
  if (allowAny && pin !== undefined) {
    throw new TypeError(
      `[kya-os] ${prefix}allowAnyRootIssuer is true and ${prefix}${pin.option} is set, and they contradict each ` +
        `other: ${pin.trusts}, and allowAnyRootIssuer trusts every issuer. Set one or the other.`,
    );
  }
  const kind = pin !== undefined ? 'pinned' : allowAny || settings.development ? 'any-issuer' : 'unpinned';
  return {
    kind,
    refusal: (entry) =>
      `[kya-os] ${unpinned(names)}, so ${entry} would accept a delegation from any issuer, including one an agent ` +
      `signs for itself. ${pinFix(names)}; in local development, set development: true; to accept any issuer ` +
      `anyway, set ${prefix}allowAnyRootIssuer: true.`,
    warning: (entry) => {
      const pins = names.resourceOwner ? 'one of them' : 'it';
      const because = allowAny
        ? `${prefix}allowAnyRootIssuer is true`
        : `development is true; outside development, ${entry} throws without ${pins}`;
      return (
        `[kya-os] ${unpinned(names)}, so a delegation from any issuer is accepted, including one an agent signs ` +
        `for itself, because ${because}. ${pinFix(names)}.`
      );
    },
  };
}

/**
 * Whether `value`, the `development` option of an API named `setting` that reads no host, turns
 * development on, which lets the API accept any issuer. It is checked as everywhere else: anything
 * but a boolean throws a `TypeError`, and `true` throws an `Error` naming every fix while `NODE_ENV`
 * is `production`. The API's root-issuer warning says what it changes, so it logs nothing itself.
 */
export function rootIssuerDevelopment(value: unknown, setting: string, names: RootIssuerOptionNames): boolean {
  return developmentSwitch(
    value,
    setting,
    'development: true accepts a delegation from any issuer and must never run in production. Remove it, and ' +
      `${lowerFirst(pinFix(names))}; to accept any issuer anyway, set ${names.prefix}allowAnyRootIssuer: true.`,
  );
}

/** The option that pins the root, and what it trusts, or `undefined` when none does. */
function pinOf(
  settings: RootIssuerSettings,
  names: RootIssuerOptionNames,
): { option: string; trusts: string } | undefined {
  if (settings.trustedRootIssuers !== undefined) {
    return { option: 'trustedRootIssuers', trusts: 'the list names the only issuers to trust' };
  }
  if (names.resourceOwner && settings.resourceOwner !== undefined) {
    return { option: 'resourceOwner', trusts: 'resourceOwner names the only issuer to trust' };
  }
  return undefined;
}

/** `value`, the `allowAnyRootIssuer` option: absent reads as `false`, and any other value but a boolean throws. */
function readAllowAnyRootIssuer(value: unknown, prefix: string): boolean {
  if (value === undefined || typeof value === 'boolean') return value === true;
  throw new TypeError(`[kya-os] ${prefix}allowAnyRootIssuer must be true or false (got a value ${describeValue(value)})`);
}

/** That no option pins the root, in the API's own option names. */
function unpinned({ prefix, resourceOwner }: RootIssuerOptionNames): string {
  return resourceOwner
    ? `neither ${prefix}trustedRootIssuers nor ${prefix}resourceOwner is set`
    : `${prefix}trustedRootIssuers is not set`;
}

/** How to pin the root, in the API's own option names. */
function pinFix({ prefix, resourceOwner }: RootIssuerOptionNames): string {
  const owner = resourceOwner ? `, or ${prefix}resourceOwner to the DID that owns the resource` : '';
  return `Set ${prefix}trustedRootIssuers to the DIDs allowed to grant authority${owner}`;
}

/** `text` with its first letter in lower case, to follow a comma. */
function lowerFirst(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1);
}
