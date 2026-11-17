/**
 * Who keeps a status-list URL: the one issuer whose signature a list fetched from that URL must
 * carry. A list's `id` binds the list to a URL, but nothing in a list binds a URL to one signer, so
 * a reader that took a list from any of several issuers it trusts would let each of them speak at
 * every URL an entry names: a pinned root could serve a clear list at a delegate's own URL, and a
 * delegate one at the root's. So every URL has exactly one keeper, decided before any fetch from
 * the verifier's configuration and the signed credentials, and never from the list.
 *
 * The keeper of the URL `U` that a credential's status entry names is, first match first:
 * 1. the issuer `statusListIssuers` binds to the exact string `U`;
 * 2. the issuer `statusListIssuers` binds to the `https:` origin `U` is at;
 * 3. the pinned root of the credential's chain, when `U` is, byte for byte, the URL the root's own
 *    credential's status entry names;
 * 4. the credential's own issuer.
 * So the configuration decides before a root's credential does, and at a URL a configured issuer or
 * the root keeps, a list the credential's own issuer signed is refused as any other is.
 */

import { describeValue } from './describe-value.js';
import { isPlainObjectOfThisRealm } from './guards.js';
import type { VerifiedRootMark } from './verified-root.js';

/**
 * The status-list URLs each status-list issuer keeps, keyed by that issuer's DID:
 *
 *     {
 *       'did:web:status.example': ['https://status.example'],
 *       'did:web:acme.example': ['https://lists.acme.example/herd/1', 'https://lists.acme.example/herd/2'],
 *     }
 *
 * A binding is read as SPEC.md §6.6 reads it: a whole `https:` origin, written as `https://` and a
 * lower-case host with an optional port and nothing after it, or else an exact URL, which a status
 * entry must name byte for byte. A credential opts in to a keeper by naming, in the status entry its
 * issuer signed, a URL the map binds to that keeper; the map is not scoped by credential issuer. One
 * binding has one keeper, so the same string under two issuers is refused. An exact URL of one
 * issuer may lie inside an origin of another, and the exact binding then decides. There is no other
 * form of an origin and no prefix binding, so the bindings that are almost always one written in
 * another form are refused, as §6.6 says a verifier should, naming the fix: an origin followed by
 * `/`, an origin whose host has an upper-case letter, and any other binding that ends in `/`. Any
 * other exact URL is taken as written, upper-case letters included. An origin whose host is an IPv6
 * literal is not offered: such a deployment binds exact URLs. Off by default: with no map, a URL is
 * kept by a pinned root whose own credential names it, or else by the credential's own issuer.
 */
export type StatusListIssuers = Readonly<Record<string, readonly string[]>>;

/** The credential whose status a status-list reader checks. */
export interface StatusCheckContext {
  /** The DID of the credential's issuer: its `issuer`, or `issuer.id`. */
  credentialIssuer: string;
  /**
   * The issuer of the first credential of the credential's delegation chain, named only when the
   * verifier pins it (`trustedRootIssuers` or `resourceOwner`), or, for an Entity Card, the Card's
   * responsible party once the Card's accountability check has verified it as that root. The root
   * can revoke its own credential, which revokes every credential below it. It keeps the URL
   * {@link trustedRootStatusList} names, and the URLs the configuration binds to it. The issuers
   * between the root and the credential are not named: a credential commits to its parent only by
   * an id the parent's issuer chose, so whoever presents a chain decides who stands between them,
   * while the root is held to the verifier's own configuration.
   */
  trustedRootIssuer?: string;
  /**
   * The `statusListCredential` URL that the status entry of the chain's first credential names, a
   * credential {@link trustedRootIssuer} signed. A credential of the chain whose own entry names
   * the same URL, byte for byte, has its status on the root's list. It means something only beside
   * `trustedRootIssuer`, and is ignored without it.
   */
  trustedRootStatusList?: string;
  /**
   * The library's mark that the proof of the credential {@link trustedRootIssuer} signed has
   * verified, so {@link trustedRootStatusList} is that root's own word and a read of it is the
   * operator's: its host may be private (`./verified-root`). Only the library makes one, after that
   * proof, and a reader honours only a mark the library made for this root and this URL. Leave it as
   * it is given; a context without it is read as one whose root list a presenter named.
   */
  trustedRootVerified?: VerifiedRootMark;
}

/** The one issuer whose list is read at a status-list URL, and why it is that issuer. */
export interface StatusListKeeper {
  /** The DID whose signature a list at the URL must carry. */
  did: string;
  /**
   * Why it keeps the URL: the configuration binds the exact URL to it, or the URL's origin; it is
   * the pinned root and its own credential names the URL; it is the credential's own issuer; or it
   * is the one issuer a resolver is configured to trust for every list it reads.
   */
  why: 'configured-url' | 'configured-origin' | 'root-credential' | 'credential-issuer' | 'resolver-issuer';
}

/** A binding that is a whole origin: `https://`, a lower-case host, an optional port, nothing after. */
const ORIGIN = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/;
/**
 * A binding written as an origin with a host in any case, and perhaps a `/` after it: its host and
 * port are the first group, and the `/` the second. Only {@link ORIGIN} is an origin.
 */
const ORIGIN_IN_ANY_FORM = /^https:\/\/([A-Za-z0-9.-]+(?::[0-9]{1,5})?)(\/?)$/;
/** The whole origin a URL is at, in the form {@link ORIGIN} takes, when one of {@link AFTER_ORIGIN} follows it. */
const AT_ORIGIN = /^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?(?=[/?#])/;
/** What an exact URL binding must start with. */
const URL_SCHEME = /^https?:\/\//;
/** The characters that end the authority of an `https:` URL, so one of them follows an origin in a URL at it. */
const AFTER_ORIGIN = ['/', '?', '#'];

/** Whether `binding` is an origin binding, in SPEC.md §6.6's form, rather than an exact URL. */
export function isOriginBinding(binding: string): boolean {
  return ORIGIN.test(binding);
}

/**
 * The origin binding that holds `url`, in SPEC.md §6.6's form, `https://`, the host and its port if
 * written, or `undefined` when no origin binding holds it, as for an `http:` URL, a host with an
 * upper-case letter or an IPv6 literal, or a URL that is itself an origin.
 */
export function originBindingOf(url: string): string | undefined {
  return AT_ORIGIN.exec(url)?.[0];
}

/**
 * Throw a `TypeError` unless `statusListIssuers` is absent or a plain object whose own keys are
 * non-empty strings and whose values are arrays of bindings, each an `https:` origin or a URL that
 * starts with `https://` or `http://`, none of them one {@link assertNotMistaken} refuses, and none
 * bound to two issuers. A reader checks it when it is configured: a map it could not apply, or one
 * that writes an origin or a prefix in a form SPEC.md §6.6 does not read as one, is a configuration
 * error, never a refusal of each list it reads. {@link statusListKeeperFor} checks it as well, so a
 * reader that skips that check meets this error, not another. A value that is not a URL, such as a
 * DID, is refused, which catches a map written the other way round, from a credential issuer to the
 * issuers accepted for it.
 */
export function assertStatusListIssuers(value: unknown): asserts value is StatusListIssuers | undefined {
  if (value === undefined) return;
  if (!isPlainObjectOfThisRealm(value)) {
    throw new TypeError(
      'statusListIssuers must be a plain object mapping each status-list issuer DID to the status-list URLs or https origins it keeps',
    );
  }
  const originKeepers = keepersOfOrigins(value);
  const keeperOf = new Map<string, string>();
  for (const [keeper, bindings] of Object.entries(value)) {
    if (keeper === '') {
      throw new TypeError('statusListIssuers has an empty key, where it must name a status-list issuer DID');
    }
    if (!Array.isArray(bindings)) {
      throw new TypeError(`statusListIssuers[${describeValue(keeper)}] must be an array of status-list URLs or https origins`);
    }
    for (const binding of bindings as unknown[]) {
      if (typeof binding !== 'string' || !URL_SCHEME.test(binding)) {
        throw new TypeError(
          `statusListIssuers[${describeValue(keeper)}] holds ${describeValue(binding)}, which is not a status-list URL or an https origin: ` +
            'each value names the URLs that issuer keeps, not the issuers accepted for a credential issuer',
        );
      }
      assertNotMistaken(keeper, binding, originKeepers);
      const other = keeperOf.get(binding);
      if (other !== undefined && other !== keeper) {
        throw new TypeError(
          `statusListIssuers binds ${describeValue(binding)} to both ${describeValue(other)} and ${describeValue(keeper)}, and a URL has one keeper`,
        );
      }
      keeperOf.set(binding, keeper);
    }
  }
}

/** The issuer each origin binding of `value`, a plain object, binds its origin to, read without judging the rest. */
function keepersOfOrigins(value: Readonly<Record<string, unknown>>): ReadonlyMap<string, string> {
  const keepers = new Map<string, string>();
  for (const [keeper, bindings] of Object.entries(value)) {
    if (!Array.isArray(bindings)) continue;
    for (const binding of bindings as unknown[]) {
      if (typeof binding === 'string' && ORIGIN.test(binding) && !keepers.has(binding)) keepers.set(binding, keeper);
    }
  }
  return keepers;
}

/**
 * Throw a `TypeError` naming the fix when `binding`, which starts with `http://` or `https://`, is
 * one SPEC.md §6.6 says a verifier should refuse, since it is almost always an origin or a prefix
 * written in a form §6.6 does not read as one: an origin followed by `/`, an origin whose host has
 * an upper-case letter, or any other binding that ends in `/`. Read as written, each is an exact
 * URL, which binds only the status entries that name it byte for byte. The rule is on the bytes as
 * written, as the keeper rule is, so the conformance harness refuses exactly these bindings too.
 * `originKeepers` names the issuer each origin binding of the configuration keeps, so that the
 * refusal of a binding that ends in `/` says what accepts a list whose own URL ends in `/`.
 */
function assertNotMistaken(keeper: string, binding: string, originKeepers: ReadonlyMap<string, string>): void {
  const holds = `statusListIssuers[${describeValue(keeper)}] holds ${describeValue(binding)}`;
  const written = ORIGIN_IN_ANY_FORM.exec(binding);
  if (written !== null && !ORIGIN.test(binding)) {
    // The host and port are ASCII letters, digits, `.`, `-` and `:`, so JSON prints them exactly.
    const origin = JSON.stringify(`https://${written[1]!.toLowerCase()}`);
    throw new TypeError(
      written[2] === '/'
        ? `${holds}, an origin followed by "/", which binds only itself, as an exact URL, and no other URL at that origin: ` +
            `write it as ${origin}`
        : `${holds}, an origin whose host is not in lower case, which binds only itself, as an exact URL, and no URL at ` +
            `that origin: write the host in lower case, as ${origin}`,
    );
  }
  if (binding.endsWith('/')) {
    throw new TypeError(
      `${holds}, which ends in "/" as a path prefix would, but a binding is an https origin or a list's exact URL, never a prefix: ` +
        trailingSlashFix(keeper, originBindingOf(binding), originKeepers),
    );
  }
}

/**
 * What to bind instead of a binding of `keeper`'s that ends in `/` and is at `origin`, if any. A
 * binding may not end in `/`, so a list whose own URL does is kept only through its origin: the fix
 * names that origin, and says plainly that the list's URL must change where no origin binding holds
 * it or the configuration binds its origin to another issuer.
 */
function trailingSlashFix(keeper: string, origin: string | undefined, originKeepers: ReadonlyMap<string, string>): string {
  const eachUrl = 'bind each list URL that does not end in "/"';
  const changeIt = "change that list's URL";
  if (origin === undefined) {
    return `${eachUrl}; no binding can accept a list whose own URL ends in "/" and is at no https origin a binding can name: ${changeIt}`;
  }
  const other = originKeepers.get(origin);
  if (other !== undefined && other !== keeper) {
    return (
      `${eachUrl}; no binding can accept a list whose own URL ends in "/" there, since the origin, ${JSON.stringify(origin)}, ` +
      `is bound to ${describeValue(other)}: ${changeIt}`
    );
  }
  return `bind the origin, ${JSON.stringify(origin)}, which keeps every list at it, one whose own URL ends in "/" included, or ${eachUrl}`;
}

/**
 * Whether the URL `url` is at the origin binding `origin`: it continues that string with `/`, `?`
 * or `#`. (The origin's own string, named as a URL, is an exact binding.) This is a rule on the
 * bytes as written, with no parsing and no normalisation, so every implementation decides alike.
 * It never gives a keeper a URL a parser would place at another host: the authority of an
 * `https:` URL ends at the first `/`, `?` or `#`, so a URL that continues the origin with anything
 * else, more of a host name, a port, an `@` or a `\`, is not at it. Such a URL falls to the rules
 * below, which hand it only to the issuer that chose to write it in its own credential. A host
 * written in another case is likewise not at the origin.
 */
function isAtOrigin(url: string, origin: string): boolean {
  return AFTER_ORIGIN.some((next) => url.startsWith(origin + next));
}

/**
 * The keeper of `statusListCredential`, the URL a status entry names, for the credential `context`
 * names, by the four rules this module opens with. Only a binding the map owns counts, so an
 * inherited key such as `constructor` binds nothing. Two origin bindings never both hold one URL,
 * since no origin continues another with `/`, `?` or `#`, so the order of the map decides nothing.
 * `trustedRootStatusList` counts only beside `trustedRootIssuer`.
 *
 * @throws TypeError when `statusListIssuers` is malformed, as {@link assertStatusListIssuers} words it.
 */
export function statusListKeeperFor(
  statusListCredential: string,
  context: StatusCheckContext,
  statusListIssuers?: StatusListIssuers,
): StatusListKeeper {
  const configured = configuredKeeper(statusListCredential, statusListIssuers);
  if (configured !== undefined) return configured;
  const { credentialIssuer, trustedRootIssuer, trustedRootStatusList } = context;
  if (trustedRootIssuer !== undefined && trustedRootStatusList === statusListCredential) {
    return { did: trustedRootIssuer, why: 'root-credential' };
  }
  return { did: credentialIssuer, why: 'credential-issuer' };
}

/**
 * The keeper `statusListIssuers` binds `url` to, by the first two rules this module opens with, or
 * `undefined` when it binds it to none.
 *
 * @throws TypeError when `statusListIssuers` is malformed, as {@link assertStatusListIssuers} words it.
 */
function configuredKeeper(url: string, statusListIssuers: StatusListIssuers | undefined): StatusListKeeper | undefined {
  assertStatusListIssuers(statusListIssuers);
  const bound = Object.entries(statusListIssuers ?? {});
  for (const [did, bindings] of bound) {
    if (bindings.includes(url)) return { did, why: 'configured-url' };
  }
  for (const [did, bindings] of bound) {
    if (bindings.some((binding) => ORIGIN.test(binding) && isAtOrigin(url, binding))) return { did, why: 'configured-origin' };
  }
  return undefined;
}

/**
 * Whether `statusListIssuers` binds the status-list URL `url`, as its exact string or by its
 * `https:` origin, to any issuer: whether the verifier's operator named the URL, as a reader that
 * reads such a URL on a private host asks.
 *
 * @throws TypeError when `statusListIssuers` is malformed, as {@link assertStatusListIssuers} words it.
 */
export function statusListIssuersBind(url: string, statusListIssuers: StatusListIssuers | undefined): boolean {
  return configuredKeeper(url, statusListIssuers) !== undefined;
}

/**
 * Whether `statusListIssuers` names an issuer other than `did`, whatever it binds to it. A reader
 * that lets a list leave out its `id` asks this: only the `id` binds a list to its URL, so a list
 * may omit it only where no other issuer keeps any URL.
 */
export function namesAnotherKeeper(statusListIssuers: StatusListIssuers | undefined, did: string): boolean {
  return Object.keys(statusListIssuers ?? {}).some((keeper) => keeper !== did);
}
