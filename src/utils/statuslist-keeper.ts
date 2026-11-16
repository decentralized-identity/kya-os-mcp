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

/**
 * The status-list URLs each status-list issuer keeps, keyed by that issuer's DID:
 *
 *     {
 *       'did:web:status.example': ['https://status.example/'],
 *       'did:web:acme.example': ['https://lists.acme.example/herd/1', 'https://lists.acme.example/herd/2'],
 *     }
 *
 * A binding is a whole `https:` origin, written as `https://` and a lower-case host with an
 * optional port and nothing after it but, at most, one `/`, or an exact URL, which a status entry
 * must name byte for byte. `https://status.example/` and `https://status.example` are one origin;
 * the first is the form refusals print. A credential opts in to a keeper by naming, in the status
 * entry its issuer signed, a URL the map binds to that keeper; the map is not scoped by credential
 * issuer. One binding has one keeper, so the same URL, or the same origin in either form, under two
 * issuers is refused. An exact URL of one issuer may lie inside an origin of another, and the exact
 * binding then decides. There is no prefix binding: a URL that ends in `/` and is not a whole
 * origin is refused, and so is a binding with an upper-case letter in its host, since neither could
 * match the URL of a list. An origin whose host is an IPv6 literal is not offered: such a deployment
 * binds exact URLs. Off by default: with no map, a URL is kept by a pinned root whose own
 * credential names it, or else by the credential's own issuer.
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

/** A binding that is a whole origin: `https://`, a lower-case host, an optional port, and at most a `/` after. */
const ORIGIN = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?\/?$/;
/** The whole origin a URL is at, in the form {@link ORIGIN} takes, when one of {@link AFTER_ORIGIN} follows it. */
const AT_ORIGIN = /^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?(?=[/?#])/;
/** What an exact URL binding must start with. */
const URL_SCHEME = /^https?:\/\//;
/** The authority of a binding that starts with {@link URL_SCHEME}, as written. */
const AUTHORITY = /^https?:\/\/([^/?#]*)/;
/** The characters that end the authority of an `https:` URL, so one of them follows an origin in a URL at it. */
const AFTER_ORIGIN = ['/', '?', '#'];

/** The origin an origin binding names, without the `/` it may end in, or `undefined` for an exact URL binding. */
function originOf(binding: string): string | undefined {
  return ORIGIN.test(binding) ? binding.replace(/\/$/, '') : undefined;
}

/**
 * The origin binding that holds `url`, in the form refusals print, `https://`, the host, its port if
 * written, and `/`, or `undefined` when no origin binding holds it, as for an `http:` URL, a host
 * with an upper-case letter or an IPv6 literal.
 */
export function originBindingOf(url: string): string | undefined {
  const origin = AT_ORIGIN.exec(url)?.[0];
  return origin === undefined ? undefined : `${origin}/`;
}

/**
 * Throw a `TypeError` unless `statusListIssuers` is absent or a plain object whose own keys are
 * non-empty strings and whose values are arrays of bindings, each an `https:` origin or a URL that
 * starts with `https://` or `http://`, and none bound to two issuers, an origin in either of its
 * forms. A binding that could match no list's URL is refused, with what to write instead: one that
 * a URL parser does not take, one with an upper-case letter in its host, and one that ends in `/`
 * but is not a whole origin, which would bind only the URL that ends there. A reader checks it when it is
 * configured: a map it could not apply is a configuration error, never a refusal of each list it
 * reads. {@link statusListKeeperFor} checks it as well, so a reader that skips that check meets
 * this error, not another. A value that is not a URL, such as a DID, is refused, which catches a
 * map written the other way round, from a credential issuer to the issuers accepted for it.
 */
export function assertStatusListIssuers(value: unknown): asserts value is StatusListIssuers | undefined {
  if (value === undefined) return;
  if (!isPlainObjectOfThisRealm(value)) {
    throw new TypeError(
      'statusListIssuers must be a plain object mapping each status-list issuer DID to the status-list URLs or https origins it keeps',
    );
  }
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
      assertMatchable(keeper, binding);
      const bound = originOf(binding) ?? binding;
      const other = keeperOf.get(bound);
      if (other !== undefined && other !== keeper) {
        throw new TypeError(
          `statusListIssuers binds ${describeValue(binding)} to both ${describeValue(other)} and ${describeValue(keeper)}, and a URL has one keeper`,
        );
      }
      keeperOf.set(bound, keeper);
    }
  }
}

/**
 * Throw a `TypeError` saying what to write instead when `binding`, which starts with `http://` or
 * `https://`, could match no status list's URL. A list is fetched from its URL, so a binding a URL
 * parser does not take matches none. A host is compared as written, and a URL parser writes it in
 * lower case. And a binding that ends in `/` but is not a whole origin reads as a path prefix, which
 * binds nothing: it is an exact URL, matched only by the URL that ends at that `/`.
 */
function assertMatchable(keeper: string, binding: string): void {
  const holds = `statusListIssuers[${describeValue(keeper)}] holds ${describeValue(binding)}`;
  if (!parsesAsUrl(binding)) {
    throw new TypeError(`${holds}, which is not a URL, so no status list's URL can match it`);
  }
  const authority = AUTHORITY.exec(binding)?.[1] ?? '';
  const host = authority.slice(authority.lastIndexOf('@') + 1);
  if (host !== host.toLowerCase()) {
    throw new TypeError(
      `${holds}, whose host is not in lower case, so no status list's URL can match it: write the host as ${describeValue(host.toLowerCase())}`,
    );
  }
  if (binding.endsWith('/') && originOf(binding) === undefined) {
    const origin = originBindingOf(binding);
    throw new TypeError(
      `${holds}, which ends in "/" but is not a whole origin: a binding is a status list's exact URL or a whole https origin` +
        (origin === undefined ? '' : `, such as ${describeValue(origin)}`) +
        ', and binds no URL that merely starts with it',
    );
  }
}

/** Whether `value` is a URL a URL parser takes. */
function parsesAsUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether the URL `url` is at the origin `origin`, an origin binding without the `/` it may end in:
 * it is that string, or continues it with `/`, `?` or `#`. So both forms of one origin bind the same
 * URLs, though rule 1 takes first the URL that is a binding's own string. This is a rule on the
 * bytes as written, with no parsing and no normalisation, so every implementation decides alike.
 * It never gives a keeper a URL a parser would place at another host: the authority of an
 * `https:` URL ends at the first `/`, `?` or `#`, so a URL that continues the origin with anything
 * else, more of a host name, a port, an `@` or a `\`, is not at it. Such a URL falls to the rules
 * below, which hand it only to the issuer that chose to write it in its own credential. A host
 * written in another case is likewise not at the origin.
 */
function isAtOrigin(url: string, origin: string | undefined): boolean {
  return origin !== undefined && (url === origin || AFTER_ORIGIN.some((next) => url.startsWith(origin + next)));
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
  assertStatusListIssuers(statusListIssuers);
  const bound = Object.entries(statusListIssuers ?? {});
  for (const [did, bindings] of bound) {
    if (bindings.includes(statusListCredential)) return { did, why: 'configured-url' };
  }
  for (const [did, bindings] of bound) {
    if (bindings.some((binding) => isAtOrigin(statusListCredential, originOf(binding)))) {
      return { did, why: 'configured-origin' };
    }
  }
  const { credentialIssuer, trustedRootIssuer, trustedRootStatusList } = context;
  if (trustedRootIssuer !== undefined && trustedRootStatusList === statusListCredential) {
    return { did: trustedRootIssuer, why: 'root-credential' };
  }
  return { did: credentialIssuer, why: 'credential-issuer' };
}

/**
 * Whether `statusListIssuers` names an issuer other than `did`, whatever it binds to it. A reader
 * that lets a list leave out its `id` asks this: only the `id` binds a list to its URL, so a list
 * may omit it only where no other issuer keeps any URL.
 */
export function namesAnotherKeeper(statusListIssuers: StatusListIssuers | undefined, did: string): boolean {
  return Object.keys(statusListIssuers ?? {}).some((keeper) => keeper !== did);
}
