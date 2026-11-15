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
 *       'did:web:status.example': ['https://status.example'],
 *       'did:web:acme.example': ['https://lists.acme.example/herd/1', 'https://lists.acme.example/herd/2'],
 *     }
 *
 * A binding is a whole `https:` origin, written as `https://` and a lower-case host with an
 * optional port and nothing after it, or an exact URL, which a status entry must name byte for
 * byte. A credential opts in to a keeper by naming, in the status entry its issuer signed, a URL
 * the map binds to that keeper; the map is not scoped by credential issuer. One binding has one
 * keeper, so the same string under two issuers is refused. An exact URL of one issuer may lie
 * inside an origin of another, and the exact binding then decides. An origin whose host is an IPv6
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
/** What an exact URL binding must start with. */
const URL_SCHEME = /^https?:\/\//;
/** The characters that end the authority of an `https:` URL, so one of them follows an origin in a URL at it. */
const AFTER_ORIGIN = ['/', '?', '#'];

/**
 * Throw a `TypeError` unless `statusListIssuers` is absent or a plain object whose own keys are
 * non-empty strings and whose values are arrays of bindings, each an `https:` origin or a URL that
 * starts with `https://` or `http://`, and none bound to two issuers. A reader checks it when it is
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

/**
 * Whether the URL `url` is at the origin binding `origin`: it continues that string with `/`, `?`
 * or `#`. (The origin's own string, named as a URL, is an exact binding.) This is a rule on the bytes as written, with no parsing and no normalisation, so
 * every implementation decides alike. It never gives a keeper a URL a parser would place at another
 * host: the authority of an `https:` URL ends at the first `/`, `?` or `#`, so a URL that continues
 * the origin with anything else, more of a host name, a port, an `@` or a `\`, is not at it. Such a
 * URL falls to the rules below, which hand it only to the issuer that chose to write it in its own
 * credential. A host written in another case is likewise not at the origin.
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
  assertStatusListIssuers(statusListIssuers);
  const bound = Object.entries(statusListIssuers ?? {});
  for (const [did, bindings] of bound) {
    if (bindings.includes(statusListCredential)) return { did, why: 'configured-url' };
  }
  for (const [did, bindings] of bound) {
    if (bindings.some((binding) => ORIGIN.test(binding) && isAtOrigin(statusListCredential, binding))) {
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
