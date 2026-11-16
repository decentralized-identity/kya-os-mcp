/**
 * How a reader that takes `statusListIssuers` ends the keeper rule's refusal of a list another DID
 * signed: with the configuration that would accept the list, phrased as a condition, since anyone
 * can sign a list and only the operator knows whether that DID speaks for the URL.
 *
 * W3C Bitstring Status List v1.0 lets a list's issuer differ from the credential's and leaves
 * trusting it to the verifier; `statusListIssuers` is that decision. So the remedy names the list's
 * issuer and what to bind to it: the list URL's origin, in SPEC.md §6.6's form with nothing after
 * it, when no binding names the URL's keeper, so that the DID keeps every list at that origin; and
 * the list's own URL when no origin binding holds it, as for an `http:` URL or a host with an
 * upper-case letter, or when the configuration binds the URL or its origin to another issuer,
 * moving that issuer's binding of the URL itself when it has one. The remedy is checked before it
 * is offered: the configuration it prints is one `assertStatusListIssuers` takes and under which
 * the keeper rule gives the URL to the list's issuer, and where no configuration would, as for a
 * URL that ends in `/` and could be bound only as itself, which no binding may be, there is no
 * remedy to offer. Where it cannot be printed whole and exactly, within the length a reason may
 * have, the refusal says where to name the list's issuer instead, and where that does not fit
 * either, it offers none. The words of a remedy are `./remedy-text`'s, which also keeps a reason cut
 * for length from ending inside one.
 */

import { isRecord, issuerOf } from './guards.js';
import {
  BOUND_GENERAL_REMEDY,
  exactRemedy,
  type ExactRemedyKind,
  PRINTABLE_DID,
  PRINTABLE_URL,
  UNBOUND_GENERAL_REMEDY,
} from './remedy-text.js';
import {
  originBindingOf,
  statusListKeeperFor,
  type StatusCheckContext,
  type StatusListIssuers,
  type StatusListKeeper,
} from './statuslist-keeper.js';

/** A list the keeper rule refused, and what decided its keeper. */
export interface KeeperRefusal {
  /** The fetched status-list credential, whose `issuer` is not the keeper. */
  readonly list: unknown;
  /** The URL the status entry names, which the list was fetched from. */
  readonly statusListCredential: string;
  /** The credential the list was held to. */
  readonly context: StatusCheckContext;
  /** The reader's configuration, if it has one. */
  readonly statusListIssuers: StatusListIssuers | undefined;
  /** The one issuer whose list is read at the URL. */
  readonly keeper: StatusListKeeper;
}

/**
 * `reason`, the keeper rule's refusal of `refused.list`, ending with the `statusListIssuers`
 * configuration that would accept the list, or with where to name its issuer when that does not fit
 * in `maxLength` UTF-16 code units or cannot be printed exactly, or with neither when that does not
 * fit either, so that the reason never needs to be cut inside a remedy. A list whose `issuer` is no
 * DID, or the keeper itself, a list a resolver holds to the one issuer it is configured with, and a
 * list at a URL no binding can name gain nothing: no configuration accepts them.
 */
export function withStatusListIssuersRemedy(reason: string, refused: KeeperRefusal, maxLength: number): string {
  const signer = issuerOf(isRecord(refused.list) ? refused.list.issuer : undefined);
  const { keeper } = refused;
  if (!signer?.startsWith('did:') || signer === keeper.did || keeper.why === 'resolver-issuer') return reason;
  const exact = configurationRemedy(signer, refused);
  if (exact === NONE) return reason;
  const fitting = [exact, generalRemedy(keeper)].find((remedy) => remedy !== undefined && reason.length + remedy.length <= maxLength);
  return fitting === undefined ? reason : reason + fitting;
}

/** What {@link configurationRemedy} answers when no configuration would give the URL to the list's issuer. */
const NONE = Symbol('no remedy');

/** Whether no binding names the keeper: it keeps the URL as the credential's issuer or as the pinned root. */
function isUnbound(keeper: StatusListKeeper): boolean {
  return keeper.why === 'credential-issuer' || keeper.why === 'root-credential';
}

/**
 * The remedy that prints the configuration that accepts the list `signer` signed; `undefined` when a
 * value it would print cannot be printed exactly; or {@link NONE} when that configuration, checked
 * as a reader checks it, would not give the URL to `signer`, so that none would.
 */
function configurationRemedy(signer: string, refused: KeeperRefusal): string | undefined | typeof NONE {
  const { statusListCredential: url, keeper } = refused;
  const binding = (isUnbound(keeper) ? originBindingOf(url) : undefined) ?? url;
  if (!acceptsSigner(signer, binding, refused)) return NONE;
  if (!PRINTABLE_DID.test(signer) || !PRINTABLE_URL.test(binding)) return undefined;
  return exactRemedy(signer, binding, remedyKind(keeper));
}

/** What the remedy asks of the operator, from why `keeper` keeps the URL. */
function remedyKind(keeper: StatusListKeeper): ExactRemedyKind {
  if (isUnbound(keeper)) return 'unbound';
  return keeper.why === 'configured-url' ? 'moved' : 'bound';
}

/**
 * Whether binding `binding` to `signer` gives it the URL: the reader's configuration, with the
 * keeper's binding of the URL itself moved to `signer` when there is one, is one
 * `assertStatusListIssuers` takes, and the keeper rule then names `signer`.
 */
function acceptsSigner(signer: string, binding: string, refused: KeeperRefusal): boolean {
  const { statusListCredential: url, keeper } = refused;
  const configured = Object.entries(refused.statusListIssuers ?? {}).map(([did, bindings]): [string, string[]] => [
    did,
    keeper.why === 'configured-url' && did === keeper.did ? bindings.filter((bound) => bound !== url) : [...bindings],
  ]);
  const own = configured.find(([did]) => did === signer);
  if (own === undefined) configured.push([signer, [binding]]);
  else own[1].push(binding);
  try {
    return statusListKeeperFor(url, refused.context, Object.fromEntries(configured)).did === signer;
  } catch {
    return false;
  }
}

/** Where to name the list's issuer, for a refusal that cannot print the configuration whole. */
function generalRemedy(keeper: StatusListKeeper): string {
  return isUnbound(keeper) ? UNBOUND_GENERAL_REMEDY : BOUND_GENERAL_REMEDY;
}
