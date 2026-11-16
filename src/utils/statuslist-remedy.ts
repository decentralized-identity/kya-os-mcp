/**
 * How a reader that takes `statusListIssuers` ends the keeper rule's refusal of a list another DID
 * signed: with the configuration that would accept the list, phrased as a condition, since anyone
 * can sign a list and only the operator knows whether that DID speaks for the URL.
 *
 * W3C Bitstring Status List v1.0 lets a list's issuer differ from the credential's and leaves
 * trusting it to the verifier; `statusListIssuers` is that decision. So the remedy names the list's
 * issuer and what to bind to it: the canonical form of the list URL's origin when no binding names
 * the URL's keeper, so that the DID keeps every list at that origin, and the list's own URL when the
 * configuration binds the URL or its origin to another issuer, moving that issuer's binding of the
 * URL itself when it has one. The remedy is checked before it is offered: the configuration it
 * prints is one `assertStatusListIssuers` takes and under which the keeper rule gives the URL to the
 * list's issuer, and where no configuration would, as for a URL whose host has an upper-case
 * letter, there is no remedy to offer. Where it cannot be printed whole and exactly, within the
 * length a reason may have, the refusal says where to name the list's issuer instead.
 */

import { isRecord, issuerOf } from './guards.js';
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

/** A DID as `statusListIssuers` names an issuer, written so that a refusal prints it whole and exactly. */
const PRINTABLE_DID = /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/;
/** A URL a refusal prints whole and exactly: visible ASCII, with nothing JSON would escape. */
const PRINTABLE_URL = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

/**
 * `reason`, the keeper rule's refusal of `refused.list`, ending with the `statusListIssuers`
 * configuration that would accept the list, or with where to name its issuer when that does not fit
 * in `maxLength` UTF-16 code units or cannot be printed exactly. A list whose `issuer` is no DID, or
 * the keeper itself, a list a resolver holds to the one issuer it is configured with, and a list at
 * a URL no binding can name gain nothing: no configuration accepts them.
 */
export function withStatusListIssuersRemedy(reason: string, refused: KeeperRefusal, maxLength: number): string {
  const signer = issuerOf(isRecord(refused.list) ? refused.list.issuer : undefined);
  const { keeper } = refused;
  if (!signer?.startsWith('did:') || signer === keeper.did || keeper.why === 'resolver-issuer') return reason;
  const exact = exactRemedy(signer, refused);
  if (exact === NONE) return reason;
  if (exact !== undefined && reason.length + exact.length <= maxLength) return reason + exact;
  return reason + generalRemedy(keeper);
}

/** What {@link exactRemedy} answers when no configuration would give the URL to the list's issuer. */
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
function exactRemedy(signer: string, refused: KeeperRefusal): string | undefined | typeof NONE {
  const { statusListCredential: url, keeper } = refused;
  const binding = (isUnbound(keeper) ? originBindingOf(url) : undefined) ?? url;
  if (!acceptsSigner(signer, binding, refused)) return NONE;
  if (!PRINTABLE_DID.test(signer) || !PRINTABLE_URL.test(binding)) return undefined;
  const configuration = `{ ${JSON.stringify(signer)}: [${JSON.stringify(binding)}] }`;
  if (isUnbound(keeper)) {
    return `; if ${JSON.stringify(signer)} signs this issuer's lists, name it in statusListIssuers: ${configuration}`;
  }
  const remedy = keeper.why === 'configured-url' ? "move the URL's binding to it" : 'name it';
  return `; if ${JSON.stringify(signer)} signs the list at this URL, ${remedy} in statusListIssuers: ${configuration}`;
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
  return isUnbound(keeper)
    ? "; if the list's issuer signs this issuer's lists, name it in statusListIssuers with this list's https origin or URL"
    : "; if the list's issuer signs the list at this URL, bind the URL to it in statusListIssuers";
}
