/**
 * The mark that a pinned root's own status-list URL is that root's word. A chain's first credential
 * names the URL its own status entry is at, and the keeper rule (`./statuslist-keeper`) lets the
 * root's list there speak for each hop that names it. Until the root credential's proof has
 * verified, that URL is only what whoever presented the chain wrote, so a read of it is held to the
 * private-network rule as any URL a presenter names is. Once the proof has verified, the root the
 * verifier pins has named it, so the read is the operator's own, as a URL `statusListIssuers` binds
 * is, and its host may be private.
 *
 * Only the library marks a context, and only after that proof: `evaluateDelegationChain` once
 * `verifyHopProof` has passed for every hop, `verifyRequestDelegation` once its hop proofs have, and
 * `verifyCard` once the accountability check has verified the Card's responsible party as that root,
 * each only for a root the operator pins ({@link pinnedRootOf}).
 * A mark is an object this module makes and records with the root and the URL it was made for, so
 * no data a presenter sends, nor a context a caller writes, carries one a reader honours: a reader
 * asks this module whether the mark it was given is one it made, for the context's own root and
 * URL. The exemption is decided hop by hop: only a request to that very URL is the operator's, and
 * a redirect from it to any other URL is held as one a presenter named.
 */

import { operatorNamedRequests } from './operator-named.js';
import { statusListIssuersBind, type StatusCheckContext, type StatusListIssuers } from './statuslist-keeper.js';

declare const VERIFIED_ROOT: unique symbol;

/** The library's mark that the proof of the credential a context's pinned root signed has verified. */
export interface VerifiedRootMark {
  readonly [VERIFIED_ROOT]: true;
}

/** The root and the status-list URL each mark was made for. */
const made = new WeakMap<object, { readonly did: string; readonly list: string }>();

/** The members of a context, or of a chain's revocation entry, that name its pinned root. */
type RootNaming = Partial<Pick<StatusCheckContext, 'trustedRootIssuer' | 'trustedRootStatusList' | 'trustedRootVerified'>>;

/**
 * `entries`, each that names a pinned root and the URL the root's own credential names marked as
 * that root's verified word. Call it only once the proof of the credential that root signed has
 * verified.
 */
export function withVerifiedRoot<T extends RootNaming>(entries: readonly T[]): T[] {
  const marks = new Map<string, VerifiedRootMark>();
  return entries.map((entry) => {
    const { trustedRootIssuer: did, trustedRootStatusList: list } = entry;
    if (did === undefined || list === undefined) return entry;
    const key = JSON.stringify([did, list]);
    let mark = marks.get(key);
    if (mark === undefined) {
      mark = Object.freeze(Object.create(null) as object) as VerifiedRootMark;
      made.set(mark, { did, list });
      marks.set(key, mark);
    }
    return { ...entry, trustedRootVerified: mark };
  });
}

/** The operator's pins of a chain's root: the `resourceOwner` and the `trustedRootIssuers` a verifier is given. */
export interface RootPins {
  readonly resourceOwner?: string;
  readonly trustedRootIssuers?: readonly string[];
}

/**
 * `issuer`, the root issuer of a chain, when the operator pins it, as the `resourceOwner` or one of
 * the `trustedRootIssuers` it gives a verifier, and `undefined` otherwise. Only a pinned root's own
 * list is marked as its word ({@link withVerifiedRoot}), on every path that marks one: a root the
 * verifier accepts without naming it, under `allowAnyRootIssuer` or on a Card's accountability
 * verdict alone, may be the presenter, and so may have chosen the URL its credential names.
 */
export function pinnedRootOf(issuer: string | undefined, pins: RootPins): string | undefined {
  if (issuer === undefined) return undefined;
  return issuer === pins.resourceOwner || pins.trustedRootIssuers?.includes(issuer) === true ? issuer : undefined;
}

/** `context` marked as {@link withVerifiedRoot} marks an entry. */
export function verifiedRootContext<T extends RootNaming>(context: T): T {
  return withVerifiedRoot([context])[0] ?? context;
}

/**
 * Which requests of the read of the status list at `url` are the operator's own, request by request,
 * the first and each redirect (`./operator-named`): one for a URL `statusListIssuers` binds, and one
 * for the URL a pinned root's own credential names, when that URL is https and `context` carries a
 * mark this module made for that root and that URL. Any other request is one a presenter named.
 * `undefined` when no request can be the operator's, so the read is held as a presenter's whole.
 *
 * A read takes http only at a URL its operator named as written, and the operator writes only what
 * `statusListIssuers` binds: the root's credential, not the operator, names the root's own list, so
 * that list is read over https alone, as a list a presenter names is.
 */
export function operatorNamedHops(
  url: string,
  context: StatusCheckContext | undefined,
  statusListIssuers?: StatusListIssuers,
): ((request: string) => boolean) | undefined {
  const rootList = httpsOnly(verifiedRootList(context));
  if (rootList === undefined && statusListIssuers === undefined) return undefined;
  return operatorNamedRequests(
    url,
    (named) => named === rootList || (statusListIssuers !== undefined && statusListIssuersBind(named, statusListIssuers)),
  );
}

/** `url` when it is an https URL, and `undefined` otherwise. */
function httpsOnly(url: string | undefined): string | undefined {
  if (url === undefined) return undefined;
  try {
    return new URL(url).protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

/** The URL a pinned root's own credential names, when `context` carries this module's mark for that root and that URL. */
function verifiedRootList(context: StatusCheckContext | undefined): string | undefined {
  const mark: unknown = context?.trustedRootVerified;
  if (typeof mark !== 'object' || mark === null) return undefined;
  const root = made.get(mark);
  if (root === undefined || root.did !== context?.trustedRootIssuer || root.list !== context.trustedRootStatusList) return undefined;
  return root.list;
}
