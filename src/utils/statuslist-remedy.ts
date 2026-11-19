/**
 * How a reader that takes `statusListIssuers` ends the keeper rule's refusal of a list another DID
 * signed: with the configuration that would accept the list, phrased as a condition, since anyone
 * can sign a list and only the operator knows whether that DID speaks for the URL.
 *
 * W3C Bitstring Status List v1.0 lets a list's issuer differ from the credential's and leaves
 * trusting it to the verifier; `statusListIssuers` is that decision. So the remedy names the list's
 * issuer and what to bind to it: the list's own URL, moving another issuer's binding of the URL
 * itself when the configuration has one. It never offers the URL's origin, which would hand the
 * list's issuer every list at that origin on the word of one list it signed; an operator who means
 * that writes the origin knowingly. The remedy is checked before it is offered: the configuration
 * it prints is one `assertStatusListIssuers` takes and under which the keeper rule gives the URL to
 * the list's issuer, and where no configuration would, as for a URL that ends in `/`, which no
 * binding may be, there is no remedy to offer. Where it cannot be printed whole and exactly,
 * within the length a reason may have, the refusal says where to name the list's issuer instead,
 * and where that does not fit either, it offers none. The words of a remedy are `./remedy-text`'s,
 * which also keeps a reason cut for length from ending inside one. A verdict about a list reaches
 * the presenter only once the list's proof verifies, and the keeper rule is asked before it, so the
 * refusal and its remedy go to the operator's log (`./thrown-words.ts`).
 */

import { isRecord, issuerOf } from './guards.js';
import { exactRemedy, GENERAL_REMEDY, PRINTABLE_DID, PRINTABLE_URL } from './remedy-text.js';
import {
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
  const fitting = [exact, GENERAL_REMEDY].find((remedy) => remedy !== undefined && reason.length + remedy.length <= maxLength);
  return fitting === undefined ? reason : reason + fitting;
}

/** What {@link configurationRemedy} answers when no configuration would give the URL to the list's issuer. */
const NONE = Symbol('no remedy');

/**
 * The remedy that prints the configuration that accepts the list `signer` signed; `undefined` when a
 * value it would print cannot be printed exactly; or {@link NONE} when that configuration, checked
 * as a reader checks it, would not give the URL to `signer`, so that none would.
 */
function configurationRemedy(signer: string, refused: KeeperRefusal): string | undefined | typeof NONE {
  const { statusListCredential: url, keeper } = refused;
  if (!acceptsSigner(signer, refused)) return NONE;
  if (!PRINTABLE_DID.test(signer) || !PRINTABLE_URL.test(url)) return undefined;
  return exactRemedy(signer, url, keeper.why === 'configured-url' ? 'move' : 'name');
}

/**
 * Whether binding the list's URL to `signer` gives it the URL: the reader's configuration, with
 * the keeper's binding of the URL itself moved to `signer` when there is one, is one
 * `assertStatusListIssuers` takes, and the keeper rule then names `signer`.
 */
function acceptsSigner(signer: string, refused: KeeperRefusal): boolean {
  const { statusListCredential: url, keeper } = refused;
  const configured = Object.entries(refused.statusListIssuers ?? {}).map(([did, bindings]): [string, string[]] => [
    did,
    keeper.why === 'configured-url' && did === keeper.did ? bindings.filter((bound) => bound !== url) : [...bindings],
  ]);
  const own = configured.find(([did]) => did === signer);
  if (own === undefined) configured.push([signer, [url]]);
  else own[1].push(url);
  try {
    return statusListKeeperFor(url, refused.context, Object.fromEntries(configured)).did === signer;
  } catch {
    return false;
  }
}
