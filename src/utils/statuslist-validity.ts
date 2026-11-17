/**
 * The status-list VALIDITY rule: whether a status list may be read now, by the window it states.
 * W3C Bitstring Status List v1.0 §2.2 gives a list a `validFrom`, "The earliest point in time at which
 * the status list is valid.", and a `validUntil`, "The latest point in time at which the status list
 * is valid."; a list of the Verifiable Credentials Data Model 1.1 states the same window as
 * `issuanceDate` and `expirationDate`. The VC 2.0 member decides when it is present, `null` included,
 * and its VC 1.1 predecessor only when it is absent.
 *
 * A list's proof does not tell versions of the list apart: an earlier version, signed before a
 * credential was revoked, still verifies, and its window is how its issuer bounds how long it may be
 * served. So every status-list reader in the library refuses a list outside the window it states, as
 * a status that could not be read, `status_unavailable`, which is transient: the issuer republishes
 * and the next read succeeds. A list that states no bound is read as before. A bound the list states
 * that is not a date leaves the window unknown, and is refused the same way. The bounds are
 * inclusive.
 *
 * The rule is pure and checks no proof. A reader asks it once the list's proof has verified, where it
 * verifies one, so the time a refusal quotes is the issuer's, read from the list itself and never
 * from the network, and a reader that keeps lists asks it again on every read of one it kept.
 */

import { describeValue } from './describe-value.js';
import { isRecord } from './guards.js';
import { RefusalError } from './refusal.js';
import type { StatusListVerdict } from './statuslist-acceptance.js';

/** One bound of a list's window: the member that states it, and the time it states, when it is a date. */
interface Bound {
  member: string;
  stated: unknown;
  ms: number | undefined;
}

/**
 * Whether `list`, a status-list credential, may be read at `nowMs`, epoch milliseconds, by the window
 * it states and, when it may not, why: `status list expired at "<time>" (its validUntil)`, `status
 * list is not valid until "<time>" (its validFrom)`, or `status list states a validUntil (...) that is
 * not a date`, each naming the member it went by and quoting its value as `describeValue` does.
 * A value that is not an object states no bound.
 */
export function acceptStatusListValidity(list: unknown, nowMs: number): StatusListVerdict {
  const reason = outsideWindow(isRecord(list) ? list : {}, nowMs);
  return reason === undefined ? { valid: true } : { valid: false, reason };
}

/**
 * Throw a {@link RefusalError} of code `status_unavailable`, with the reason, unless `list` may be read
 * at `nowMs` ({@link acceptStatusListValidity}). The one place the library's readers decide the code.
 */
export function assertStatusListValidity(list: unknown, nowMs: number): void {
  const verdict = acceptStatusListValidity(list, nowMs);
  if (!verdict.valid) throw new RefusalError('status_unavailable', verdict.reason);
}

/** Why a list stating `fields` may not be read at `nowMs`, or `undefined` when it may. */
function outsideWindow(fields: Record<string, unknown>, nowMs: number): string | undefined {
  const until = boundOf(fields, 'validUntil', 'expirationDate');
  const from = boundOf(fields, 'validFrom', 'issuanceDate');
  const unknown = [until, from].find((bound) => bound !== undefined && bound.ms === undefined);
  if (unknown) {
    return `status list states ${article(unknown.member)} ${unknown.member} (${describeValue(unknown.stated)}) that is not a date`;
  }
  if (until?.ms !== undefined && until.ms < nowMs) {
    return `status list expired at ${describeValue(until.stated)} (its ${until.member})`;
  }
  if (from?.ms !== undefined && from.ms > nowMs) {
    return `status list is not valid until ${describeValue(from.stated)} (its ${from.member})`;
  }
  return undefined;
}

/** The bound `current` states, or else `legacy`, or `undefined` when the list states neither. */
function boundOf(fields: Record<string, unknown>, current: string, legacy: string): Bound | undefined {
  const member = fields[current] !== undefined ? current : fields[legacy] !== undefined ? legacy : undefined;
  if (member === undefined) return undefined;
  const stated = fields[member];
  const ms = typeof stated === 'string' ? Date.parse(stated) : Number.NaN;
  return { member, stated, ms: Number.isNaN(ms) ? undefined : ms };
}

/** The indefinite article before `word`. */
function article(word: string): string {
  return /^[aeiou]/.test(word) ? 'an' : 'a';
}
