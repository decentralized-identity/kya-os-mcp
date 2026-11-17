/**
 * The cascading walk of a delegation chain's revocation status, root to leaf, over a
 * {@link BitstringRevocationChecker}: the first hop that is revoked, or whose status could not be
 * proven clear, refuses the chain, with the code of why. Re-exported from `./revocation.ts`.
 */

import type { RefusalCode } from '../refusal-codes.js';
import { dependencyTimeout } from '../utils/deadline.js';
import { describeValue } from '../utils/describe-value.js';
import { isRecord } from '../utils/guards.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { coded, refusalCodeOf, type Coded } from '../utils/refusal.js';
import { WRAPPED_REASON_LENGTH, readRevocationAnswer } from '../utils/revocation-answer.js';
import { thrownReason } from '../utils/thrown-words.js';
import type { StatusCheckContext } from '../utils/statuslist-acceptance.js';
import { checkWithinDeadline } from './revocation-deadline.js';
import type { BitstringRevocationChecker, RevocationStatusEntry } from './revocation.js';
import type { RefusalCoding } from '../delegation/vc-verifier.types.js';

/** Result of a cascading root→leaf chain walk, with the code of the hop that refused it when it is refused. */
export interface RevocationChainResult extends RefusalCoding {
  /** True iff EVERY hop is non-revoked (fail-closed: any revoked/unresolvable hop ⇒ false). */
  ok: boolean;
  /** True iff EVERY checked hop was read from a live, in-window status list. */
  fresh: boolean;
  /** Fail-closed reasons (empty ⇒ ok). */
  reasons: string[];
}

/**
 * One hop for {@link evaluateRevocationChain}: a status entry, with the `statusPurpose` its hop
 * states, and the context the checker holds the hop's status list to: the issuer of the credential
 * it belongs to and, when the verifier pins it, the chain's root issuer.
 */
export interface RevocationChainEntry extends Omit<StatusCheckContext, 'credentialIssuer'> {
  entry: RevocationStatusEntry;
  /**
   * The credential's issuer DID, or `undefined` when its `issuer` names none: the entry is then
   * checked with no context.
   */
  credentialIssuer: string | undefined;
  /**
   * The hop's position in its chain, the root being 0, which a refusal names it by. Omitted, the
   * hop is named by its place among the entries the walk is given.
   */
  position?: number;
}

/**
 * Walk a delegation/capability chain root→leaf and fail-close on the first revoked or
 * unresolvable hop (cascading: a revoked ancestor invalidates the subtree, so the walk
 * short-circuits). `fresh` is the AND of every checked hop's liveness.
 *
 * An empty set of status entries is trivially `ok` (nothing is revoked, an offline/L2-acceptable
 * verdict) but is NOT `fresh`: freshness is a LIVE-check signal, and zero checks obtained no live
 * signal. An L3 liveness gate that requires `fresh` therefore cannot be satisfied by a chain that
 * simply omits all `credentialStatus` entries; it must consult at least one live status list.
 *
 * Pass each hop as a {@link RevocationChainEntry} (`revocationEntriesOf` builds them from a
 * delegation chain) so the checker can hold the hop's list to the hop's issuer and the chain's pinned
 * root. A bare entry, like a hop that names no issuer, is checked with no context, which a checker
 * given `verifyStatusList` refuses (fail-closed). Any other item is checked as a bare entry, so it is
 * refused too, and the walk never throws on it.
 *
 * A checker's answer is read as {@link BitstringRevocationChecker} says: a hop passes only on a
 * literal `revoked: false`, and an answer that is neither that nor a literal `revoked: true` refuses
 * the hop with a reason that says what could not be read. No answer makes the walk throw; a checker
 * that throws or rejects still does, and the callers in this package catch that and fail closed,
 * `evaluateDelegationChain` with {@link checkerThrew}.
 *
 * A revoked hop's refusal ends with the `reason` its checker gave, when it gave one, after a colon:
 * at most its first {@link WRAPPED_REASON_LENGTH} UTF-16 code units, so the reason of a library
 * checker that a checker of the host's wrapped in words of its own still ends whole, with every
 * control character replaced, as `sanitizeForMessage` leaves text.
 *
 * The reason for a refused hop names the hop by its `position` in the chain, or by its place among
 * `entries` when it has none, and names the list and the index its entry states. Whoever issued the
 * hop wrote both, so the reason quotes each as `describeValue` does, at most its first 64
 * characters, and names one that is not a string by its type alone, never converting it.
 *
 * A refused walk carries the code of why: the code the checker's answer names, as the library's
 * checker names one for every status it cannot prove clear, else `delegation_revoked` for a hop
 * revoked; `status_unavailable` for an answer that cannot be read; and `deadline_exceeded` for a
 * checker that has not answered in time.
 *
 * Each answer of the checker gets `options.dependencyTimeoutMs`, 5,000 ms by default, and a hop
 * whose checker has not answered by then is unresolvable. Rejects with a `TypeError` for a value
 * that is not a number of milliseconds greater than 0 and at most 2,147,483,647.
 */
export async function evaluateRevocationChain(
  entries: readonly (RevocationStatusEntry | RevocationChainEntry)[],
  check: BitstringRevocationChecker,
  options: { dependencyTimeoutMs?: number } = {},
): Promise<RevocationChainResult> {
  return walkRevocationChain(entries, check, options);
}

/**
 * {@link evaluateRevocationChain}, with a refusal that cannot be built without its code: the library's
 * own verifiers walk a chain through it, so the code of a refused walk is typed as always present.
 */
export async function walkRevocationChain(
  entries: readonly (RevocationStatusEntry | RevocationChainEntry)[],
  check: BitstringRevocationChecker,
  options: { dependencyTimeoutMs?: number },
): Promise<RevocationChainWalk> {
  const timeoutMs = dependencyTimeout(options.dependencyTimeoutMs);
  let fresh = entries.length > 0; // no entries ⇒ no live signal ⇒ not fresh (fail-closed for L3)
  for (const [index, item] of entries.entries()) {
    let entry: RevocationStatusEntry | undefined;
    let context: StatusCheckContext | undefined;
    let hop = index;
    if (isChainEntry(item)) {
      const { entry: hopEntry, credentialIssuer, position, ...pinned } = item;
      entry = hopEntry;
      if (isPosition(position)) hop = position;
      context = credentialIssuer === undefined ? undefined : { ...pinned, credentialIssuer };
    } else {
      entry = item;
    }
    const asked = await checkWithinDeadline(check, entry, context, timeoutMs);
    if ('expired' in asked) {
      return refusedHop('deadline_exceeded', `${hopName(hop, entry)} is unresolvable: ${asked.expired}`);
    }
    const status = readRevocationAnswer(asked.answer);
    if (status.revoked === undefined) {
      return refusedHop('status_unavailable', `${hopName(hop, entry)} has a status that could not be read: ${status.unreadable}`);
    }
    fresh = fresh && status.fresh;
    if (status.revoked) {
      // The checker's own code says why it could not prove the hop clear; with none, its bit is set.
      return refusedHop(
        status.code ?? 'delegation_revoked',
        [
          `${hopName(hop, entry)} ` +
          'is revoked or unresolvable \u2014 fail-closed, subtree invalidated',
          ...(status.reason ? [sanitizeForMessage(status.reason, WRAPPED_REASON_LENGTH)] : []),
        ].join(': '),
      );
    }
  }
  return { ok: true, fresh, reasons: [] };
}

/** What the walk comes to: every hop passed, or one was refused with a code. */
export type RevocationChainWalk =
  | { readonly ok: true; readonly fresh: boolean; readonly reasons: string[] }
  | (Coded & { readonly ok: false; readonly fresh: false; readonly reasons: string[] });

/**
 * The walk's refusal when its checker threw or rejected with `error`: the code of a `RefusalError`
 * it threw, `deadline_exceeded` for a deadline that passed, else `status_unavailable`. The reason
 * holds the error's words only where they may reach whoever presented the chain
 * (`utils/thrown-words.ts`); any other words, such as a transport's, go to the operator's log.
 */
export function checkerThrew(error: unknown): RevocationChainWalk {
  const reason = thrownReason(error, {
    withheld: 'revocation checker threw: status unprovable, fail-closed',
    shown: (words) => `revocation checker threw: ${words}`,
    tag: '[kya-os]',
  });
  return refusedHop(refusalCodeOf(error, 'status_unavailable'), reason);
}

/** The walk's refusal at a hop, for `reason`, with `code`. */
function refusedHop(code: RefusalCode, reason: string): RevocationChainWalk {
  return { ok: false, fresh: false, reasons: [reason], ...coded(code) };
}

/** How a refusal names hop `hop`: by its position, and by the list and the index its entry states. */
function hopName(hop: number, entry: RevocationStatusEntry | undefined): string {
  return (
    `revocation: hop ${hop} (list ${describeValue(entry?.statusListCredential)}, ` +
    `index ${describeValue(entry?.statusListIndex)})`
  );
}

/** A hop paired with its context, as opposed to a bare status entry (or a malformed item). */
function isChainEntry(item: unknown): item is RevocationChainEntry {
  return isRecord(item) && isRecord(item.entry);
}

/** Whether a hop's stated `position` is one a refusal can name it by: a non-negative safe integer. */
function isPosition(position: unknown): position is number {
  return Number.isSafeInteger(position) && (position as number) >= 0;
}
