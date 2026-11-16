/**
 * KYA-OS Entity Card: the revocation check `verifyCard` runs on a Card's own status entry, and how
 * a revoked Card demotes its level. Every status that is not proven clear reads as revoked, with
 * the code of why: the code the checker gave, `delegation_revoked` when it gave none, and
 * `deadline_exceeded` or `status_unavailable` for a checker that did not answer in time, gave an
 * answer that is not a status, or threw.
 */

import { CHECKER_REASON_LENGTH, type BitstringRevocationChecker } from './revocation.js';
import type { EntityCard } from './schema.js';
import type { CapabilityCheckResult } from './verify.js';
import type { RefusalCoding } from '../delegation/vc-verifier.types.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { readRevocationAnswer } from '../utils/revocation-answer.js';
import { coded, refusalCodeOf, type Coded } from '../utils/refusal.js';
import type { StatusCheckContext } from '../utils/statuslist-keeper.js';
import type { RefusalCode } from '../refusal-codes.js';
import { checkWithinDeadline } from './revocation-deadline.js';

/**
 * The Card's revocation as `verifyCard` reports it: whether it is revoked and fresh, why when its
 * checker said why or its answer could not be read, and, when revoked, the code of why.
 */
export type CardRevocation = { revoked: boolean; fresh: boolean; reason?: string } & RefusalCoding;

/** Verdict for the card's own credential status entry (`card.revocation`). */
export type CardRevocationVerdict =
  /** No `statusListChecker` was supplied, or the card declares no `revocation`. */
  | { checked: false; revoked: false; fresh: true }
  | { checked: true; revoked: false; fresh: boolean }
  /** Why the Card reads as revoked, when its checker said why or its answer could not be read, and the code of why. */
  | ({ checked: true; revoked: true; fresh: boolean; reason?: string } & Coded);

/** The part of a status check's context that names the root of a Card's chain. */
type CardRoot = Partial<Pick<StatusCheckContext, 'trustedRootIssuer' | 'trustedRootStatusList'>>;

/** What `verifyCard` found of a Card's accountability, as far as the checker is told of it. */
interface VerifiedParty {
  verified: boolean;
  responsibleParty?: string;
  rootStatusList?: string;
}

/**
 * The Card's responsible party as the checker is told of it, once the accountability check has
 * verified it and never before: the root of the Card's chain, with the list URL the verdict
 * reported that root's own credential names, when it reported one.
 */
export function verifiedRoot(accountability: VerifiedParty | undefined): CardRoot {
  if (!accountability?.verified || accountability.responsibleParty === undefined) return {};
  const { responsibleParty, rootStatusList } = accountability;
  return { trustedRootIssuer: responsibleParty, ...(rootStatusList === undefined ? {} : { trustedRootStatusList: rootStatusList }) };
}

/** The Card read as revoked and not fresh, with `code`, and `reason` when there is one. */
function unproven(code: RefusalCode, reason?: string): CardRevocationVerdict {
  return { checked: true, revoked: true, fresh: false, ...(reason === undefined ? {} : { reason }), ...coded(code) };
}

/**
 * Live-check `card.revocation` via the injected seam; fail-closed (unreachable ⇒ revoked). The Card's
 * `id` is named as the issuer its status list is held to, and `root` names a verified
 * `responsibleParty` as the root of the Card's delegation chain ({@link verifiedRoot}).
 */
export async function checkCardRevocation(
  card: EntityCard,
  checker: BitstringRevocationChecker | undefined,
  root: CardRoot,
  timeoutMs: number,
): Promise<CardRevocationVerdict> {
  if (!checker || !card.revocation) return { checked: false, revoked: false, fresh: true };
  try {
    const asked = await checkWithinDeadline(checker, card.revocation, { credentialIssuer: card.id, ...root }, timeoutMs);
    if ('expired' in asked) return unproven('deadline_exceeded', asked.expired);
    const status = readRevocationAnswer(asked.answer);
    if (status.revoked === undefined) {
      return unproven('status_unavailable', `the Card's revocation status could not be read: ${status.unreadable}`);
    }
    if (!status.revoked) return { checked: true, revoked: false, fresh: status.fresh };
    const given = status.reason ? { reason: sanitizeForMessage(status.reason, CHECKER_REASON_LENGTH) } : {};
    return { checked: true, revoked: true, fresh: status.fresh, ...given, ...coded(status.code ?? 'delegation_revoked') };
  } catch (error) {
    return unproven(refusalCodeOf(error, 'status_unavailable'));
  }
}

/** The revocation verdict as the result reports it, with its `reason`, `code` and `transient` only when it has them. */
export function reportedRevocation(verdict: CardRevocationVerdict): CardRevocation {
  if (!verdict.revoked) return { revoked: verdict.revoked, fresh: verdict.fresh };
  const { revoked, fresh, reason, code, transient } = verdict;
  return { revoked, fresh, ...(reason === undefined ? {} : { reason }), code, transient };
}

/**
 * A REVOKED card credential voids its attested trust: every otherwise-verified capability drops to
 * unverified so the floor collapses to L1 (revocation demotes L3→L2→L1). A clean-but-stale list
 * leaves `check` untouched: it only trims `revocationFresh` (L3→L2). No-op when not revoked.
 */
export function demoteOnRevocation(check: CapabilityCheckResult, revoked: boolean): CapabilityCheckResult {
  if (!revoked) return check;
  return { verified: [], unverified: [...check.verified, ...check.unverified] };
}
