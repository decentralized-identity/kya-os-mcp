/**
 * The claims of an Entity Card a verifier the host supplies decides: its capabilities, its
 * accountability edge, its attestations and the live per-request proof. Each verifier is asked under
 * the dependency deadline, and its answer is read as data, not trusted: only a literal `true`
 * verifies, an answer that is malformed or throws when read is a refusal with its reason, and one
 * that has not come in time is a refusal coded `deadline_exceeded`. Nothing a verifier answers
 * throws out of `verifyCard`, which weighs these verdicts into `ok` and the level (`./verify`); the
 * revocation claim is read in `./verify-revocation`.
 */

import { capabilityNames, type EntityCard } from './schema.js';
import type { CapabilityCheckResult, VerifyCardDeps, VerifyCardResult } from './verify.js';
import type { ProofAssurance, ProofVerifyResult } from './proof/index.js';
import { describeValue } from '../utils/describe-value.js';
import { answerWithinDeadline, DeadlineExceededError } from '../utils/deadline.js';
import { coded, type Coded } from '../utils/refusal.js';

/** Run the capability seam (or floor everything to unverified when no seam is injected). */
export async function checkCapabilities(
  card: EntityCard,
  deps: VerifyCardDeps,
  trustedIssuers: readonly string[],
  timeoutMs: number,
): Promise<CapabilityCheckResult> {
  const capabilities = card.capabilities ?? [];
  const verifier = deps.capabilityVerifier;
  const unverified: CapabilityCheckResult = { verified: [], unverified: capabilityNames(capabilities) };
  if (!verifier) return unverified;
  const answer: unknown = await unlessUnanswered<unknown>('the capability verifier', unverified, () =>
    verifier(capabilities, { subjectDid: card.id, trustedIssuers }),
  timeoutMs);
  return readCapabilityCheck(answer) ?? unverified;
}

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === 'string');

/**
 * The capability check `answer`, which the host's capability verifier gave, comes to, or `undefined`
 * when it is not one: `verified` and `unverified` must each be an array of strings, and a caller
 * then counts no capability verified.
 * `fresh` is read as the accountability verdict's is: left out or `undefined` it is unknown, and
 * any other value but the literal `true` is `false`. Each member is read once, and an answer whose
 * member throws when read is not a capability check.
 */
function readCapabilityCheck(answer: unknown): CapabilityCheckResult | undefined {
  let verified: unknown;
  let unverified: unknown;
  let fresh: unknown;
  try {
    // Reading a member of `undefined` or `null` throws, and any other value that is not an object has none.
    ({ verified, unverified, fresh } = answer as Record<string, unknown>);
  } catch {
    return undefined;
  }
  if (!isStringArray(verified) || !isStringArray(unverified)) return undefined;
  return { verified, unverified, ...(fresh === undefined ? {} : { fresh: fresh === true }) };
}

/**
 * What a seam the host supplies answers, asked under a deadline of `timeoutMs`, or `unanswered`, the verdict of a claim that did not verify, when it has not answered by
 * then: `verifyCard` does not wait on, and does not throw for it. A seam that throws still throws.
 */
async function unlessUnanswered<T>(who: string, unanswered: T, ask: () => T | Promise<T>, timeoutMs: number): Promise<T> {
  try {
    return await answerWithinDeadline(who, ask, timeoutMs);
  } catch (error) {
    if (error instanceof DeadlineExceededError) return unanswered;
    throw error;
  }
}

/** What a seam the host supplies stands for when it has not answered in time. */
const UNANSWERED: unique symbol = Symbol('unanswered');

/** A claim of the Card as the result reports it, with the code of why when it did not verify. */
interface CheckedClaim<T> {
  reported: T;
  refusal?: Coded;
}

/**
 * Recompute the accountability edge, threading `proofDid` for the leaf-invoker join and surfacing the
 * delegation-chain `fresh` signal the §9.3/§12.6 L3 gate needs. A bare boolean is the DEPRECATED alias.
 * A party that did not verify is refused with `configuration_error` when no verifier is supplied,
 * `deadline_exceeded` when it has not answered in time, `claim_unverified` when it answered no, and
 * `runtime_error` when its answer could not be read.
 */
export async function checkAccountability(
  card: EntityCard,
  deps: VerifyCardDeps,
  trustedIssuers: readonly string[],
  proofDid: string | undefined,
  timeoutMs: number,
): Promise<CheckedClaim<NonNullable<VerifyCardResult['accountability']>> | undefined> {
  if (!card.responsibleParty) return undefined;
  const verifier = deps.accountabilityVerifier;
  const read: AccountabilityRead = verifier
    ? readAccountability(
        await unlessUnanswered<unknown>('the accountability verifier', UNANSWERED, () =>
          verifier(card, { trustedIssuers, proofDid }),
        timeoutMs),
      )
    : { verified: false, fresh: undefined, ...coded('configuration_error') };
  const reported = { responsibleParty: card.responsibleParty, principal: card.principal };
  if (read.verified) return { reported: { ...reported, ...read } };
  const { code, transient, ...found } = read;
  return { reported: { ...reported, ...found }, refusal: { code, transient } };
}

const ACCOUNTABILITY_ANSWER = "the accountability verifier's answer";

/** What an accountability verdict comes to: verified, or not, with the code of why. */
type AccountabilityRead =
  | { verified: true; fresh: boolean | undefined; rootStatusList?: string }
  | ({ verified: false; fresh: boolean | undefined; reason?: string } & Coded);

/**
 * What the accountability verifier's `answer` comes to. A truthy string such as "false" must
 * neither grant status-list authority nor keep the Card's L3, so it verifies only as the literal
 * `true` (the DEPRECATED bare boolean) or an object whose `verified` is `true`, and is fresh only
 * as a literal `true`; a `fresh` left out or `undefined` stays unknown. An answer that is neither a
 * boolean nor an object, a `verified` that is not a boolean, and an answer that throws when looked
 * at do not verify, with a reason. The `rootStatusList` names what the responsible party may sign
 * for this Card, so it is kept only from the read that saw `verified: true`, and only as the
 * non-empty string it is. Each member is read once, inside the `try`, so nothing throws. A party
 * the verifier did not answer for in time does not verify, with no reason.
 */
function readAccountability(answer: unknown): AccountabilityRead {
  if (answer === UNANSWERED) return { verified: false, fresh: undefined, ...coded('deadline_exceeded') };
  if (typeof answer === 'boolean') {
    return answer ? { verified: true, fresh: undefined } : { verified: false, fresh: undefined, ...coded('claim_unverified') };
  }
  const unreadable = (reason: string, fresh?: boolean): AccountabilityRead => ({ verified: false, fresh, reason, ...coded('runtime_error') });
  try {
    if (typeof answer !== 'object' || answer === null) {
      return unreadable(`${ACCOUNTABILITY_ANSWER} (${describeValue(answer)}) is neither a boolean nor an object`);
    }
    const { verified, fresh: stated, rootStatusList: reported } = answer as Record<string, unknown>;
    const fresh = stated === undefined ? undefined : stated === true;
    if (verified === true) {
      const listed = typeof reported === 'string' && reported.length > 0 ? { rootStatusList: reported } : {};
      return { verified, fresh, ...listed };
    }
    if (verified === false) return { verified, fresh, ...coded('claim_unverified') };
    return unreadable(`the verified member of ${ACCOUNTABILITY_ANSWER} (${describeValue(verified)}) is neither true nor false`, fresh);
  } catch {
    return unreadable(`${ACCOUNTABILITY_ANSWER} threw when it was read`);
  }
}

/**
 * Recompute each attestation VC via the injected seam (unverified when no seam is injected). One that
 * did not verify is refused with `configuration_error` when no verifier is supplied,
 * `deadline_exceeded` when it has not answered in time, and `claim_unverified` otherwise.
 */
export async function checkAttestations(
  card: EntityCard,
  deps: VerifyCardDeps,
  trustedIssuers: readonly string[],
  timeoutMs: number,
): Promise<CheckedClaim<VerifyCardResult['attestations'][number]>[]> {
  const verifier = deps.attestationVerifier;
  return Promise.all(
    (card.attestations ?? []).map(async (a) => {
      const answer = verifier
        ? await unlessUnanswered<unknown>('the attestation verifier', UNANSWERED, () =>
            verifier(a, { subjectDid: a.subject ?? card.id, trustedIssuers }),
          timeoutMs)
        : undefined;
      // Only the literal `true` verifies: a truthy answer such as "false" does not.
      const verified = answer === true;
      const code = !verifier ? 'configuration_error' : answer === UNANSWERED ? 'deadline_exceeded' : 'claim_unverified';
      return { reported: { type: a.type, subject: a.subject, verified }, ...(verified ? {} : { refusal: coded(code) }) };
    }),
  );
}

/**
 * Recompute the live per-request proof. Returns `undefined` when no proof/request/verifier was
 * supplied (the level then rests at the capability floor, no proof lift). Fail-closed: a throwing
 * verifier yields `{ ok:false }` (a demotion) rather than escaping `verifyCard`.
 */
export async function recomputeProof(deps: VerifyCardDeps, timeoutMs: number): Promise<ProofVerifyResult | undefined> {
  const { proofVerifier, proof, request } = deps;
  if (!proofVerifier || proof === undefined || request === undefined) return undefined;
  let answer: unknown;
  try {
    answer = await answerWithinDeadline('the proof verifier', () => proofVerifier(proof, request), timeoutMs);
  } catch (error) {
    return { ok: false, reasons: [error instanceof DeadlineExceededError ? error.message : 'proof_verifier_threw'] };
  }
  return readProofVerdict(answer);
}

/** What `verifyCard` reports for a proof verifier's answer that is not a proof verdict. */
const UNREADABLE_PROOF_VERDICT: ProofVerifyResult = { ok: false, reasons: ['proof_verdict_unreadable'] };
const PROOF_ASSURANCES: readonly unknown[] = ['L3', 'L3-minus'] satisfies readonly ProofAssurance[];

/**
 * The proof verdict `answer`, which the host's proof verifier gave, comes to. The proof verified
 * only when `answer` is an object whose `ok` is the literal `true` and whose `did` is a string; its
 * `level` is kept when it is one a proof can have. On the literal `false` it is a refusal with the
 * `reasons` the answer gave that are strings. Anything else is a refusal with the one reason
 * `proof_verdict_unreadable`: an answer that is not an object, an `ok` that is not a boolean, a
 * verified proof that names no DID, and an answer whose member throws when read. Each member is
 * read once.
 */
function readProofVerdict(answer: unknown): ProofVerifyResult {
  let ok: unknown;
  let did: unknown;
  let level: unknown;
  let reasons: unknown;
  try {
    // Reading a member of `undefined` or `null` throws, and any other value that is not an object has none.
    ({ ok, did, level, reasons } = answer as Record<string, unknown>);
  } catch {
    return UNREADABLE_PROOF_VERDICT;
  }
  if (ok === false) {
    return { ok, reasons: Array.isArray(reasons) ? reasons.filter((reason): reason is string => typeof reason === 'string') : [] };
  }
  if (ok !== true || typeof did !== 'string') return UNREADABLE_PROOF_VERDICT;
  return { ok, did, reasons: [], ...(PROOF_ASSURANCES.includes(level) ? { level: level as ProofAssurance } : {}) };
}
