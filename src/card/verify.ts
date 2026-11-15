/**
 * KYA-OS Entity Card — VERIFY (the proof half).
 *
 * Verify a resolved card's claims via injected, level-AGNOSTIC crypto seams (the pattern
 * `validateLevel2` uses for its `signatureVerifier`, keeping `@kya-os/mcp` free of any mcp-i-core
 * runtime dep) and RECOMPUTE the conformance level — the self-declared `conformanceLevel` is NEVER
 * trusted; the LEVEL is derived here, never baked into a function name. Four fail-closed seams the
 * SPEC §9/§11 ladder needs:
 *   - `capabilityVerifier`  — per-capability attestation check (L1 floor if omitted);
 *   - `accountabilityVerifier` — delegation edge: `responsibleParty === issuer(rootVC)`, `leaf-invoker
 *     === proof.did` (via `ctx.proofDid`), AND the chain `fresh` L3 gate (./delegation);
 *   - `proofVerifier` + `proof`/`request` — the live per-request holder-of-key proof (./proof);
 *   - `statusListChecker` — W3C Bitstring Status List v1.0 liveness (./revocation).
 * Fail-closed everywhere: a missing/expired/revoked artifact DEMOTES the level (L3→L2→L1) and never
 * errors open; an unreachable/stale status list OR stale delegation chain demotes L3→L2.
 */

import {
  EntityTypeSchema,
  capabilityNames,
  type EntityCard,
  type EntityType,
  type ConformanceLevel,
  type Capability,
  type Attestation,
} from './schema.js';
import { CHECKER_REASON_LENGTH, type BitstringRevocationChecker } from './revocation.js';
import { sanitizeForMessage } from '../utils/message-text.js';
import { describeValue } from '../utils/describe-value.js';
import { readRevocationAnswer } from '../utils/revocation-answer.js';
import type { StatusCheckContext } from '../utils/statuslist-keeper.js';
import { answerWithinDeadline, DeadlineExceededError, dependencyTimeout } from '../utils/deadline.js';
import { checkWithinDeadline } from './revocation-deadline.js';
import type { ProofAssurance, ProofVerifyResult } from './proof/index.js';
import type { ToolRequest } from '../proof/generator.js';

export const ENTITY_TYPES: readonly EntityType[] = EntityTypeSchema.options;

export const DEFAULT_TRUSTED_ISSUERS = ['did:web:example.com'] as const;

// ── Pluggable verification seams (level-AGNOSTIC; crypto lives in the runtime) ─

export interface CapabilityCheckResult {
  /** Capability names whose attestation verified (eligible for L2). */
  verified: string[];
  /** Capability names that were self-declared (bare string) or failed. */
  unverified: string[];
  /**
   * True iff every attested capability's status was read from a LIVE list (§9.3 L3 gate). Omitted ⇒ unknown ⇒ no demotion;
   * any other value but the literal `true` reads as `false`.
   */
  fresh?: boolean;
}

/**
 * Verifies capability attestations. Deliberately NOT named for a level — the level is DERIVED
 * downstream (see `deriveConformanceLevel`). A runtime supplies an implementation (e.g. an adapter
 * over mcp-i-core's `validateLevel2`); `@kya-os/mcp` ships only the interface.
 */
export type CapabilityVerifier = (
  capabilities: Capability[],
  ctx: { subjectDid: string; trustedIssuers: readonly string[] },
) => Promise<CapabilityCheckResult>;

/** Verifies a single attestation VC (trusted issuer + signature + expiry). Only the literal `true` verifies it. */
export type AttestationVerifier = (
  attestation: Attestation,
  ctx: { subjectDid: string; trustedIssuers: readonly string[] },
) => Promise<boolean>;

/**
 * The accountability seam's verdict. `fresh` is the freshness channel a bare boolean cannot express
 * (SPEC §9.3/§12.6): a stale-but-non-revoked chain stays `verified:true` (keeps §10.6's cached L2)
 * yet `fresh:false` demotes L3→L2; omitted `fresh` ⇒ freshness UNKNOWN so no demotion (back-compat).
 * `verifyCard` reads only a literal `true` as verified, and a `fresh` that is present and not a
 * boolean as `false`, so a malformed verdict neither grants authority nor keeps L3.
 */
export interface AccountabilityResult {
  /** True iff the delegation edge verified (`responsibleParty === issuer(rootVC)`, leaf-invoker join). */
  verified: boolean;
  /**
   * True iff every leaf/chain delegation credential status was read from a LIVE list (drives L2→L3).
   * Omitted or `undefined`, freshness is unknown; any other value but `true` reads as `false`.
   */
  fresh?: boolean;
  /**
   * The `statusListCredential` URL that the status entry of the chain's root credential names, read
   * from the credential whose proof the verifier checked. The responsible party keeps the list at
   * that URL, so its list there counts for the Card's `revocation` entry. It is read only from a
   * verdict whose `verified` is `true`, and only when it is a non-empty string; omitted, the
   * responsible party keeps only the URLs the checker's `statusListIssuers` binds to it.
   */
  rootStatusList?: string;
}

/**
 * Verifies the accountability edge: resolve `card.delegationRef` → the signed
 * DelegationCredential chain and confirm `card.responsibleParty === issuerDid(rootVC)` AND —
 * when a live proof accompanies the request — the leaf invoker `=== ctx.proofDid` (the
 * delegation/accountability JOIN of ./delegation, recomputed, asserted nowhere). `proofDid` is
 * OPTIONAL and additive: implementations that ignore it keep the L2 offline check unchanged.
 * Returns a bare boolean (DEPRECATED alias) or an {@link AccountabilityResult} carrying `fresh`.
 * A verified responsible party's status list also counts for the Card's `revocation` entry, at the
 * URL the verdict reports as `rootStatusList` or one the configuration binds to it (see
 * `statusListChecker`). Reporting `verified: true` is an authority grant: the host must verify
 * every hop's proof, continuity, attenuation, expiry and revocation under its policy, bind the
 * resolved chain to this Card and its leaf, and confirm the root equality. A structural check or
 * a Card-supplied root alone is insufficient. The host must authorize that root for this Card;
 * `trustedIssuers` is attestation policy, not an automatic root pin. See SPEC-ENTITY-CARD §10.3.
 */
export type AccountabilityVerifier = (
  card: EntityCard,
  ctx: { trustedIssuers: readonly string[]; proofDid?: string },
) => Promise<boolean | AccountabilityResult>;

/**
 * Recompute a live per-request holder-of-key proof against the request it must bind. The
 * caller pre-binds the crypto seams (e.g. `verifyCardProof(proof, req, deps)` from ./proof);
 * `@kya-os/mcp` ships only this interface. Fail-closed: a rejected promise DEMOTES, never throws
 * out of `verifyCard`.
 */
export type CardProofVerifier = (
  proof: unknown,
  request: ToolRequest,
) => Promise<ProofVerifyResult>;

export interface VerifyCardDeps {
  /** Verifies capability attestations (option C seam). If omitted, capabilities are L1. */
  capabilityVerifier?: CapabilityVerifier;
  /** Verifies an attestation VC (e.g. KYC/KYB). If omitted, attestations are unverified. */
  attestationVerifier?: AttestationVerifier;
  /** Verifies the accountability edge (delegationRef → responsibleParty, leaf-invoker join). */
  accountabilityVerifier?: AccountabilityVerifier;
  /** The per-request holder-of-key proof that rode `_meta['org.kya-os/request-proof']` (recomputed here). */
  proof?: unknown;
  /** The request the proof must bind (`method` + `params`); required alongside `proof`. */
  request?: ToolRequest;
  /** Recomputes `proof` against `request` (pre-bound ./proof `verifyCardProof`). Lifts L2 → L3. */
  proofVerifier?: CardProofVerifier;
  /**
   * Live W3C Bitstring Status List v1.0 check for `card.revocation` (fail-closed). It is called with
   * `{ credentialIssuer: card.id }`, the Card being its Entity's own statement, and, once the
   * accountability check has verified the Card's `responsibleParty` as the root issuer of the Card's
   * delegation chain, with that party as `trustedRootIssuer` and, when the verdict reported it, the
   * list URL the root credential names as `trustedRootStatusList`. A checker that verifies the list
   * then reads the party's list for the Card only at that URL or at one its `statusListIssuers`
   * binds to the party, and otherwise the Card's own (`acceptStatusList`). A responsible party
   * that did not verify is not named, and neither is a URL it reported.
   */
  statusListChecker?: BitstringRevocationChecker;
  /** True iff the caller independently proved CIMD L1 key possession (private_key_jwt ↔ jwks_uri). */
  cimdKeyProven?: boolean;
  /** Trusted issuer allowlist. Default: `DEFAULT_TRUSTED_ISSUERS`. */
  trustedIssuers?: readonly string[];
  /**
   * How long, in milliseconds, each seam `verifyCard` asks may take to answer: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value makes `verifyCard` reject with a `TypeError`.
   */
  dependencyTimeoutMs?: number;
}

export interface VerifyCardResult {
  /** True iff every trust-bearing claim *present* on the card verified (proof is per-request, not a card claim). */
  ok: boolean;
  entityType: EntityType;
  /** RECOMPUTED — the card's self-declared `conformanceLevel` is never trusted. */
  conformanceLevel: ConformanceLevel;
  verifiedCapabilities: string[];
  accountability?: {
    responsibleParty?: string;
    principal?: string;
    verified: boolean;
    fresh?: boolean;
    /** Why the party did not verify, when the accountability verifier's answer could not be read. */
    reason?: string;
    /** The list URL a verified verdict reported the root credential names ({@link AccountabilityResult.rootStatusList}). */
    rootStatusList?: string;
  };
  attestations: Array<{ type: string; subject?: string; verified: boolean }>;
  /** Present when a proof was recomputed: the live holder-of-key verdict. */
  proof?: { verified: boolean; did?: string; level?: ProofAssurance; reasons: string[] };
  /**
   * Present when the card declares `revocation` and a `statusListChecker` was supplied. The checker's
   * answer is read as `evaluateRevocationChain` reads one: only a literal `revoked: false` passes and
   * only a literal `fresh: true` is fresh. An answer that could not be read is reported as revoked and
   * not fresh, with the `reason`; a revoked Card carries the `reason` its checker gave, when it gave
   * one, bounded as `evaluateRevocationChain` bounds it.
   */
  revocation?: { revoked: boolean; fresh: boolean; reason?: string };
  /** Echoes `deps.cimdKeyProven` — the caller's L1 CIMD key-possession evidence. */
  cimdKeyProven?: boolean;
}

/**
 * Verify a resolved card: recompute capabilities + accountability + attestations + the live proof
 * + revocation via the injected seams, and RECOMPUTE the conformance level. The card's
 * self-declared `conformanceLevel` is ignored. `ok` is true iff every claim that is *present*
 * verified (a card with only self-declared capabilities is still `ok` — it is just L1); a per-request
 * proof affects the LEVEL, not `ok`, but a revoked card credential fails closed (`ok:false`, L1).
 */
export async function verifyCard(card: EntityCard, deps: VerifyCardDeps): Promise<VerifyCardResult> {
  const trustedIssuers = deps.trustedIssuers ?? DEFAULT_TRUSTED_ISSUERS;
  const timeoutMs = dependencyTimeout(deps.dependencyTimeoutMs);
  const check = await checkCapabilities(card, deps, trustedIssuers, timeoutMs);
  const proof = await recomputeProof(deps, timeoutMs);
  const proofDid = proof?.ok ? proof.did : undefined;

  const accountability = await checkAccountability(card, deps, trustedIssuers, proofDid, timeoutMs);
  const attestations = await checkAttestations(card, deps, trustedIssuers, timeoutMs);
  const revocation = await checkCardRevocation(card, deps.statusListChecker, verifiedRoot(accountability), timeoutMs);

  const accountabilityOk = !card.responsibleParty || Boolean(accountability?.verified);
  const attestationsOk = attestations.every((a) => a.verified);

  return {
    ok: accountabilityOk && attestationsOk && !revocation.revoked,
    entityType: card.entityType,
    conformanceLevel: deriveConformanceLevel(
      demoteOnRevocation(check, revocation.revoked),
      proof?.ok ?? false,
      (!revocation.checked || revocation.fresh) && (accountability?.fresh ?? true) && (check.fresh ?? true),
    ),
    verifiedCapabilities: check.verified,
    accountability,
    attestations,
    proof: proof
      ? { verified: proof.ok, did: proof.did, level: proof.level, reasons: proof.reasons }
      : undefined,
    revocation: revocation.checked ? reportedRevocation(revocation) : undefined,
    cimdKeyProven: deps.cimdKeyProven,
  };
}

/**
 * Derive the conformance FLOOR from verified capabilities, live-proof validity, and freshness.
 * L3 ⊇ L2 ⊇ L1: all declared capabilities attested ⇒ L2; plus a valid holder-of-key proof (`proofOk`)
 * AND a fresh (live) status check ⇒ L3. Any self-declared (unverified) capability keeps the floor at
 * L1. `revocationFresh` (the AND of card / delegation-chain / capability status liveness) defaults to
 * `true` so 2-arg calls still compile; a `false` (unreachable/stale list) demotes L3 → L2.
 */
export function deriveConformanceLevel(
  check: CapabilityCheckResult,
  proofOk: boolean,
  revocationFresh = true,
): ConformanceLevel {
  const allAttested = check.verified.length > 0 && check.unverified.length === 0;
  if (!allAttested) return 'L1';
  return proofOk && revocationFresh ? 'L3' : 'L2';
}

// ── Internals ──────────────────────────────────────────────────────────────────

/** Run the capability seam (or floor everything to unverified when no seam is injected). */
async function checkCapabilities(
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

/**
 * Recompute the accountability edge, threading `proofDid` for the leaf-invoker join and surfacing the
 * delegation-chain `fresh` signal the §9.3/§12.6 L3 gate needs. A bare boolean is the DEPRECATED alias.
 */
async function checkAccountability(
  card: EntityCard,
  deps: VerifyCardDeps,
  trustedIssuers: readonly string[],
  proofDid: string | undefined,
  timeoutMs: number,
): Promise<VerifyCardResult['accountability']> {
  if (!card.responsibleParty) return undefined;
  const verifier = deps.accountabilityVerifier;
  const raw = verifier
    ? await unlessUnanswered<unknown>('the accountability verifier', false, () =>
        verifier(card, { trustedIssuers, proofDid }),
      timeoutMs)
    : false;
  return { responsibleParty: card.responsibleParty, principal: card.principal, ...readAccountability(raw) };
}

const ACCOUNTABILITY_ANSWER = "the accountability verifier's answer";

/**
 * What the accountability verifier's `answer` comes to. A truthy string such as "false" must
 * neither grant status-list authority nor keep the Card's L3, so it verifies only as the literal
 * `true` (the DEPRECATED bare boolean) or an object whose `verified` is `true`, and is fresh only
 * as a literal `true`; a `fresh` left out or `undefined` stays unknown. An answer that is neither a
 * boolean nor an object, a `verified` that is not a boolean, and an answer that throws when looked
 * at do not verify, with a reason. The `rootStatusList` names what the responsible party may sign
 * for this Card, so it is kept only from the read that saw `verified: true`, and only as the
 * non-empty string it is. Each member is read once, inside the `try`, so nothing throws.
 */
function readAccountability(
  answer: unknown,
): Pick<NonNullable<VerifyCardResult['accountability']>, 'verified' | 'fresh' | 'reason' | 'rootStatusList'> {
  if (typeof answer === 'boolean') return { verified: answer, fresh: undefined };
  try {
    if (typeof answer !== 'object' || answer === null) {
      const reason = `${ACCOUNTABILITY_ANSWER} (${describeValue(answer)}) is neither a boolean nor an object`;
      return { verified: false, fresh: undefined, reason };
    }
    const { verified, fresh: stated, rootStatusList: reported } = answer as Record<string, unknown>;
    const fresh = stated === undefined ? undefined : stated === true;
    if (typeof verified === 'boolean') {
      const listed = verified && typeof reported === 'string' && reported.length > 0 ? { rootStatusList: reported } : {};
      return { verified, fresh, ...listed };
    }
    const reason = `the verified member of ${ACCOUNTABILITY_ANSWER} (${describeValue(verified)}) is neither true nor false`;
    return { verified: false, fresh, reason };
  } catch {
    return { verified: false, fresh: undefined, reason: `${ACCOUNTABILITY_ANSWER} threw when it was read` };
  }
}

/** Recompute each attestation VC via the injected seam (unverified when no seam is injected). */
async function checkAttestations(
  card: EntityCard,
  deps: VerifyCardDeps,
  trustedIssuers: readonly string[],
  timeoutMs: number,
): Promise<VerifyCardResult['attestations']> {
  const verifier = deps.attestationVerifier;
  return Promise.all(
    (card.attestations ?? []).map(async (a) => ({
      type: a.type,
      subject: a.subject,
      // Only the literal `true` verifies: a truthy answer such as "false" does not.
      verified: verifier
        ? (await unlessUnanswered<unknown>('the attestation verifier', false, () =>
            verifier(a, { subjectDid: a.subject ?? card.id, trustedIssuers }),
          timeoutMs)) === true
        : false,
    })),
  );
}

/**
 * Recompute the live per-request proof. Returns `undefined` when no proof/request/verifier was
 * supplied (the level then rests at the capability floor, no proof lift). Fail-closed: a throwing
 * verifier yields `{ ok:false }` (a demotion) rather than escaping `verifyCard`.
 */
async function recomputeProof(deps: VerifyCardDeps, timeoutMs: number): Promise<ProofVerifyResult | undefined> {
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

/** Verdict for the card's own credential status entry (`card.revocation`). */
interface CardRevocationVerdict {
  /** True iff a `statusListChecker` was supplied AND the card declares `revocation`. */
  checked: boolean;
  revoked: boolean;
  fresh: boolean;
  /** Why the Card reads as revoked, when its checker said why or its answer could not be read. */
  reason?: string;
}

/** The part of a status check's context that names the root of a Card's chain. */
type CardRoot = Partial<Pick<StatusCheckContext, 'trustedRootIssuer' | 'trustedRootStatusList'>>;

/**
 * The Card's responsible party as the checker is told of it, once the accountability check has
 * verified it and never before: the root of the Card's chain, with the list URL the verdict
 * reported that root's own credential names, when it reported one.
 */
function verifiedRoot(
  accountability: VerifyCardResult['accountability'],
): CardRoot {
  if (!accountability?.verified || accountability.responsibleParty === undefined) return {};
  const { responsibleParty, rootStatusList } = accountability;
  return { trustedRootIssuer: responsibleParty, ...(rootStatusList === undefined ? {} : { trustedRootStatusList: rootStatusList }) };
}

/**
 * Live-check `card.revocation` via the injected seam; fail-closed (unreachable ⇒ revoked). The Card's
 * `id` is named as the issuer its status list is held to, and `root` names a verified
 * `responsibleParty` as the root of the Card's delegation chain ({@link verifiedRoot}).
 */
async function checkCardRevocation(
  card: EntityCard,
  checker: BitstringRevocationChecker | undefined,
  root: CardRoot,
  timeoutMs: number,
): Promise<CardRevocationVerdict> {
  if (!checker || !card.revocation) return { checked: false, revoked: false, fresh: true };
  try {
    const asked = await checkWithinDeadline(checker, card.revocation, { credentialIssuer: card.id, ...root }, timeoutMs);
    if ('expired' in asked) return { checked: true, revoked: true, fresh: false, reason: asked.expired };
    const status = readRevocationAnswer(asked.answer);
    if (status.revoked === undefined) {
      const reason = `the Card's revocation status could not be read: ${status.unreadable}`;
      return { checked: true, revoked: true, fresh: false, reason };
    }
    const given = status.revoked && status.reason ? { reason: sanitizeForMessage(status.reason, CHECKER_REASON_LENGTH) } : {};
    return { checked: true, revoked: status.revoked, fresh: status.fresh, ...given };
  } catch {
    return { checked: true, revoked: true, fresh: false };
  }
}

/** The revocation verdict as the result reports it, with its `reason` only when it has one. */
function reportedRevocation({ revoked, fresh, reason }: CardRevocationVerdict): NonNullable<VerifyCardResult['revocation']> {
  return reason === undefined ? { revoked, fresh } : { revoked, fresh, reason };
}

/**
 * A REVOKED card credential voids its attested trust: every otherwise-verified capability drops to
 * unverified so the floor collapses to L1 (revocation demotes L3→L2→L1). A clean-but-stale list
 * leaves `check` untouched — it only trims `revocationFresh` (L3→L2). No-op when not revoked.
 */
function demoteOnRevocation(check: CapabilityCheckResult, revoked: boolean): CapabilityCheckResult {
  if (!revoked) return check;
  return { verified: [], unverified: [...check.verified, ...check.unverified] };
}
