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
import type { RevocationChecker } from './revocation.js';
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
  /** True iff every attested capability's status was read from a LIVE list (§9.3 L3 gate). Omitted ⇒ unknown ⇒ no demotion. */
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

/** Verifies a single attestation VC (trusted issuer + signature + expiry). */
export type AttestationVerifier = (
  attestation: Attestation,
  ctx: { subjectDid: string; trustedIssuers: readonly string[] },
) => Promise<boolean>;

/**
 * The accountability seam's verdict. `fresh` is the freshness channel a bare boolean cannot express
 * (SPEC §9.3/§12.6): a stale-but-non-revoked chain stays `verified:true` (keeps §10.6's cached L2)
 * yet `fresh:false` demotes L3→L2; omitted `fresh` ⇒ freshness UNKNOWN so no demotion (back-compat).
 */
export interface AccountabilityResult {
  /** True iff the delegation edge verified (`responsibleParty === issuer(rootVC)`, leaf-invoker join). */
  verified: boolean;
  /** True iff every leaf/chain delegation credential status was read from a LIVE list (drives L2→L3). */
  fresh?: boolean;
}

/**
 * Verifies the accountability edge: resolve `card.delegationRef` → the signed
 * DelegationCredential chain and confirm `card.responsibleParty === issuerDid(rootVC)` AND —
 * when a live proof accompanies the request — the leaf invoker `=== ctx.proofDid` (the
 * delegation/accountability JOIN of ./delegation, recomputed, asserted nowhere). `proofDid` is
 * OPTIONAL and additive: implementations that ignore it keep the L2 offline check unchanged.
 * Returns a bare boolean (DEPRECATED alias) or an {@link AccountabilityResult} carrying `fresh`.
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
  /** The per-request holder-of-key proof that rode `_meta['org.kya-os/proof.v1']` (recomputed here). */
  proof?: unknown;
  /** The request the proof must bind (`method` + `params`); required alongside `proof`. */
  request?: ToolRequest;
  /** Recomputes `proof` against `request` (pre-bound ./proof `verifyCardProof`). Lifts L2 → L3. */
  proofVerifier?: CardProofVerifier;
  /** Live W3C Bitstring Status List v1.0 check for `card.revocation` (fail-closed). */
  statusListChecker?: RevocationChecker;
  /** True iff the caller independently proved CIMD L1 key possession (private_key_jwt ↔ jwks_uri). */
  cimdKeyProven?: boolean;
  /** Trusted issuer allowlist. Default: `DEFAULT_TRUSTED_ISSUERS`. */
  trustedIssuers?: readonly string[];
}

export interface VerifyCardResult {
  /** True iff every trust-bearing claim *present* on the card verified (proof is per-request, not a card claim). */
  ok: boolean;
  entityType: EntityType;
  /** RECOMPUTED — the card's self-declared `conformanceLevel` is never trusted. */
  conformanceLevel: ConformanceLevel;
  verifiedCapabilities: string[];
  accountability?: { responsibleParty?: string; principal?: string; verified: boolean; fresh?: boolean };
  attestations: Array<{ type: string; subject?: string; verified: boolean }>;
  /** Present when a proof was recomputed: the live holder-of-key verdict. */
  proof?: { verified: boolean; did?: string; level?: ProofAssurance; reasons: string[] };
  /** Present when the card declares `revocation` and a `statusListChecker` was supplied. */
  revocation?: { revoked: boolean; fresh: boolean };
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
  const check = await checkCapabilities(card, deps, trustedIssuers);
  const proof = await recomputeProof(deps);
  const proofDid = proof?.ok ? proof.did : undefined;

  const accountability = await checkAccountability(card, deps, trustedIssuers, proofDid);
  const attestations = await checkAttestations(card, deps, trustedIssuers);
  const revocation = await checkCardRevocation(card, deps.statusListChecker);

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
    revocation: revocation.checked ? { revoked: revocation.revoked, fresh: revocation.fresh } : undefined,
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
): Promise<CapabilityCheckResult> {
  const capabilities = card.capabilities ?? [];
  return deps.capabilityVerifier
    ? deps.capabilityVerifier(capabilities, { subjectDid: card.id, trustedIssuers })
    : { verified: [], unverified: capabilityNames(capabilities) };
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
): Promise<VerifyCardResult['accountability']> {
  if (!card.responsibleParty) return undefined;
  const raw = deps.accountabilityVerifier
    ? await deps.accountabilityVerifier(card, { trustedIssuers, proofDid })
    : false;
  const { verified, fresh } = typeof raw === 'boolean' ? { verified: raw, fresh: undefined } : raw;
  return { responsibleParty: card.responsibleParty, principal: card.principal, verified, fresh };
}

/** Recompute each attestation VC via the injected seam (unverified when no seam is injected). */
async function checkAttestations(
  card: EntityCard,
  deps: VerifyCardDeps,
  trustedIssuers: readonly string[],
): Promise<VerifyCardResult['attestations']> {
  return Promise.all(
    (card.attestations ?? []).map(async (a) => ({
      type: a.type,
      subject: a.subject,
      verified: deps.attestationVerifier
        ? await deps.attestationVerifier(a, { subjectDid: a.subject ?? card.id, trustedIssuers })
        : false,
    })),
  );
}

/**
 * Recompute the live per-request proof. Returns `undefined` when no proof/request/verifier was
 * supplied (the level then rests at the capability floor, no proof lift). Fail-closed: a throwing
 * verifier yields `{ ok:false }` (a demotion) rather than escaping `verifyCard`.
 */
async function recomputeProof(deps: VerifyCardDeps): Promise<ProofVerifyResult | undefined> {
  if (!deps.proofVerifier || deps.proof === undefined || deps.request === undefined) return undefined;
  try {
    return await deps.proofVerifier(deps.proof, deps.request);
  } catch {
    return { ok: false, reasons: ['proof_verifier_threw'] };
  }
}

/** Verdict for the card's own credential status entry (`card.revocation`). */
interface CardRevocationVerdict {
  /** True iff a `statusListChecker` was supplied AND the card declares `revocation`. */
  checked: boolean;
  revoked: boolean;
  fresh: boolean;
}

/** Live-check `card.revocation` via the injected seam; fail-closed (unreachable ⇒ revoked). */
async function checkCardRevocation(
  card: EntityCard,
  checker: RevocationChecker | undefined,
): Promise<CardRevocationVerdict> {
  if (!checker || !card.revocation) return { checked: false, revoked: false, fresh: true };
  try {
    const status = await checker(card.revocation);
    return { checked: true, revoked: status.revoked, fresh: status.fresh };
  } catch {
    return { checked: true, revoked: true, fresh: false };
  }
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
