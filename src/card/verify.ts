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
 *     A card that declares `revocation` is refused without it.
 * Fail-closed everywhere: a missing/expired/revoked artifact DEMOTES the level (L3→L2→L1) and never
 * errors open; an unreachable/stale status list OR stale delegation chain demotes L3→L2.
 * This module weighs the verdicts into `ok` and the level. Each verifier is asked, and its answer
 * read, in `./verify-claims`, and the status list in `./verify-revocation`.
 */

import {
  EntityTypeSchema,
  type EntityCard,
  type EntityType,
  type ConformanceLevel,
  type Capability,
  type Attestation,
} from './schema.js';
import type { BitstringRevocationChecker } from './revocation.js';
import { dependencyTimeout } from '../utils/deadline.js';
import { coded, decidingRefusal } from '../utils/refusal.js';
import type { RefusalCoding } from '../delegation/vc-verifier.types.js';
import {
  checkCardRevocation,
  demoteOnRevocation,
  reportedRevocation,
  verifiedRoot,
  type CardRevocation,
} from './verify-revocation.js';
import type { ProofAssurance, ProofVerifyResult } from './proof/index.js';
import { sameDid } from './same-did.js';
import { checkAccountability, checkAttestations, checkCapabilities, recomputeProof } from './verify-claims.js';
import { assertTrustedRootIssuers } from '../delegation/root-admission.js';
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
  /**
   * Recomputes `proof` against `request` (pre-bound ./proof `verifyCardProof`). Lifts L2 → L3 only
   * when the proof's DID is the Card's own `id`.
   */
  proofVerifier?: CardProofVerifier;
  /**
   * Live W3C Bitstring Status List v1.0 check for `card.revocation` (fail-closed), e.g.
   * `createRevocationChecker`. Required for a card that declares `revocation`: without it such a card
   * is refused as `configuration_error`, since nothing shows it is not revoked. A card that declares
   * no `revocation` is not checked, so it needs none. It is called with
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
   * The DIDs the verifier pins as roots, as `verifyRequestDelegation`'s `trustedRootIssuers` names
   * them. When the accountability check has verified the Card's `responsibleParty` and it is one of
   * these, the list URL the verdict reports as `rootStatusList` is that pinned root's own, and the
   * checker reads it on any host, a private one included, still pinned. Otherwise that URL is read
   * as one the presenter named, under the private-network rule, since a host that accepts any root
   * lets the presenter be the root and choose the URL. It is not an allowlist for accountability
   * itself, which the `accountabilityVerifier` decides. Each entry is a string that starts with
   * `did:` and has no white space around it; any other value makes `verifyCard` reject with a
   * `TypeError`.
   */
  trustedRootIssuers?: readonly string[];
  /**
   * How long, in milliseconds, each seam `verifyCard` asks may take to answer: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value makes `verifyCard` reject with a `TypeError`.
   */
  dependencyTimeoutMs?: number;
}

/**
 * What {@link verifyCard} finds. A Card that is not `ok` carries the `code` of why, and whether it is
 * `transient`: with several claims refused, the code of the first that is not transient, else of the
 * first, in the order accountability, attestations, revocation. An `ok` Card carries neither.
 */
export interface VerifyCardResult extends RefusalCoding {
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
   * Present when the card declares `revocation`. The checker's answer is read as
   * `evaluateRevocationChain` reads one: only a literal `revoked: false` passes and only a literal
   * `fresh: true` is fresh. An answer that could not be read is reported as revoked and not fresh,
   * with the `reason`; a revoked Card carries the `reason` its checker gave, when it gave one, bounded
   * as `evaluateRevocationChain` bounds it, and the `code` of why it is revoked: the checker's own,
   * `delegation_revoked` when it gave none, `deadline_exceeded` for a checker that did not answer in
   * time, `status_unavailable` for one whose answer could not be read or that threw, and
   * `configuration_error`, with the `reason`, when no `statusListChecker` was supplied.
   */
  revocation?: CardRevocation;
  /** Echoes `deps.cimdKeyProven` — the caller's L1 CIMD key-possession evidence. */
  cimdKeyProven?: boolean;
}

/**
 * Verify a resolved card: recompute capabilities + accountability + attestations + the live proof
 * + revocation via the injected seams, and RECOMPUTE the conformance level. The card's
 * self-declared `conformanceLevel` is ignored. `ok` is true iff every claim that is *present*
 * verified (a card with only self-declared capabilities is still `ok` — it is just L1); a per-request
 * proof affects the LEVEL, not `ok`, but a revoked card credential fails closed (`ok:false`, L1), and
 * so does a card that declares `revocation` when no `statusListChecker` is supplied to check it.
 */
export async function verifyCard(card: EntityCard, deps: VerifyCardDeps): Promise<VerifyCardResult> {
  const trustedIssuers = deps.trustedIssuers ?? DEFAULT_TRUSTED_ISSUERS;
  const timeoutMs = dependencyTimeout(deps.dependencyTimeoutMs);
  assertTrustedRootIssuers(deps.trustedRootIssuers, 'VerifyCardDeps.');
  const check = await checkCapabilities(card, deps, trustedIssuers, timeoutMs);
  const proof = await recomputeProof(deps, timeoutMs);
  const proofDid = proof?.ok ? proof.did : undefined;
  // A proof lifts the level only when the Card's own DID signed it: a valid proof by any other DID
  // shows possession of that DID's key, not the Card's. The join still gets the signer's DID.
  const holderProven = proofDid !== undefined && sameDid(proofDid, card.id);

  const party = await checkAccountability(card, deps, trustedIssuers, proofDid, timeoutMs);
  const accountability = party?.reported;
  const attested = await checkAttestations(card, deps, trustedIssuers, timeoutMs);
  const attestations = attested.map((claim) => claim.reported);
  const revocation = await checkCardRevocation(card, deps.statusListChecker, verifiedRoot(accountability, deps.trustedRootIssuers), timeoutMs);

  // The Card is ok exactly when no claim it makes was refused, and each refusal carries its code.
  const refused = decidingRefusal([
    ...(party?.refusal ? [party.refusal] : []),
    ...attested.flatMap((claim) => (claim.refusal ? [claim.refusal] : [])),
    ...(revocation.revoked ? [revocation] : []),
  ]);

  return {
    ok: refused === undefined,
    ...(refused === undefined ? {} : coded(refused.code)),
    entityType: card.entityType,
    conformanceLevel: deriveConformanceLevel(
      demoteOnRevocation(check, revocation.revoked),
      holderProven,
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
