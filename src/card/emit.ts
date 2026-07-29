/**
 * KYA-OS Entity Card — EMIT discovery surfaces.
 *
 * "Discover like everyone": one canonical `EntityCard` PROJECTED onto every rail the
 * ecosystem already indexes. These are pure, deterministic projections (no I/O, no crypto)
 * of a single card — each one references the SAME canonical `card.json` endpoint on the
 * entity's `did:web` DID document, so a verifier always lands back on one source of truth:
 *
 *   - `toDidServiceEntry`  — the `KyaOsEntityCard` service entry that ANCHORS the card on
 *     the DID document (the canonical home);
 *   - `toServerCardMeta`   — MCP `server.json` / catalog `_meta['org.kya-os/card']` (inline
 *     summary, or `{ byRef }` → a lazy-fetch `cardRef`);
 *   - `toCatalogEntry`     — a `/.well-known/mcp/catalog.json` INDEX row (always by-ref);
 *   - `toA2AExtension`     — an A2A `AgentCard.capabilities.extensions[]` entry (agents only,
 *     `required:false` IS the graceful-degradation contract);
 *   - `toAgentFacts`       — a NANDA AgentFacts JSON-LD projection (we POPULATE `owner` from
 *     `responsibleParty`, never re-claim it; our axes live under the `kya:` context).
 *
 * The per-request holder-of-key proof is NEVER projected here — it rides per-request `_meta`.
 * A stripped `_meta` degrades to a fetch, never a failure.
 */

import {
  didWebToCardUrl,
  KYA_OS_CARD_META_KEY,
  KYA_OS_CARD_REF_KEY,
  KYA_OS_CARD_SERVICE_ID,
  KYA_OS_CARD_SERVICE_TYPE,
} from './resolve.js';
import {
  capabilityNames,
  PROOF_PROFILE_ID,
  type ProofProfile,
  type BitstringStatusListEntry,
  type EntityCard,
  type EntityType,
} from './schema.js';

/**
 * Shared emit option: override the card.json URL the web-anchored projections point at. Lets a
 * BARE `did:web` org root (which has no path-derived card path) publish via the shipped helpers,
 * or point at a non-conventional home. Defaults to `didWebToCardUrl(card.id)` — the well-known
 * path for a bare root, `/…/card.json` for a path-form DID.
 */
export interface CardUrlOverride {
  serviceEndpoint?: string;
}

/** A2A extension URI for the entity-card surface (version pinned IN the URI). */
export const A2A_ENTITY_CARD_EXT_URI = 'https://kya-os.org/a2a/ext/entity-card/v1';
/** Human-readable description carried on the A2A extension entry. */
export const A2A_ENTITY_CARD_EXT_DESCRIPTION = 'KYA-OS typed DID-anchored holder-of-key identity';
/** JSON-LD `@context` namespace for the uniquely-ours AgentFacts axes. */
export const AGENTFACTS_KYA_CONTEXT = 'https://kya-os.org/ns/agentfacts/v1#';
/** The per-request holder-of-key proof profile a card advertises (named, never inlined). */
export const PROOF_PROFILE = PROOF_PROFILE_ID;

// ── Shapes ──────────────────────────────────────────────────────────────────

/** A W3C DID-document `service[]` entry anchoring the card. */
export interface DidServiceEntry {
  id: string;
  type: string;
  serviceEndpoint: string;
}

/**
 * Inline projection of a card for `_meta` indexing. Carries the identity axes AND the
 * trust-bearing POINTERS — `delegationRef` (the proof for the `responsibleParty` claim) and
 * `revocation` (the post-issuance kill switch) — so the projection stays self-verifiable and can
 * never be mistaken for a clean card once a trust field is stripped. `resolveCard` DEREFERENCES
 * the summary to the canonical `card.json` (the summary is an index, not the authority), but
 * carrying these pointers keeps the index honest for any consumer that reads it directly:
 * emitting the `responsibleParty` claim WITHOUT its `delegationRef` proof, or dropping
 * `revocation`, is exactly the asymmetry that would let a revoked card look live.
 */
export interface EntityCardSummary {
  id: string;
  entityType: EntityType;
  name: string;
  capabilities?: string[];
  responsibleParty?: string;
  delegationRef?: string;
  proofProfile?: string;
  revocation?: BitstringStatusListEntry;
}

/** The lazy-fetch alternative to an inline summary inside `org.kya-os/card`. */
export type CardRefValue = { 'org.kya-os/cardRef': string };

/** The `_meta` fragment carrying the card on an MCP server.json / catalog surface. */
export type ServerCardMeta = Record<typeof KYA_OS_CARD_META_KEY, EntityCardSummary | CardRefValue>;

/** A catalog.json INDEX row (always by-ref for lazy fetch). */
export interface CatalogEntry {
  name: string;
  _meta: ServerCardMeta;
}

/** An A2A `AgentCard.capabilities.extensions[]` entry. */
export interface A2AExtension {
  uri: string;
  description: string;
  required: boolean;
  params: {
    id: string;
    entityType: 'agent';
    cardUrl: string;
    /** Emitted only when the card DECLARES a proof profile — consistent with the other rails. */
    proofProfile?: ProofProfile;
  };
}

/** A NANDA AgentFacts JSON-LD projection. */
export interface AgentFacts {
  '@context': { kya: string };
  id: string;
  agent_name: string;
  'kya:entityType': EntityType;
  owner?: string;
  capabilities?: string[];
  'kya:conformanceLevel'?: string;
  'kya:proofProfile'?: string;
  'kya:delegationRef'?: string;
}

// ── Projections ─────────────────────────────────────────────────────────────

/**
 * The `KyaOsEntityCard` DID-document service entry — the card's canonical home. `opts.serviceEndpoint`
 * overrides the derived URL so a bare `did:web` org root (or a non-conventional home) can anchor its
 * entry explicitly; otherwise it defaults to `didWebToCardUrl(card.id)`.
 */
export function toDidServiceEntry(card: EntityCard, opts: CardUrlOverride = {}): DidServiceEntry {
  return {
    id: KYA_OS_CARD_SERVICE_ID,
    type: KYA_OS_CARD_SERVICE_TYPE,
    serviceEndpoint: opts.serviceEndpoint ?? didWebToCardUrl(card.id),
  };
}

/** The MCP `server.json` / catalog `_meta['org.kya-os/card']` fragment (inline, or by-ref). */
export function toServerCardMeta(
  card: EntityCard,
  opts: CardUrlOverride & { byRef?: boolean } = {},
): ServerCardMeta {
  const value: EntityCardSummary | CardRefValue = opts.byRef
    ? { [KYA_OS_CARD_REF_KEY]: opts.serviceEndpoint ?? didWebToCardUrl(card.id) }
    : cardSummary(card);
  return { [KYA_OS_CARD_META_KEY]: value };
}

/** A catalog.json INDEX row — by-ref so the index stays cheap and the card lazy-fetches. */
export function toCatalogEntry(card: EntityCard): CatalogEntry {
  return { name: card.name, _meta: toServerCardMeta(card, { byRef: true }) };
}

/**
 * An A2A AgentExtension entry. Scoped to `entityType:'agent'` (the only A2A principal) and
 * fail-closed otherwise. `required:false` (the default) IS the graceful-degradation contract:
 * an unaware peer ignores the extension instead of rejecting the AgentCard. `proofProfile` is
 * emitted ONLY when the card declares one — the same gate as `_meta` and AgentFacts, so all four
 * projections advertise the proof posture consistently (never A2A-only).
 */
export function toA2AExtension(
  card: EntityCard,
  opts: CardUrlOverride & { required?: boolean } = {},
): A2AExtension {
  if (card.entityType !== 'agent') {
    throw new Error(
      `toA2AExtension: the A2A AgentExtension is scoped to entityType "agent" (got "${card.entityType}")`,
    );
  }
  const params: A2AExtension['params'] = {
    id: card.id,
    entityType: 'agent',
    cardUrl: opts.serviceEndpoint ?? didWebToCardUrl(card.id),
  };
  if (card.proofProfile !== undefined) params.proofProfile = card.proofProfile;
  return {
    uri: A2A_ENTITY_CARD_EXT_URI,
    description: A2A_ENTITY_CARD_EXT_DESCRIPTION,
    required: opts.required ?? false,
    params,
  };
}

/**
 * A NANDA AgentFacts JSON-LD projection. We POPULATE NANDA's shipped `owner` slot from
 * `responsibleParty` (we do not re-claim it); the uniquely-ours axes live under the `kya:`
 * context. Optional fields are omitted when absent (claim-minimalism, deterministic output).
 */
export function toAgentFacts(card: EntityCard): AgentFacts {
  const facts: AgentFacts = {
    '@context': { kya: AGENTFACTS_KYA_CONTEXT },
    id: card.id,
    agent_name: card.name,
    'kya:entityType': card.entityType,
  };
  if (card.responsibleParty !== undefined) facts.owner = card.responsibleParty;
  if (card.capabilities !== undefined) facts.capabilities = capabilityNames(card.capabilities);
  if (card.conformanceLevel !== undefined) facts['kya:conformanceLevel'] = card.conformanceLevel;
  if (card.proofProfile !== undefined) facts['kya:proofProfile'] = card.proofProfile;
  if (card.delegationRef !== undefined) facts['kya:delegationRef'] = card.delegationRef;
  return facts;
}

// ── Internals ───────────────────────────────────────────────────────────────

/**
 * Inline summary: identity + type + capability names, PLUS the trust-bearing pointers
 * (`delegationRef` proves the `responsibleParty` claim; `revocation` is the kill switch). Carrying
 * both closes the claim-without-proof asymmetry so the projection is self-verifiable and never
 * fails open on a revoked card. Still a valid card (all fields optional), but `resolveCard`
 * dereferences it to the canonical `card.json` rather than trusting it.
 */
function cardSummary(card: EntityCard): EntityCardSummary {
  const summary: EntityCardSummary = { id: card.id, entityType: card.entityType, name: card.name };
  if (card.capabilities !== undefined) summary.capabilities = capabilityNames(card.capabilities);
  if (card.responsibleParty !== undefined) summary.responsibleParty = card.responsibleParty;
  if (card.delegationRef !== undefined) summary.delegationRef = card.delegationRef;
  if (card.proofProfile !== undefined) summary.proofProfile = card.proofProfile;
  if (card.revocation !== undefined) summary.revocation = card.revocation;
  return summary;
}
