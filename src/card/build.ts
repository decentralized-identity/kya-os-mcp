/**
 * KYA-OS Entity Card — EMIT.
 *
 * `buildCard` projects this entity's identity + declared facts into a card. Pure,
 * claim-minimal: it asserts only identity + type + declared capabilities (trust-bearing
 * claims are proven by the referenced credentials, not minted here). `conformanceLevel`
 * is intentionally omitted — it is a derived value a verifier recomputes.
 */

import type {
  Attestation,
  BitstringStatusListEntry,
  Capability,
  CimdBinding,
  Ed25519PublicJwk,
  EntityCard,
  EntityType,
  ProofProfile,
} from './schema.js';

export interface BuildCardFacts {
  entityType: EntityType;
  name: string;
  capabilities?: Capability[];
  responsibleParty?: string;
  principal?: string;
  delegationRef?: string;
  attestations?: Attestation[];
  didDocument?: string;
  /** Card's Ed25519 public JWK (for a card that inlines its verification key). */
  publicKeyJwk?: Ed25519PublicJwk;
  /** Names the per-request holder-of-key proof profile this entity's requests carry. */
  proofProfile?: ProofProfile;
  /** L1 CIMD on-ramp coordinates (client_id ⇄ did:web, jwks_uri ⇄ DID keys). */
  cimd?: CimdBinding;
  /** W3C Bitstring Status List revocation entry (the post-issuance kill switch). */
  revocation?: BitstringStatusListEntry;
}

/** Minimal identity shape this helper needs (structurally compatible with `Identity`). */
export interface CardIdentity {
  did: string;
  kid?: string;
  createdAt?: string;
}

/**
 * Build this entity's card from its identity + declared facts. Pure. Asserts only
 * identity + type + declared capabilities (claim-minimalism — trust-bearing claims are
 * proven by the referenced credentials, not minted here). `conformanceLevel` is
 * intentionally omitted on emit: it is a derived value a verifier recomputes.
 */
export function buildCard(identity: CardIdentity, facts: BuildCardFacts): EntityCard {
  const card: EntityCard = {
    id: identity.did,
    entityType: facts.entityType,
    name: facts.name,
  };
  if (identity.kid !== undefined) card.kid = identity.kid;
  if (identity.createdAt !== undefined) card.createdAt = identity.createdAt;
  if (facts.capabilities !== undefined) card.capabilities = facts.capabilities;
  if (facts.responsibleParty !== undefined) card.responsibleParty = facts.responsibleParty;
  if (facts.principal !== undefined) card.principal = facts.principal;
  if (facts.delegationRef !== undefined) card.delegationRef = facts.delegationRef;
  if (facts.attestations !== undefined) card.attestations = facts.attestations;
  if (facts.didDocument !== undefined) card.didDocument = facts.didDocument;
  if (facts.publicKeyJwk !== undefined) card.publicKeyJwk = facts.publicKeyJwk;
  if (facts.proofProfile !== undefined) card.proofProfile = facts.proofProfile;
  if (facts.cimd !== undefined) card.cimd = facts.cimd;
  if (facts.revocation !== undefined) card.revocation = facts.revocation;
  return card;
}
