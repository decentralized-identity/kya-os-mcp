/**
 * KYA-OS Entity Card — fluent BUILDER (the 10-minute adoption path).
 *
 * `card({ did, entityType, name })` opens a fluent chain that accumulates declared facts and
 * `.build()`s them into an `EntityCard` — a thin, ergonomic front over {@link buildCard} that
 * hides the card shape behind readable, self-documenting calls:
 *
 *   card({ did, entityType: 'agent', name: 'Acme Pay' })
 *     .capability('search')                              // L1 bare-string capability
 *     .attestedCapability('payments.transfer', vc)       // L2 attested capability (VC-backed)
 *     .accountableTo('did:web:acme.example', { via: 'vc_root>del_123' })
 *     .build();
 *
 * Claim-minimal like `buildCard`: it asserts only identity + type + declared capabilities +
 * accountability locators; trust-bearing claims are PROVEN by the referenced credentials, not
 * minted here. The infrastructure coordinates it can ALSO carry — `.usesProof()` (proof profile),
 * `.cimd()`, `.revocation()`, `.didDocument()`, `.publicKey()` — are self-descriptive pointers, not
 * credential-proven claims, so the ergonomic path can emit a card that plugs into the proof / CIMD /
 * revocation machinery. `conformanceLevel` is intentionally never set — a verifier RECOMPUTES it.
 * Pure, no I/O, no crypto: no runtime (`mcp-i-core`) dependency leaks in.
 */

import { buildCard, type CardIdentity } from './build.js';
import { PROOF_PROFILE_ID } from './schema.js';
import type {
  Attestation,
  BitstringStatusListEntry,
  Capability,
  CapabilityAttestation,
  CimdBinding,
  Ed25519PublicJwk,
  EntityCard,
  EntityType,
  Level2Capability,
  ProofProfile,
} from './schema.js';

/** The single proof profile a KYA-OS card advertises (holder-of-key, per-request `_meta`). */
const KYA_OS_PROOF_PROFILE: ProofProfile = PROOF_PROFILE_ID;

/** A Verifiable Credential value (a compact VC-JWT string or a pre-parsed object). */
export type VcInput = CapabilityAttestation['vc'];

/** The identity + type coordinates a card chain opens with. */
export interface CardBuilderInit {
  did: string;
  entityType: EntityType;
  name: string;
  kid?: string;
  createdAt?: string;
}

/** Accountability locators for `accountableTo`: the delegation chain (`via`) + human `principal`. */
export interface AccountableToOptions {
  /** Compact delegation-chain locator (`delegationRef`, e.g. `vc_root>del_123`) — resolved, not inlined. */
  via?: string;
  /** The immediate human delegator DID (`principal`), when distinct from the responsible party. */
  principal?: string;
}

/**
 * A fluent accumulator over one card's declared facts. Mutable + chainable (each method returns
 * `this`); `.build()` projects the accumulated facts through {@link buildCard}. Prefer the `card()`
 * factory over `new CardBuilder(...)`.
 */
export class CardBuilder {
  private readonly identity: CardIdentity;
  private readonly entityType: EntityType;
  private readonly name: string;
  private readonly capabilities: Capability[] = [];
  private readonly attestations: Attestation[] = [];
  private responsibleParty?: string;
  private principal?: string;
  private delegationRef?: string;
  private proofProfile?: ProofProfile;
  private cimdBinding?: CimdBinding;
  private revocationEntry?: BitstringStatusListEntry;
  private didDocumentUrl?: string;
  private publicKeyJwk?: Ed25519PublicJwk;

  constructor(init: CardBuilderInit) {
    this.identity = { did: init.did };
    if (init.kid !== undefined) this.identity.kid = init.kid;
    if (init.createdAt !== undefined) this.identity.createdAt = init.createdAt;
    this.entityType = init.entityType;
    this.name = init.name;
  }

  /** Declare an L1 bare-string capability (self-asserted; a verifier floors it at L1). */
  capability(name: string): this {
    this.capabilities.push(name);
    return this;
  }

  /**
   * Declare an L2 capability backed by an attestation VC. Repeated calls for the SAME capability
   * name accumulate onto its `attestations[]` (one capability, several proofs) rather than
   * duplicating the entry.
   */
  attestedCapability(name: string, vc: VcInput): this {
    const existing = this.findAttested(name);
    if (existing) existing.attestations.push({ vc });
    else this.capabilities.push({ name, attestations: [{ vc }] });
    return this;
  }

  /**
   * Attach a standalone attestation (e.g. a KYC/KYB `IdentityVerification` VC on the responsible
   * party) that is not tied to a single capability.
   */
  attestation(attestation: Attestation): this {
    this.attestations.push(attestation);
    return this;
  }

  /**
   * Declare the accountability edge: `responsibleParty` is the ultimately-accountable root (a
   * KYC-able org), `opts.via` the compact `delegationRef` chain locator, and `opts.principal` the
   * immediate human delegator. A verifier RECOMPUTES this edge (delegationRef → responsibleParty).
   */
  accountableTo(responsibleParty: string, opts: AccountableToOptions = {}): this {
    this.responsibleParty = responsibleParty;
    if (opts.via !== undefined) this.delegationRef = opts.via;
    if (opts.principal !== undefined) this.principal = opts.principal;
    return this;
  }

  /**
   * Advertise the per-request holder-of-key proof profile (`org.kya-os/proof.v1`). This only NAMES
   * the profile — the proof itself is never on the static card; it rides per-request `_meta`.
   */
  usesProof(): this {
    this.proofProfile = KYA_OS_PROOF_PROFILE;
    return this;
  }

  /** Bind the L1 CIMD on-ramp coordinates (`client_id` ⇄ `did:web`, `jwks_uri` ⇄ DID keys). */
  cimd(binding: CimdBinding): this {
    this.cimdBinding = binding;
    return this;
  }

  /** Attach the W3C Bitstring Status List revocation entry (the post-issuance kill switch). */
  revocation(entry: BitstringStatusListEntry): this {
    this.revocationEntry = entry;
    return this;
  }

  /** Record the entity's DID document URL (where the `KyaOsEntityCard` service entry lives). */
  didDocument(url: string): this {
    this.didDocumentUrl = url;
    return this;
  }

  /** Inline the entity's Ed25519 public JWK (the card's self-contained verification key). */
  publicKey(jwk: Ed25519PublicJwk): this {
    this.publicKeyJwk = jwk;
    return this;
  }

  /** Project the accumulated facts into an `EntityCard` (via {@link buildCard}). */
  build(): EntityCard {
    return buildCard(this.identity, {
      entityType: this.entityType,
      name: this.name,
      ...(this.capabilities.length > 0 ? { capabilities: this.capabilities } : {}),
      ...(this.attestations.length > 0 ? { attestations: this.attestations } : {}),
      ...(this.responsibleParty !== undefined ? { responsibleParty: this.responsibleParty } : {}),
      ...(this.principal !== undefined ? { principal: this.principal } : {}),
      ...(this.delegationRef !== undefined ? { delegationRef: this.delegationRef } : {}),
      ...(this.proofProfile !== undefined ? { proofProfile: this.proofProfile } : {}),
      ...(this.cimdBinding !== undefined ? { cimd: this.cimdBinding } : {}),
      ...(this.revocationEntry !== undefined ? { revocation: this.revocationEntry } : {}),
      ...(this.didDocumentUrl !== undefined ? { didDocument: this.didDocumentUrl } : {}),
      ...(this.publicKeyJwk !== undefined ? { publicKeyJwk: this.publicKeyJwk } : {}),
    });
  }

  /** Find an already-declared attested capability by name (for attestation accumulation). */
  private findAttested(name: string): Level2Capability | undefined {
    return this.capabilities.find(
      (c): c is Level2Capability => typeof c !== 'string' && c.name === name,
    );
  }
}

/** Open a fluent card-building chain (the ergonomic entry point). */
export function card(init: CardBuilderInit): CardBuilder {
  return new CardBuilder(init);
}
