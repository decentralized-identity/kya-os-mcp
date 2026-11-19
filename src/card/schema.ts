import * as z from 'zod';
import { DID_MAX_LENGTH, didPattern, whyNotDid } from '../utils/did-syntax.js';

/**
 * Zod schema for the KYA-OS Entity Card — the runtime source of truth, mirroring
 * `schemas/kya-os-card.schema.json` (the published JSON Schema). Types are derived
 * via `z.infer`, matching the package convention (see `src/authz/requirement.ts`).
 */

/** The DID methods a Card's DID members take (SPEC-ENTITY-CARD.md §5.1), in the order a refusal lists them. */
export const CARD_DID_METHODS = ['key', 'web'] as const;

/** What a refusal of {@link Did} says should the DID rule name no reason, which it names for every value either check of `Did` refuses. */
const NOT_A_DID = 'is not a DID';

/** The reason {@link Did} refuses the value of `issue` for: the one `whyNotDid` gives it. */
function refusalOf(issue: { readonly input: unknown }): string {
  return whyNotDid(issue.input, CARD_DID_METHODS) ?? NOT_A_DID;
}

/**
 * A DID of a method a Card takes ({@link CARD_DID_METHODS}), as W3C DID Core §3.1 writes one, so never
 * a DID URL, which adds a path, query or fragment: the one source of the DID shape, imported and never
 * declared again. Its `regex` check makes `z.toJSONSchema` emit the `pattern` the published schema
 * gives each DID member. A `max` check comes first and ends the parse of a value longer than
 * `DID_MAX_LENGTH`, so the pattern is never tested against one; it is the library's own bound, which
 * the published schema does not state, and `z.toJSONSchema` emits it as `maxLength`. Each check refuses
 * a value with the reason `whyNotDid` gives, which is decided by the value alone and so may be shown to
 * whoever presented it.
 */
export const Did = z
  .string()
  .max(DID_MAX_LENGTH, { abort: true, error: refusalOf })
  .regex(didPattern(CARD_DID_METHODS), { error: refusalOf });

export const EntityTypeSchema = z.enum(['mcp', 'agent', 'client', 'verifier', 'human']);

export const ConformanceLevelSchema = z.enum(['L1', 'L2', 'L3']);

export const Ed25519PublicJwkSchema = z
  .object({
    kty: z.literal('OKP'),
    crv: z.literal('Ed25519'),
    x: z.string(),
    kid: z.string().optional(),
    use: z.string().optional(),
  })
  .strict();

/** A P-256 public JWK — the ES256 (ECDSA, FIPS-eligible) proof-signing key. */
export const P256PublicJwkSchema = z
  .object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: z.string(),
    y: z.string(),
    kid: z.string().optional(),
    use: z.string().optional(),
  })
  .strict();

/** A proof-signing public JWK: Ed25519 (EdDSA) or P-256 (ES256) — the two profile algorithms. */
export const ProofPublicJwkSchema = z.union([Ed25519PublicJwkSchema, P256PublicJwkSchema]);

/** A Verifiable Credential — a compact VC-JWT string or a pre-parsed object. */
const VcValue = z.union([z.string(), z.record(z.string(), z.unknown())]);

/**
 * Deliberately NON-strict: the JSON Schema marks `CapabilityAttestation` as
 * `additionalProperties: true`, so extra keys alongside `vc` are permitted here — and PRESERVED.
 * A plain `z.object` strips unknown keys, which would hand the capability verifier an attestation
 * missing sidecar members it may need (a `credentialStatus`, say).
 */
export const CapabilityAttestationSchema = z
  .object({
    vc: VcValue,
  })
  .passthrough();

export const Level2CapabilitySchema = z
  .object({
    name: z.string().min(1),
    attestations: z.array(CapabilityAttestationSchema).min(1),
  })
  .strict();

/** L1 bare-string name, or an L2 object carrying attestations. */
export const CapabilitySchema = z.union([z.string().min(1), Level2CapabilitySchema]);

export const AttestationSchema = z
  .object({
    type: z.enum(['IdentityVerification', 'CapabilityAttestation']),
    vc: VcValue,
    subject: Did.optional(),
    issuer: Did.optional(),
  })
  .strict();

/** The canonical per-request proof profile id — the ONE source of truth every consumer
 *  references (the proof's `prf` tag, its `_meta` key, and the card's `proofProfile` field). */
export const PROOF_PROFILE_ID = 'org.kya-os/proof.v1';

/**
 * The profile id of the earlier draft (`proof@1`), replaced because the `@`
 * spelling collided with MCP's `_meta` key grammar and duplicated the version
 * the `prf` field already carries. Verifiers accept it (in `prf` and in
 * `proofProfile`) for one major version; producers emit only
 * {@link PROOF_PROFILE_ID}.
 */
export const LEGACY_PROOF_PROFILE_ID = 'org.kya-os/proof@1';

/**
 * Self-declared per-request holder-of-key proof profile. A card carrying this advertises
 * that its requests ride the stateless, sender-constrained `org.kya-os/proof.v1` envelope
 * (distinct from the legacy session-bound ProofMeta). The proof itself is NEVER on the
 * static card — it rides per-request `_meta`; this field only names the profile.
 */
export const ProofProfileSchema = z.union([
  z.literal(PROOF_PROFILE_ID),
  z.literal(LEGACY_PROOF_PROFILE_ID),
]);

/**
 * CIMD (draft-ietf-oauth-client-id-metadata-document) binding — the L1 on-ramp
 * coordinates. `clientId` is the `did:web` HTTPS form; `jwksUri` is the DID-keyed JWKS the
 * AS validates `private_key_jwt` against (so OAuth client-auth IS a DID-key proof).
 */
export const CimdBindingSchema = z
  .object({
    clientId: z.string().min(1),
    jwksUri: z.string().min(1),
  })
  .strict();

/**
 * The members by which a W3C Bitstring Status List v1.0 entry states how wide its status is, as its
 * section 2.1 has them: `statusSize`, the size of the entry in bits, an integer greater than zero
 * (an entry that states none is one bit wide), and `statusMessage`, an array that gives each value
 * of the entry a `status`, written as a hexadecimal string, and a `message`. A Card's entry and a
 * delegation hop's share them. They are kept so that a status-list reader sees the size the entry
 * states: one that reads one bit per entry refuses an entry of any other size. Section 2.1 also
 * has an entry of more than one bit state a `statusMessage`, with one element for each value its
 * size allows; the schema does not check either, since every reader refuses such an entry.
 */
export const statusEntrySizeShape = {
  statusSize: z.number().int().positive().optional(),
  statusMessage: z.array(z.object({ status: z.string(), message: z.string() }).passthrough()).optional(),
};

/**
 * W3C Bitstring Status List v1.0 `credentialStatus` entry — the StatusList2021
 * SUCCESSOR. `statusListIndex` is an integer expressed as a string (per the spec).
 */
export const BitstringStatusListEntrySchema = z
  .object({
    statusListCredential: z.string().min(1),
    statusListIndex: z.string().regex(/^[0-9]+$/, 'statusListIndex must be a canonical non-negative decimal'),
    ...statusEntrySizeShape,
  })
  .strict();

export const EntityCardSchema = z
  .object({
    id: Did,
    entityType: EntityTypeSchema,
    name: z.string().min(1),
    kid: z.string().optional(),
    publicKeyJwk: Ed25519PublicJwkSchema.optional(),
    createdAt: z.string().optional(),
    capabilities: z.array(CapabilitySchema).optional(),
    /** DERIVED summary — never trusted on input (a verifier recomputes it). */
    conformanceLevel: ConformanceLevelSchema.optional(),
    responsibleParty: Did.optional(),
    principal: Did.optional(),
    delegationRef: z.string().optional(),
    attestations: z.array(AttestationSchema).optional(),
    didDocument: z.string().optional(),
    /** Names the per-request holder-of-key proof profile this entity's requests carry. */
    proofProfile: ProofProfileSchema.optional(),
    /** L1 CIMD on-ramp coordinates (client_id ↔ did:web, jwks_uri ↔ DID keys). */
    cimd: CimdBindingSchema.optional(),
    /** W3C Bitstring Status List v1.0 revocation entry for this card's credential. */
    revocation: BitstringStatusListEntrySchema.optional(),
  })
  // Mirrors `additionalProperties: false` on the published JSON Schema: a conformant
  // Card MUST NOT carry unknown top-level properties (SPEC §7). Reject, never strip.
  .strict();

export type EntityType = z.infer<typeof EntityTypeSchema>;
export type ConformanceLevel = z.infer<typeof ConformanceLevelSchema>;
export type Ed25519PublicJwk = z.infer<typeof Ed25519PublicJwkSchema>;
export type P256PublicJwk = z.infer<typeof P256PublicJwkSchema>;
/** The proof-signing key type — Ed25519 or P-256 (discriminated by `kty`/`crv`). */
export type ProofPublicJwk = z.infer<typeof ProofPublicJwkSchema>;
export type CapabilityAttestation = z.infer<typeof CapabilityAttestationSchema>;
export type Level2Capability = z.infer<typeof Level2CapabilitySchema>;
export type Capability = z.infer<typeof CapabilitySchema>;
export type Attestation = z.infer<typeof AttestationSchema>;
export type ProofProfile = z.infer<typeof ProofProfileSchema>;
export type CimdBinding = z.infer<typeof CimdBindingSchema>;
export type BitstringStatusListEntry = z.infer<typeof BitstringStatusListEntrySchema>;
export type EntityCard = z.infer<typeof EntityCardSchema>;

/** Flatten capabilities (bare strings or attested objects) to their names. */
export function capabilityNames(caps: Capability[]): string[] {
  return caps.map((c) => (typeof c === 'string' ? c : c.name));
}
