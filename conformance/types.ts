/**
 * KYA-OS Conformance Harness — shared types and the implementation-agnostic
 * adapter contract.
 *
 * The harness is independent of the reference implementation: it reads versioned
 * JSON test vectors (`conformance/vectors/*.json`) and runs each one through a
 * {@link ConformanceAdapter}. A third party brings their OWN implementation by
 * implementing this single interface — every primitive a vector exercises maps to
 * one adapter method. The reference adapter
 * ({@link ./reference-adapter.ReferenceConformanceAdapter}) wires these methods to
 * `@kya-os/mcp`'s PUBLIC verify primitives and does not fork their logic.
 *
 * See CONFORMANCE.md § "Running the harness against your implementation".
 */

/**
 * Categories a vector can target. One adapter method per category.
 *
 * The first five exercise the LEGACY session-bound primitives (detached
 * `ProofMeta`, `DelegationCredential` + StatusList2021, the DID resolvers). The
 * last two exercise the NEWER Entity Card layer — the stateless
 * `org.kya-os/proof@1` holder-of-key proof (`card-proof`) and the typed,
 * DID-anchored card (`entity-card`) — which is a distinct, orthogonal profile.
 */
export type VectorCategory =
  | 'signed-proof'
  | 'delegation-chain'
  | 'status-list'
  | 'did-key-resolution'
  | 'did-web-resolution'
  | 'card-proof'
  | 'entity-card'
  | 'audit-integrity';

/** The outcome a conformant implementation MUST produce for a vector. */
export type ExpectedOutcome = 'pass' | 'fail';

/**
 * A single, self-contained conformance vector. `input` is category-specific and
 * carries fully-formed, pre-signed artifacts so the vector is reproducible
 * against ANY implementation without re-signing.
 */
export interface ConformanceVector {
  /** Stable, unique id (e.g. `signed-proof/valid-basic`). */
  id: string;
  /** Which adapter method verifies this vector. */
  category: VectorCategory;
  /** Human-readable description of what the vector exercises. */
  description: string;
  /** Whether a conformant verifier MUST accept (`pass`) or reject (`fail`). */
  expected: ExpectedOutcome;
  /** Why the expected outcome holds (the security property under test). */
  reason: string;
  /** Category-specific input. Validated structurally by the loader. */
  input: unknown;
}

/** A versioned file of vectors as stored on disk under `conformance/vectors/`. */
export interface VectorFile {
  /** Vector-format version (semver). Bump on a breaking input-shape change. */
  version: string;
  /** Category every vector in this file targets. */
  category: VectorCategory;
  vectors: ConformanceVector[];
}

/**
 * The result an adapter returns for a single vector. `pass`/`fail` mirrors the
 * vector's `expected`; the runner compares them.
 */
export interface AdapterResult {
  /** `pass` = the implementation ACCEPTED the artifact; `fail` = it REJECTED it. */
  outcome: ExpectedOutcome;
  /** Optional human-readable reason (especially useful on rejection). */
  detail?: string;
}

// ── Category-specific input shapes ────────────────────────────────────────────
// These are the wire shapes embedded in the JSON vectors. They are intentionally
// minimal and JSON-serializable so any implementation can consume them.

export interface SignedProofInput {
  /** A DetachedProof: `{ jws, meta }`. */
  proof: unknown;
  /** The signer's Ed25519 public key in JWK form (`{ kty, crv, x, kid }`). */
  publicKeyJwk: { kty: string; crv: string; x: string; kid?: string };
  /** Reference epoch-seconds the verifier should treat as "now" (skew anchor). */
  now: number;
  /** Allowed timestamp skew in seconds for this vector. */
  skewSeconds: number;
}

export interface DelegationChainInput {
  /** The leaf DelegationCredential (signed). */
  leaf: unknown;
  /** Ancestors root→parent (signed), if the leaf is a re-delegation. */
  ancestors?: unknown[];
  /** The verifying server's DID; every credential's audience must include it. */
  serverDid: string;
  /** DID documents the verifier may resolve, keyed by DID. */
  didDocuments: Record<string, unknown>;
}

export interface StatusListInput {
  /** The DelegationCredential carrying a `credentialStatus`. */
  credential: unknown;
  /** The signed StatusList2021Credential the entry points at, keyed by its id. */
  statusLists: Record<string, unknown>;
  /** DID documents for signature verification, keyed by DID. */
  didDocuments: Record<string, unknown>;
  /** The verifying server's DID. */
  serverDid: string;
}

export interface DidResolutionInput {
  /** The DID to resolve. */
  did: string;
  /**
   * For did:web: the JSON the resolver's fetch should return for the DID's
   * well-known URL. Omitted for did:key (resolution is offline).
   */
  didDocument?: unknown;
}

/** An Ed25519 public key in JWK form, as embedded in a vector's resolver material. */
export interface Ed25519PublicJwkLike {
  kty: string;
  crv: string;
  x: string;
  kid?: string;
  use?: string;
}

/**
 * Input for the stateless Entity Card holder-of-key proof (`org.kya-os/proof@1`).
 * Carries the full, pre-signed proof plus the resolver material a verifier needs
 * to recompute every binding — the DID-keyed JWKS (the signer's public JWK[s]),
 * the recipient `expectedAudience`, and a pinned `now`/`skew` window. All fields
 * are JSON-serializable so the vector reproduces against any implementation.
 */
export interface CardProofInput {
  /**
   * The `org.kya-os/proof@1` proof object: `{ prf, alg, did, kid, audience,
   * nonce, created, expires, requestHash, cnf?, jws, httpSig? }`.
   */
  proof: unknown;
  /** The request the proof binds (`{ method, params? }`); `requestHash` MUST recompute to it. */
  request: { method: string; params?: unknown };
  /**
   * The DID-keyed JWKS the proof verifies against. `resolveKey` selects by `kid`;
   * `resolveDidKeys` (the RFC 7638 membership proof) selects every key the `did`
   * publishes (those whose `kid` DID-part equals the proof's `did`).
   */
  jwks: { keys: Ed25519PublicJwkLike[] };
  /** The verifier's own DID — the proof's `audience` MUST equal this (anti-relay). */
  expectedAudience: string;
  /** Reference epoch-MILLISECONDS the verifier treats as "now" (the freshness anchor). */
  nowMs: number;
  /** Accepted clock skew in seconds for the created/expires window. */
  skewSeconds: number;
  /** OPTIONAL access-token RFC 9449 `cnf.jkt` enabling the L3 fusion; omit for L3-minus. */
  tokenCnfJkt?: string;
  /**
   * When true, the verifier is invoked WITHOUT a replay (nonce) seam. A conformant verifier MUST
   * then fail closed (`nonce_seam_missing`) rather than skip the replay check — this catches an
   * implementation that silently omits the atomic nonce consumer.
   */
  omitNonceSeam?: boolean;
}

/** The delegation context a card with `responsibleParty` recomputes its accountability edge over. */
export interface EntityCardAccountabilityInput {
  /** Asserted issuer of the ROOT VC (the accountable resource owner). */
  resourceOwner: string;
  /** Asserted `invocationTarget` of the ROOT VC (the delegated resource). */
  resource?: string;
  /** The signed DelegationCredential chain, root → leaf. */
  chain: unknown[];
  /** The proof's `did` a verifier asserts equals the recomputed leaf invoker (the JOIN). */
  proofDid?: string;
  /** Epoch-ms the chain is verified at — pins the wall-clock expiry gate (deterministic vectors). */
  now?: number;
}

/**
 * Input for the typed, DID-anchored Entity Card. The card is `parseCard`-validated
 * (fail-closed on a malformed card) then `verifyCard`-recomputed. When the card
 * carries `responsibleParty`, `accountability` supplies the delegation chain +
 * context the accountability seam recomputes; `trustedIssuers`/`cimdKeyProven`
 * are the remaining serializable verify deps.
 */
export interface EntityCardInput {
  /** The EntityCard to parse + verify. */
  card: unknown;
  /** Trusted issuer allowlist (default: the implementation's own default). */
  trustedIssuers?: string[];
  /** For a card carrying `responsibleParty`: the delegation chain + context to recompute. */
  accountability?: EntityCardAccountabilityInput;
  /** Echoes the caller's CIMD L1 key-possession evidence. */
  cimdKeyProven?: boolean;
}

export interface AuditIntegrityInput {
  event: unknown;
  eventCanonical: string;
  eventDigest: `sha256:${string}`;
  /**
   * Optional free-form payload exercising the full admitted RFC 8785 value
   * space (fractional numbers, exponent boundaries, non-BMP object keys with
   * UTF-16 code-unit key ordering). Implementations must reproduce
   * `canonical` byte-for-byte from `value`.
   */
  canonicalization?: {
    value: unknown;
    canonical: string;
  };
  leaves: `sha256:${string}`[];
  root: `sha256:${string}`;
  inclusion: {
    leafIndex: number;
    auditPath: `sha256:${string}`[];
  };
  consistency: {
    oldSize: number;
    oldRoot: `sha256:${string}`;
    auditPath: `sha256:${string}`[];
  };
}

/**
 * The contract a third party implements to run the KYA-OS conformance vectors
 * against their own implementation.
 *
 * Each method takes a vector's `input` and returns whether the implementation
 * ACCEPTED (`pass`) or REJECTED (`fail`) the artifact. Methods MUST be
 * fail-closed: any error, malformed input, or unmet security property maps to
 * `{ outcome: 'fail' }` — they MUST NOT throw. The runner treats a thrown error
 * as a harness failure, not a rejection.
 */
export interface ConformanceAdapter {
  /** Implementation name, surfaced in the runner report. */
  readonly name: string;

  /** Verify a signed detached proof (signature + nonce + timestamp skew). */
  verifySignedProof(input: SignedProofInput): Promise<AdapterResult>;

  /** Verify a delegation credential and its full chain to the root. */
  verifyDelegationChain(input: DelegationChainInput): Promise<AdapterResult>;

  /** Verify a credential's StatusList2021 revocation status. */
  verifyStatusList(input: StatusListInput): Promise<AdapterResult>;

  /** Resolve a did:key DID to a usable Ed25519 verification method. */
  resolveDidKey(input: DidResolutionInput): Promise<AdapterResult>;

  /** Resolve a did:web DID to a usable Ed25519 verification method. */
  resolveDidWeb(input: DidResolutionInput): Promise<AdapterResult>;

  /**
   * Verify a stateless `org.kya-os/proof@1` holder-of-key proof: recompute the
   * signature, `requestHash`, `audience`, nonce freshness, `created`/`expires`
   * window, the `kid`⇄`did` binding, and the DID-key membership.
   */
  verifyCardProof(input: CardProofInput): Promise<AdapterResult>;

  /**
   * Parse + verify a typed Entity Card: reject a malformed card, then recompute
   * accountability / attestations / revocation and the conformance level.
   */
  verifyEntityCard(input: EntityCardInput): Promise<AdapterResult>;

  /** Verify RFC 9162 audit root, inclusion, and consistency proof vectors. */
  verifyAuditIntegrity(input: AuditIntegrityInput): Promise<AdapterResult>;
}
