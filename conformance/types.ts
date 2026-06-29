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

/** Categories a vector can target. One adapter method per category. */
export type VectorCategory =
  | 'signed-proof'
  | 'delegation-chain'
  | 'status-list'
  | 'did-key-resolution'
  | 'did-web-resolution';

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
}
