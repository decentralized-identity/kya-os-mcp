/**
 * ProofVerifier
 *
 * Centralized proof verification service that validates DetachedProof
 * signatures, enforces nonce replay protection, and checks timestamp skew.
 */

import { CryptoService, type Ed25519JWK } from "../utils/crypto-service.js";
import { CryptoProvider } from "../providers/base.js";
import { ClockProvider } from "../providers/base.js";
import { NonceCacheProvider } from "../providers/base.js";
import { FetchProvider } from "../providers/base.js";
import {
  validateDetachedProof,
  type DetachedProof,
  type MetaPolicy,
} from "../types/protocol.js";
import { canonicalizeJson } from "../utils/canonical-json.js";
import {
  ProofVerificationError,
  PROOF_VERIFICATION_ERROR_CODES,
  type ProofVerificationErrorCode,
} from "./errors.js";
import { logger } from "../logging/index.js";
import {
  buildProofJwsPayload,
  computeCanonicalHashes,
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
  RESPONSE_PROOF_PROFILE_V1,
  type ToolRequest,
  type ToolResponse,
} from "./generator.js";

export interface ProofVerificationResult {
  valid: boolean;
  reason?: string;
  error?: Error;
  errorCode?: ProofVerificationErrorCode;
  details?: Record<string, unknown>;
}

export interface ProofVerifierConfig {
  cryptoProvider: CryptoProvider;
  clockProvider: ClockProvider;
  nonceCacheProvider: NonceCacheProvider;
  fetchProvider: FetchProvider;
  timestampSkewSeconds?: number;
  nonceTtlSeconds?: number;
}

/** Default timestamp skew for proof verification (seconds) */
export const DEFAULT_CLOCK_SKEW_SECONDS = 120;
/** Minimum allowed clock skew (seconds) */
export const MIN_CLOCK_SKEW_SECONDS = 30;
/** Maximum allowed clock skew (seconds) */
export const MAX_CLOCK_SKEW_SECONDS = 600;

export class ProofVerifier {
  private cryptoService: CryptoService;
  private clock: ClockProvider;
  private nonceCache: NonceCacheProvider;
  private fetch: FetchProvider;
  private timestampSkewSeconds: number;
  private nonceTtlSeconds: number;
  private cryptoProvider: CryptoProvider;

  constructor(config: ProofVerifierConfig) {
    this.cryptoService = new CryptoService(config.cryptoProvider);
    this.cryptoProvider = config.cryptoProvider;
    this.clock = config.clockProvider;
    this.nonceCache = config.nonceCacheProvider;
    this.fetch = config.fetchProvider;
    this.timestampSkewSeconds = config.timestampSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    this.nonceTtlSeconds = config.nonceTtlSeconds ?? 300; // Default 5 minutes
  }

  /**
   * Update the timestamp skew from a server-advertised value.
   * Clients SHOULD call this with the server's clockSkewSeconds from /.well-known/mcp.
   * The value is clamped to [30, 600] seconds.
   *
   * @param skewSeconds - Server-advertised clock skew in seconds
   */
  setTimestampSkew(skewSeconds: number): void {
    if (typeof skewSeconds !== 'number' || !Number.isFinite(skewSeconds)) {
      return;
    }
    this.timestampSkewSeconds = Math.max(
      MIN_CLOCK_SKEW_SECONDS,
      Math.min(MAX_CLOCK_SKEW_SECONDS, Math.floor(skewSeconds))
    );
  }

  /**
   * Get the current timestamp skew setting.
   */
  getTimestampSkew(): number {
    return this.timestampSkewSeconds;
  }

  /**
   * Verify a DetachedProof.
   *
   * Reconstructs the canonical payload from proof.meta and checks the JWS
   * signature, nonce replay, and timestamp skew — proving the proof is AUTHENTIC
   * (signed by the holder of `kid`). On its own this does NOT confirm that the
   * request/response the verifier actually received matches what was signed. To
   * detect content substitution (e.g. a MITM-swapped `authorizationUrl` in a
   * needs_authorization challenge), pass `expected`: the request you sent and the
   * response you received are re-hashed via the SAME canonical hashing the signer
   * used (computeCanonicalHashes) and compared to the bound requestHash/
   * responseHash. A mismatch fails with CONTENT_BINDING_MISMATCH.
   *
   * @param proof - The proof to verify
   * @param publicKeyJwk - Ed25519 public key in JWK format (from DID document)
   * @param expected - Optional content binding: the `request` you sent and the
   *   `response` you received. Their canonical hashes MUST match the proof's
   *   bound hashes. FAIL-CLOSED: if the proof binds a `responseHash` (success and
   *   needs_authorization proofs), `response` is REQUIRED — omitting it fails with
   *   CONTENT_BINDING_MISMATCH, so the URL-bearing body cannot go silently
   *   unverified. WHAT to pass as `response.data` depends on the proof's own
   *   `prf` claim: for a v1 proof (no `prf`) pass the response BODY (the MCP
   *   `content` array); for a v2 proof (`prf: "org.kya-os/response-proof.v2"`)
   *   pass the ENTIRE received result object — the verifier removes the
   *   top-level `_meta` member itself, so passing the result as received (proof
   *   attachment included) is correct.
   * @returns Verification result
   */
  async verifyProof(
    proof: DetachedProof,
    publicKeyJwk: Ed25519JWK,
    expected?: { request: ToolRequest; response?: ToolResponse }
  ): Promise<ProofVerificationResult> {
    try {
      const structureValidation = await this.validateProofStructure(proof);
      if (!structureValidation.valid) return structureValidation;
      const validatedProof = structureValidation.proof!;

      // Reconstruct canonical payload from proof meta
      const canonicalPayloadString = this.buildCanonicalPayload(validatedProof.meta);
      const canonicalPayloadBytes = new TextEncoder().encode(
        canonicalPayloadString
      );

      return await this.runVerificationPipeline(
        validatedProof,
        publicKeyJwk,
        canonicalPayloadBytes,
        expected,
      );
    } catch (error) {
      return this.handleVerificationError(error);
    }
  }

  /**
   * Verify a retained proof as historical evidence.
   *
   * Unlike live verification, this pure path never reads or mutates replay
   * state and never compares an old timestamp to the current clock. It verifies
   * structure, protected-header/key binding, signature, and optional content
   * binding. Historical key/status policy is evaluated by the audit verifier.
   */
  async verifyProofArtifact(
    proof: DetachedProof,
    publicKeyJwk: Ed25519JWK,
    expected?: { request: ToolRequest; response?: ToolResponse },
  ): Promise<ProofVerificationResult> {
    try {
      const structureValidation = await this.validateProofStructure(proof);
      if (!structureValidation.valid) return structureValidation;
      const validatedProof = structureValidation.proof!;
      const canonicalPayloadBytes = new TextEncoder().encode(
        this.buildCanonicalPayload(validatedProof.meta),
      );

      const signatureValidation = await this.verifySignature(
        validatedProof.jws,
        publicKeyJwk,
        canonicalPayloadBytes,
        validatedProof.meta.kid,
      );
      if (!signatureValidation.valid) return signatureValidation;

      if (expected !== undefined) {
        return this.validateContentBinding(validatedProof, expected);
      }
      return { valid: true };
    } catch (error) {
      return this.handleVerificationError(error);
    }
  }

  /**
   * Verify proof with detached payload (for CLI/verifier compatibility)
   * @param proof - The proof to verify
   * @param canonicalPayload - Canonical JSON payload (for detached JWS) as string or Uint8Array
   * @param publicKeyJwk - Ed25519 public key in JWK format
   * @returns Verification result
   */
  async verifyProofDetached(
    proof: DetachedProof,
    canonicalPayload: string | Uint8Array,
    publicKeyJwk: Ed25519JWK
  ): Promise<ProofVerificationResult> {
    try {
      // Convert canonical payload to Uint8Array if needed
      const canonicalPayloadBytes =
        canonicalPayload instanceof Uint8Array
          ? canonicalPayload
          : new TextEncoder().encode(canonicalPayload);

      return await this.runVerificationPipeline(proof, publicKeyJwk, canonicalPayloadBytes);
    } catch (error) {
      return this.handleVerificationError(error);
    }
  }

  /**
   * Shared verification pipeline for proof verification
   * @private
   */
  private async runVerificationPipeline(
    proof: DetachedProof,
    publicKeyJwk: Ed25519JWK,
    canonicalPayloadBytes: Uint8Array,
    expected?: { request: ToolRequest; response?: ToolResponse }
  ): Promise<ProofVerificationResult> {
    // 1. Validate proof structure
    const structureValidation = await this.validateProofStructure(proof);
    if (!structureValidation.valid) {
      return structureValidation;
    }
    const validatedProof = structureValidation.proof!;

    // 2. Check nonce replay protection (scoped to agent DID to prevent cross-agent replay attacks)
    const nonceValidation = await this.validateNonce(
      validatedProof.meta.nonce,
      validatedProof.meta.did
    );
    if (!nonceValidation.valid) {
      return nonceValidation;
    }

    // 3. Check timestamp skew
    const timestampValidation = await this.validateTimestamp(
      validatedProof.meta.ts
    );
    if (!timestampValidation.valid) {
      return timestampValidation;
    }

    // 4. Verify JWS signature with canonical payload
    const signatureValidation = await this.verifySignature(
      validatedProof.jws,
      publicKeyJwk,
      canonicalPayloadBytes,
      validatedProof.meta.kid
    );
    if (!signatureValidation.valid) {
      return signatureValidation;
    }

    // 4b. Content binding (optional): the signature proves the proof is
    // AUTHENTIC, but not that the request/response WE received matches what was
    // signed. When the caller supplies what it actually saw, recompute the
    // canonical hashes and confirm they match the bound hashes — this is what
    // turns the signed proof into substitution detection (e.g. a MITM-swapped
    // consent URL). Checked before caching the nonce so a mismatch does not burn
    // the nonce for a legitimate retry.
    if (expected !== undefined) {
      const bindingValidation = await this.validateContentBinding(
        validatedProof,
        expected
      );
      if (!bindingValidation.valid) {
        return bindingValidation;
      }
    }

    // 5. Add nonce to cache to prevent replay (scoped to agent DID)
    await this.addNonceToCache(
      validatedProof.meta.nonce,
      validatedProof.meta.did
    );

    return { valid: true };
  }

  /**
   * Recompute the canonical hashes of the request/response the verifier actually
   * received (via the same hashing the signer used) and compare to the proof's
   * bound hashes. Fails CONTENT_BINDING_MISMATCH on any divergence — the check
   * that makes a signed proof tamper-evident against content substitution.
   * @private
   */
  private async validateContentBinding(
    proof: DetachedProof,
    expected: { request: ToolRequest; response?: ToolResponse }
  ): Promise<ProofVerificationResult> {
    // The response-hash profile comes from the proof's own signature-covered
    // `prf` claim (validated fail-closed in validateProofStructure): a v2 proof
    // is checked with envelope hashing (result minus top-level `_meta`), a v1
    // proof (no `prf`) with body hashing. Deriving from the proof — never from
    // verifier configuration — is what lets one verifier accept both profiles
    // without a downgrade path.
    const { requestHash, responseHash } = await computeCanonicalHashes(
      expected.request,
      expected.response,
      (bytes) => this.cryptoProvider.hash(bytes),
      proof.meta.prf ?? RESPONSE_PROOF_PROFILE_V1,
    );
    if (proof.meta.requestHash !== requestHash) {
      return {
        valid: false,
        reason:
          "Request hash mismatch: the proof does not bind the request you supplied",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
      };
    }
    // Response binding (FAIL-CLOSED): proof.meta.responseHash is the ONLY thing
    // that binds the response body — including a needs_authorization challenge's
    // authorizationUrl. It MUST be checked whenever the proof carries one.
    // Gating the comparison on `expected.response !== undefined` would let a
    // caller who supplies only `request` get { valid: true } while the swapped
    // URL went unverified (the requestHash is identical for a genuine and a
    // MITM'd challenge). So: if the proof binds a responseHash the caller MUST
    // supply the response; if it binds none, the caller must not supply one.
    const proofBindsResponse = proof.meta.responseHash !== undefined;
    const callerSuppliedResponse = expected.response !== undefined;
    if (proofBindsResponse !== callerSuppliedResponse) {
      return {
        valid: false,
        reason: proofBindsResponse
          ? "Proof binds a response (responseHash present) but no response was supplied to verify against — pass expected.response"
          : "A response was supplied but the proof binds none — content/proof mismatch",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
      };
    }
    if (proofBindsResponse && proof.meta.responseHash !== responseHash) {
      return {
        valid: false,
        reason:
          "Response hash mismatch: received content differs from what the server signed (possible substitution / MITM)",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.CONTENT_BINDING_MISMATCH,
      };
    }
    return { valid: true };
  }

  /**
   * Handle verification errors consistently
   * @private
   */
  private handleVerificationError(error: unknown): ProofVerificationResult {
    return {
      valid: false,
      reason: "Proof verification error",
      errorCode: PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_ERROR,
      error: error instanceof Error ? error : new Error(String(error)),
      details: {
        errorMessage: error instanceof Error ? error.message : String(error),
      },
    };
  }

  /**
   * Validate proof structure
   * @private
   */
  private async validateProofStructure(
    proof: DetachedProof
  ): Promise<ProofVerificationResult & { proof?: DetachedProof }> {
    const validationResult = validateDetachedProof(proof);
    if (!validationResult.success) {
      return {
        valid: false,
        reason: "Invalid proof structure",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.INVALID_PROOF_STRUCTURE,
        error: new Error(
          `Proof validation failed: ${validationResult.error?.message}`
        ),
        details: {
          validationError: validationResult.error?.message,
        },
      };
    }
    return {
      valid: true,
      proof: validationResult.data,
    };
  }

  /**
   * Validate nonce replay protection
   * @private
   */
  private async validateNonce(
    nonce: string,
    agentDid?: string
  ): Promise<ProofVerificationResult> {
    const nonceUsed = await this.nonceCache.has(nonce, agentDid);
    if (nonceUsed) {
      return {
        valid: false,
        reason: "Nonce already used (replay attack detected)",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.NONCE_REPLAY_DETECTED,
        details: {
          nonce,
          agentDid,
        },
      };
    }
    return { valid: true };
  }

  /**
   * Validate timestamp skew
   * @private
   */
  private async validateTimestamp(
    timestamp: number
  ): Promise<ProofVerificationResult> {
    // Convert seconds to milliseconds for clock provider (which uses Date.now())
    const timestampMs = timestamp * 1000;
    if (!this.clock.isWithinSkew(timestampMs, this.timestampSkewSeconds)) {
      return {
        valid: false,
        reason: `Timestamp out of skew window (skew: ${this.timestampSkewSeconds}s)`,
        errorCode: PROOF_VERIFICATION_ERROR_CODES.TIMESTAMP_SKEW_EXCEEDED,
        details: {
          timestamp,
          timestampMs,
          skewSeconds: this.timestampSkewSeconds,
          currentTime: this.clock.now(),
        },
      };
    }
    return { valid: true };
  }

  /**
   * Verify JWS signature
   * @private
   */
  private async verifySignature(
    jws: string,
    publicKeyJwk: Ed25519JWK,
    canonicalPayloadBytes: Uint8Array,
    expectedKid?: string
  ): Promise<ProofVerificationResult> {
    const signatureValid = await this.cryptoService.verifyJWS(
      jws,
      publicKeyJwk,
      {
        detachedPayload: canonicalPayloadBytes,
        expectedKid,
        alg: "EdDSA",
      }
    );

    if (!signatureValid) {
      return {
        valid: false,
        reason: "Invalid JWS signature",
        errorCode: PROOF_VERIFICATION_ERROR_CODES.INVALID_JWS_SIGNATURE,
        details: {
          jwsLength: jws.length,
          expectedKid,
          actualKid: publicKeyJwk.kid,
        },
      };
    }

    return { valid: true };
  }

  /**
   * Add nonce to cache to prevent replay (scoped to agent DID)
   * @private
   */
  private async addNonceToCache(
    nonce: string,
    agentDid: string
  ): Promise<void> {
    // Pass TTL in seconds, not absolute timestamp
    await this.nonceCache.add(nonce, this.nonceTtlSeconds, agentDid);
  }

  /**
   * Fetch public key from DID document
   * @param did - DID to resolve
   * @param kid - Key ID (optional, defaults to first verification method)
   * @returns Ed25519 JWK or null if not found
   * @throws {ProofVerificationError} If DID resolution fails with specific error code
   */
  async fetchPublicKeyFromDID(
    did: string,
    kid?: string
  ): Promise<Ed25519JWK | null> {
    try {
      const didDoc = await this.fetch.resolveDID(did);

      if (!didDoc) {
        throw new ProofVerificationError(
          PROOF_VERIFICATION_ERROR_CODES.DID_DOCUMENT_NOT_FOUND,
          `DID document not found: ${did}`,
          { did }
        );
      }

      const doc = didDoc as {
        verificationMethod?: Array<{ id: string; publicKeyJwk?: unknown }>;
      };

      if (
        !doc.verificationMethod ||
        doc.verificationMethod.length === 0
      ) {
        throw new ProofVerificationError(
          PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_METHOD_NOT_FOUND,
          `No verification methods found in DID document: ${did}`,
          { did }
        );
      }

      // Find verification method by kid or use first one
      let verificationMethod:
        | { id: string; publicKeyJwk?: unknown }
        | undefined;
      if (kid) {
        const kidWithHash = kid.startsWith("#") ? kid : `#${kid}`;
        verificationMethod = doc.verificationMethod.find(
          (vm: { id: string }) =>
            vm.id === kidWithHash || vm.id === `${did}${kidWithHash}`
        );

        if (!verificationMethod) {
          throw new ProofVerificationError(
            PROOF_VERIFICATION_ERROR_CODES.VERIFICATION_METHOD_NOT_FOUND,
            `Verification method not found for kid: ${kid}`,
            {
              did,
              kid,
              availableKids: doc.verificationMethod.map(
                (vm: { id: string }) => vm.id
              ),
            }
          );
        }
      } else {
        verificationMethod = doc.verificationMethod[0];
      }

      if (!verificationMethod?.publicKeyJwk) {
        throw new ProofVerificationError(
          PROOF_VERIFICATION_ERROR_CODES.PUBLIC_KEY_NOT_FOUND,
          `Public key JWK not found in verification method`,
          { did, kid, verificationMethodId: verificationMethod?.id }
        );
      }

      const jwk = verificationMethod.publicKeyJwk as {
        kty?: string;
        crv?: string;
        x?: string;
        [key: string]: unknown;
      };

      // Validate it's an Ed25519 key
      if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x) {
        throw new ProofVerificationError(
          PROOF_VERIFICATION_ERROR_CODES.INVALID_JWK_FORMAT,
          `Unsupported key type or curve: kty=${jwk.kty}, crv=${jwk.crv}`,
          { did, kid, jwk: { kty: jwk.kty, crv: jwk.crv } }
        );
      }

      // Set kid from verification method ID so downstream kid-matching works
      const result = jwk as Ed25519JWK;
      if (!result.kid && verificationMethod.id) {
        result.kid = verificationMethod.id;
      }

      return result;
    } catch (error) {
      if (error instanceof ProofVerificationError) {
        throw error;
      }
      logger.error("[ProofVerifier] Failed to fetch public key from DID", { error });
      throw new ProofVerificationError(
        PROOF_VERIFICATION_ERROR_CODES.DID_RESOLUTION_FAILED,
        `DID resolution failed: ${error instanceof Error ? error.message : String(error)}`,
        {
          did,
          kid,
          originalError: error instanceof Error ? error.message : String(error),
        }
      );
    }
  }

  /**
   * Build canonical payload from proof meta
   *
   * CRITICAL: This must reconstruct the exact JWS payload structure that was originally signed.
   * The original JWS payload uses standard JWT claims (aud, sub, iss) plus custom proof claims,
   * NOT the proof.meta structure directly.
   *
   * @param meta - Proof metadata
   * @returns Canonical JSON string matching the original JWS payload structure
   */
  buildCanonicalPayload(meta: DetachedProof["meta"]): string {
    // Reconstruct the exact JWS payload the signer serialized: the SHAPE comes
    // from the shared buildProofJwsPayload (single source of truth with the
    // generator, so a claim — e.g. the v2 `prf` discriminator — can never be
    // covered on one side and dropped on the other), and the serialization is
    // the same RFC 8785 canonicalization the signer used.
    return canonicalizeJson(buildProofJwsPayload(meta));
  }
}

/**
 * MCP-reserved / standard `_meta` keys a KYA-OS verifier MUST tolerate but
 * never hash or trust (MCP 2026-07-28 / SEP-414): the `io.modelcontextprotocol/*`
 * reverse-DNS namespace reserved by the MCP maintainers, and the W3C Trace
 * Context propagation keys. Allowlisted so their presence is unambiguously not a
 * cause for rejection under any policy.
 */
const RESERVED_MCP_META_PREFIXES = ['io.modelcontextprotocol/'] as const;
const RESERVED_MCP_META_KEYS = ['traceparent', 'tracestate', 'baggage'] as const;

/**
 * Whether `key` is an MCP-reserved / standard `_meta` key (SEP-414) that KYA-OS
 * tolerates: never hashed, never trusted, never a cause for rejection. Exposed
 * so adopters can classify coexisting `_meta` keys with the same allowlist the
 * verifier uses. See {@link validateMetaStructure}.
 */
export function isReservedMcpMetaKey(key: string): boolean {
  return (
    (RESERVED_MCP_META_KEYS as readonly string[]).includes(key) ||
    RESERVED_MCP_META_PREFIXES.some((prefix) => key.startsWith(prefix))
  );
}

/**
 * Validate _meta structure according to meta policy.
 *
 * The KYA-OS proof rides under {@link KYA_OS_PROOF_META_KEY} (reverse-DNS,
 * SEP-414); the prior {@link LEGACY_NAMESPACED_PROOF_META_KEY} and the legacy
 * bare {@link LEGACY_PROOF_META_KEY} are still accepted for back-compat. All
 * three are treated as the proof key. Every other key is a
 * non-KYA-OS `_meta` key.
 *
 * Under MCP 2026-07-28 `_meta` is shared real estate (it also carries
 * `io.modelcontextprotocol/*` and W3C trace-context keys), so NEITHER policy
 * rejects foreign keys — the prior `strict` reject-extras behavior would have
 * made a conformant KYA-OS verifier reject conformant RC traffic. Both policies
 * carry the identical zero-trust boundary: only the proof key is ever hashed or
 * trusted; reserved/foreign keys ({@link isReservedMcpMetaKey} and any other)
 * pass through untouched.
 *
 * - `strict` (default): non-KYA-OS keys are IGNORED (discarded) — never hashed,
 *   trusted, or rejected.
 * - `allow-extensions`: identical trust boundary, but the non-KYA-OS keys are
 *   surfaced back to the caller (`extraKeys`) instead of discarded.
 *
 * @param meta - The _meta object from a response
 * @param policy - Meta policy ('strict' or 'allow-extensions')
 * @returns Validation result; always valid. Under 'allow-extensions' any
 *   non-KYA-OS keys are surfaced in `extraKeys`.
 */
export function validateMetaStructure(
  meta: Record<string, unknown>,
  policy: MetaPolicy = 'strict'
): { valid: boolean; reason?: string; extraKeys?: string[] } {
  const extraKeys = Object.keys(meta).filter(
    k =>
      k !== KYA_OS_PROOF_META_KEY &&
      k !== LEGACY_NAMESPACED_PROOF_META_KEY &&
      k !== LEGACY_PROOF_META_KEY,
  );

  // allow-extensions surfaces coexisting keys; strict discards them. Neither
  // rejects — a reserved key (io.modelcontextprotocol/*, traceparent, …) or any
  // other foreign key never fails verification.
  if (policy === 'allow-extensions' && extraKeys.length > 0) {
    return { valid: true, extraKeys };
  }

  return { valid: true };
}

/**
 * Extract proof from _meta with policy validation.
 *
 * @param meta - The _meta object from a response
 * @param policy - Meta policy ('strict' or 'allow-extensions')
 * @returns Extracted proof or error result
 */
export function extractProofFromMeta(
  meta: Record<string, unknown>,
  policy: MetaPolicy = 'strict'
): { success: true; proof: DetachedProof } | { success: false; reason: string; errorCode: string } {
  // Check for the proof field first. Prefer the canonical role-named key,
  // then the prior namespaced key, then the legacy bare key — the newest
  // canonical form wins when several are present (SPEC §7.6).
  const proof =
    meta[KYA_OS_PROOF_META_KEY] ??
    meta[LEGACY_NAMESPACED_PROOF_META_KEY] ??
    meta[LEGACY_PROOF_META_KEY];
  if (!proof) {
    return {
      success: false,
      reason: '_meta does not contain a proof',
      errorCode: PROOF_VERIFICATION_ERROR_CODES.MISSING_REQUIRED_FIELD,
    };
  }

  // Run the policy check for its semantics (strict ignores / allow-extensions
  // surfaces coexisting keys). Under MCP 2026-07-28 (SEP-414) it never rejects,
  // so it cannot block extraction — there is no policy-violation path here.
  validateMetaStructure(meta, policy);

  const proofValidation = validateDetachedProof(proof);
  if (!proofValidation.success) {
    return {
      success: false,
      reason: proofValidation.error?.message ?? 'Invalid proof structure',
      errorCode: PROOF_VERIFICATION_ERROR_CODES.INVALID_PROOF_STRUCTURE,
    };
  }

  return { success: true, proof: proofValidation.data! };
}
