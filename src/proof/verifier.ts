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
import { canonicalize } from "json-canonicalize";
import {
  ProofVerificationError,
  PROOF_VERIFICATION_ERROR_CODES,
  type ProofVerificationErrorCode,
} from "./errors.js";
import { logger } from "../logging/index.js";

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

  constructor(config: ProofVerifierConfig) {
    this.cryptoService = new CryptoService(config.cryptoProvider);
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
   * Verify a DetachedProof
   * Automatically reconstructs canonical payload from proof.meta for signature verification
   * @param proof - The proof to verify
   * @param publicKeyJwk - Ed25519 public key in JWK format (from DID document)
   * @returns Verification result
   */
  async verifyProof(
    proof: DetachedProof,
    publicKeyJwk: Ed25519JWK
  ): Promise<ProofVerificationResult> {
    try {
      // Reconstruct canonical payload from proof meta
      const canonicalPayloadString = this.buildCanonicalPayload(proof.meta);
      const canonicalPayloadBytes = new TextEncoder().encode(
        canonicalPayloadString
      );

      return await this.runVerificationPipeline(proof, publicKeyJwk, canonicalPayloadBytes);
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
    canonicalPayloadBytes: Uint8Array
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

    // 5. Add nonce to cache to prevent replay (scoped to agent DID)
    await this.addNonceToCache(
      validatedProof.meta.nonce,
      validatedProof.meta.did
    );

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
    // Reconstruct the original JWS payload structure that was signed
    // This matches the structure used in proof generation (proof.ts, proof-generator.ts)
    const payload = {
      // Standard JWT claims (RFC 7519) - these are what was actually signed
      aud: meta.audience, // Audience (who the token is for)
      sub: meta.did, // Subject (agent DID)
      iss: meta.did, // Issuer (agent DID - self-issued)

      // Custom KYA-OS proof claims
      requestHash: meta.requestHash,
      responseHash: meta.responseHash,
      ts: meta.ts,
      nonce: meta.nonce,
      sessionId: meta.sessionId,

      // Optional claims (only include if present)
      ...(meta.scopeId && { scopeId: meta.scopeId }),
      ...(meta.delegationRef && { delegationRef: meta.delegationRef }),
      ...(meta.clientDid && { clientDid: meta.clientDid }),
    };

    // Canonicalize the reconstructed payload using the same function as proof generation
    // CRITICAL: Must use json-canonicalize canonicalize() to match proof.ts exactly
    return canonicalize(payload);
  }
}

/**
 * Validate _meta structure according to meta policy.
 *
 * In 'strict' mode, _meta must contain only 'proof'.
 * In 'allow-extensions' mode, additional keys are permitted.
 *
 * @param meta - The _meta object from a response
 * @param policy - Meta policy ('strict' or 'allow-extensions')
 * @returns Validation result with valid flag and optional reason
 */
export function validateMetaStructure(
  meta: Record<string, unknown>,
  policy: MetaPolicy = 'strict'
): { valid: boolean; reason?: string; extraKeys?: string[] } {
  const keys = Object.keys(meta);
  const extraKeys = keys.filter(k => k !== 'proof');

  if (policy === 'strict' && extraKeys.length > 0) {
    return {
      valid: false,
      reason: `_meta contains keys other than 'proof' in strict mode: ${extraKeys.join(', ')}`,
      extraKeys,
    };
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
  // Check for required proof field first
  const proof = meta.proof;
  if (!proof) {
    return {
      success: false,
      reason: '_meta does not contain proof',
      errorCode: PROOF_VERIFICATION_ERROR_CODES.MISSING_REQUIRED_FIELD,
    };
  }

  // Validate meta structure according to policy
  const validation = validateMetaStructure(meta, policy);
  if (!validation.valid) {
    return {
      success: false,
      reason: validation.reason!,
      errorCode: PROOF_VERIFICATION_ERROR_CODES.META_POLICY_VIOLATION,
    };
  }

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
