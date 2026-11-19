/**
 * ProofVerifier
 *
 * Centralized proof verification service that validates DetachedProof
 * signatures, enforces nonce replay protection, and checks timestamp skew.
 */

import { CryptoService, type Ed25519JWK } from "../utils/crypto-service.js";
import { ClockProvider, CryptoProvider, FetchProvider, NonceCacheProvider } from "../providers/base.js";
import { nonceRetentionSeconds } from "../providers/nonce-retention.js";
import { admitNonce, checkNonceStore } from "../providers/nonce-admission.js";
import { fetchProofKey } from "./proof-key.js";
import type { DetachedProof } from "../types/protocol.js";
import { canonicalizeJson } from "../utils/canonical-json.js";
import { dependencyTimeout } from "../utils/deadline.js";
import {
  PROOF_VERIFICATION_ERROR_CODES,
} from "./errors.js";
import type { ProofVerificationOptions, ProofVerificationResult, ProofVerifierConfig } from "./verifier-types.js";
import { buildProofJwsPayload } from "./generator.js";
import { bindingFailure, findBindingMismatch, type ExpectedContent } from "./binding.js";
import {
  handleVerificationError,
  validateProofStructure,
  validateSigner,
} from "./verification-checks.js";

export type { ProofVerificationOptions, ProofVerificationResult, ProofVerifierConfig } from "./verifier-types.js";
export { extractProofFromMeta, isReservedMcpMetaKey, validateMetaStructure } from "./meta-extraction.js";

/** Default timestamp skew for proof verification (seconds) */
export const DEFAULT_CLOCK_SKEW_SECONDS = 120;
/** Minimum allowed clock skew (seconds) */
export const MIN_CLOCK_SKEW_SECONDS = 30;
/** Maximum allowed clock skew (seconds) */
export const MAX_CLOCK_SKEW_SECONDS = 600;

/** Reject a non-finite or negative duration at construction, not on every request. */
function requireNonNegativeSeconds(name: string, value: number): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`${name} must be a finite, non-negative number of seconds`);
  }
  return value;
}

export class ProofVerifier {
  private cryptoService: CryptoService;
  private clock: ClockProvider;
  private nonceCache: NonceCacheProvider;
  private fetch: FetchProvider;
  private timestampSkewSeconds: number;
  private nonceTtlSeconds: number;
  private requireAtomicNonce: boolean;
  private readonly timeoutMs: number;
  private cryptoProvider: CryptoProvider;

  constructor(config: ProofVerifierConfig) {
    this.cryptoService = new CryptoService(config.cryptoProvider);
    this.cryptoProvider = config.cryptoProvider;
    this.clock = config.clockProvider;
    this.nonceCache = config.nonceCacheProvider;
    this.fetch = config.fetchProvider;
    this.timestampSkewSeconds = requireNonNegativeSeconds(
      "timestampSkewSeconds",
      config.timestampSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS,
    );
    this.nonceTtlSeconds = requireNonNegativeSeconds(
      "nonceTtlSeconds",
      config.nonceTtlSeconds ?? 300, // Default 5 minutes
    );
    this.requireAtomicNonce = config.requireAtomicNonce ?? false;
    this.timeoutMs = dependencyTimeout(config.dependencyTimeoutMs);
    checkNonceStore(this.nonceCache, { requireAtomicNonce: this.requireAtomicNonce });
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
   * This path uses the caller-supplied key. The caller must retrieve it from the
   * signer's assertionMethod; fetchPublicKeyFromDID enforces that relationship.
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
   * A refusal is signed too, and may name the delegation presented with it: to
   * take a proof for evidence of an allowed call, pass `expected.outcome` or a
   * `delegationChain`, which requires one (see `ExpectedContent`).
   *
   * @param proof - The proof to verify
   * @param publicKeyJwk - Ed25519 public key in JWK format (from DID document)
   * @param expected - Optional content binding: the `request` you sent and the
   *   `response` you received. Their canonical hashes MUST match the proof's
   *   bound hashes. FAIL-CLOSED: if the proof binds a `responseHash` (success and
   *   needs_authorization proofs), `response` is REQUIRED — omitting it fails with
   *   CONTENT_BINDING_MISMATCH, so the URL-bearing body cannot go silently
   *   unverified. WHAT to pass as `response.data` depends on the proof's own
   *   `prf` claim: for a body-profile proof (no `prf`) pass the response BODY (the MCP
   *   `content` array); for an envelope-profile proof (`prf: "org.kya-os/response-proof.envelope"`)
   *   pass the ENTIRE received result object — the verifier removes the
   *   top-level `_meta` member itself, so passing the result as received (proof
   *   attachment included) is correct. Pass the `request` either as the
   *   `tools/call` request you sent (`{method: "tools/call", params: {name,
   *   arguments}}`) or in the legacy `{method: <tool name>, params: <arguments>}`
   *   shape: a `requestHash` over either shape of that call is accepted (SPEC
   *   §7.3; 1.x producers sign the legacy shape). The delegation chain the
   *   server evaluated and the outcome it recorded are compared as
   *   `ExpectedContent` says: they fail with DELEGATION_BINDING_MISMATCH and
   *   OUTCOME_MISMATCH, and `details` names the comparison that failed.
   * @param options - Optional signer binding: the `did` the proof must come
   *   from and the `audience` it must be addressed to. Independently of these,
   *   a `kid` naming a key of a DID other than `meta.did` always fails.
   * @returns Verification result
   */
  async verifyProof(
    proof: DetachedProof,
    publicKeyJwk: Ed25519JWK,
    expected?: ExpectedContent,
    options: ProofVerificationOptions = {},
  ): Promise<ProofVerificationResult> {
    try {
      const structureValidation = await validateProofStructure(proof);
      if (!structureValidation.valid) return structureValidation;
      const validatedProof = structureValidation.proof!;

      return await this.runVerificationPipeline(
        validatedProof,
        publicKeyJwk,
        this.encodeCanonicalPayload(validatedProof.meta),
        expected,
        options,
      );
    } catch (error) {
      return handleVerificationError(error);
    }
  }

  /**
   * Verify a retained proof as historical evidence.
   *
   * This path uses the caller-supplied key. The caller must retrieve it from the
   * signer's assertionMethod; fetchPublicKeyFromDID enforces that relationship.
   *
   * Unlike live verification, this pure path never reads or mutates replay
   * state and never compares an old timestamp to the current clock. It verifies
   * structure, protected-header/key binding, signature, and optional content
   * binding. Historical key/status policy is evaluated by the audit verifier.
   */
  async verifyProofArtifact(
    proof: DetachedProof,
    publicKeyJwk: Ed25519JWK,
    expected?: ExpectedContent,
  ): Promise<ProofVerificationResult> {
    try {
      const structureValidation = await validateProofStructure(proof);
      if (!structureValidation.valid) return structureValidation;
      const validatedProof = structureValidation.proof!;
      const signerValidation = validateSigner(validatedProof.meta);
      if (!signerValidation.valid) return signerValidation;

      const signatureValidation = await this.verifySignature(
        validatedProof.jws,
        publicKeyJwk,
        this.encodeCanonicalPayload(validatedProof.meta),
        validatedProof.meta.kid,
      );
      if (!signatureValidation.valid) return signatureValidation;

      if (expected !== undefined) {
        return this.validateContentBinding(validatedProof, expected);
      }
      return { valid: true };
    } catch (error) {
      return handleVerificationError(error);
    }
  }

  /**
   * Verify proof with detached payload (for CLI/verifier compatibility).
   *
   * The timestamp and replay checks read `proof.meta`, so the payload the
   * signature is checked over must be the one rebuilt from that meta: a
   * supplied payload that differs from it byte for byte is rejected. Otherwise
   * an accepted proof could be replayed with a fresh `meta.nonce` and the old
   * payload.
   *
   * @deprecated Use {@link verifyProof}. It rebuilds the payload from
   *   `proof.meta` itself, so supplying the payload adds nothing.
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
      const structureValidation = await validateProofStructure(proof);
      if (!structureValidation.valid) return structureValidation;
      const validatedProof = structureValidation.proof!;

      const suppliedPayload =
        canonicalPayload instanceof Uint8Array
          ? canonicalPayload
          : new TextEncoder().encode(canonicalPayload);
      const metaPayload = this.encodeCanonicalPayload(validatedProof.meta);
      if (!bytesEqual(suppliedPayload, metaPayload)) {
        return {
          valid: false,
          reason: "Detached payload does not match the payload rebuilt from proof.meta",
          errorCode: PROOF_VERIFICATION_ERROR_CODES.INVALID_JWS_PAYLOAD,
        };
      }

      return await this.runVerificationPipeline(validatedProof, publicKeyJwk, metaPayload);
    } catch (error) {
      return handleVerificationError(error);
    }
  }

  /**
   * Shared verification pipeline for a structurally valid proof.
   * @private
   */
  private async runVerificationPipeline(
    validatedProof: DetachedProof,
    publicKeyJwk: Ed25519JWK,
    canonicalPayloadBytes: Uint8Array,
    expected?: ExpectedContent,
    options: ProofVerificationOptions = {},
  ): Promise<ProofVerificationResult> {
    // 1. Signer binding: kid belongs to the claimed did, and did and audience
    // are the ones the caller expects.
    const signerValidation = validateSigner(validatedProof.meta, options);
    if (!signerValidation.valid) {
      return signerValidation;
    }

    // 2. Check timestamp skew
    const timestampValidation = await this.validateTimestamp(
      validatedProof.meta.ts
    );
    if (!timestampValidation.valid) {
      return timestampValidation;
    }

    // 3. Verify JWS signature with canonical payload
    const signatureValidation = await this.verifySignature(
      validatedProof.jws,
      publicKeyJwk,
      canonicalPayloadBytes,
      validatedProof.meta.kid
    );
    if (!signatureValidation.valid) {
      return signatureValidation;
    }

    // 4. Content binding (optional): the signature proves the proof is
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

    // 5. Atomically admit the validated proof (scoped to agent DID). Invalid
    // signatures/bindings must not consume state, and has/add cannot serialize
    // admission across concurrent verifications or distributed instances.
    return this.consumeNonce(
      validatedProof.meta.nonce,
      validatedProof.meta.did,
      validatedProof.meta.ts
    );
  }

  /**
   * Recompute the canonical hashes of the request/response the verifier actually
   * received (via the same hashing the signer used) and compare to the proof's
   * bound hashes. Fails CONTENT_BINDING_MISMATCH on any divergence — the check
   * that makes a signed proof tamper-evident against content substitution.
   * The outcome and the delegation chain are compared too (`findBindingMismatch`).
   * @private
   */
  private async validateContentBinding(
    proof: DetachedProof,
    expected: ExpectedContent
  ): Promise<ProofVerificationResult> {
    // The rule (fail-closed response binding, response profile from the
    // proof's own `prf`) is shared with ProofGenerator.verifyProof.
    const mismatch = await findBindingMismatch(
      proof.meta,
      expected,
      (bytes) => this.cryptoProvider.hash(bytes),
    );
    return mismatch === undefined ? { valid: true } : { valid: false, ...bindingFailure(mismatch) };
  }

  /**
   * Admit the nonce once every other proof check has passed: atomically through
   * the cache's consume(), or through the has()/add() fallback without it.
   * @private
   */
  private async consumeNonce(
    nonce: string,
    agentDid: string,
    timestamp: number
  ): Promise<ProofVerificationResult> {
    // Cover later setTimestampSkew increases too: its supported ceiling is 600s.
    const ttl = nonceRetentionSeconds(
      this.nonceTtlSeconds,
      timestamp + Math.max(this.timestampSkewSeconds, MAX_CLOCK_SKEW_SECONDS),
      this.clock.now(),
    );
    const consumed = await admitNonce(this.nonceCache, nonce, ttl, agentDid, {
      requireAtomicNonce: this.requireAtomicNonce,
    });
    if (!consumed) {
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
   * Fetch an assertionMethod public key from the signer's own DID document
   * @param did - DID to resolve
   * @param kid - Key ID (optional, defaults to the first assertionMethod entry)
   * @returns Ed25519 JWK or null if not found
   * @throws {ProofVerificationError} If DID resolution fails with specific error code
   */
  async fetchPublicKeyFromDID(
    did: string,
    kid?: string
  ): Promise<Ed25519JWK | null> {
    return fetchProofKey(this.fetch, did, kid, this.timeoutMs);
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
    // generator, so a claim — e.g. the envelope profile's `prf` discriminator — can never be
    // covered on one side and dropped on the other), and the serialization is
    // the same RFC 8785 canonicalization the signer used.
    return canonicalizeJson(buildProofJwsPayload(meta));
  }

  private encodeCanonicalPayload(meta: DetachedProof["meta"]): Uint8Array {
    return new TextEncoder().encode(this.buildCanonicalPayload(meta));
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
