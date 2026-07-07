/**
 * Dylan Hobbs
 * Delegation Credential Verifier (Platform-Agnostic)
 *
 * Progressive enhancement verification for W3C Delegation Credentials.
 *
 * Stage 1: Fast basic checks (no network, early rejection)
 * Stage 2: Parallel advanced checks (signature, status)
 * Stage 3: Combined results
 *
 * The stateless checks live in `./vc-verification-checks.ts`; the shapes in
 * `./vc-verifier.types.ts` (re-exported below). This class owns orchestration
 * and the per-instance result cache.
 *
 * Related Spec: KYA-OS §4.3, W3C VC Data Model 1.1
 */

import type { DelegationCredential } from "../types/protocol.js";
import type {
  DelegationVCVerificationResult,
  VerifyDelegationVCOptions,
  DIDResolver,
  StatusListResolver,
  StatusCheckResult,
  SignatureVerificationFunction,
} from "./vc-verifier.types.js";
import {
  validateBasicProperties,
  verifySignature,
  checkCredentialStatus,
  combineVerificationResult,
} from "./vc-verification-checks.js";
import {
  verifyVcJwtSignature,
  prepareVcJwtCredential,
} from "./vc-jwt-verify.js";
import type { VcJwtSignatureResult } from "./vc-jwt-verify.js";

// Re-export the shared type surface so existing imports of DIDResolver /
// SignatureVerificationFunction / StatusListResolver / … are unchanged.
export * from "./vc-verifier.types.js";

export class DelegationCredentialVerifier {
  private didResolver?: DIDResolver;
  private statusListResolver?: StatusListResolver;
  private signatureVerifier?: SignatureVerificationFunction;
  private cache = new Map<
    string,
    { result: DelegationVCVerificationResult; expiresAt: number }
  >();
  private cacheInsertionOrder: string[] = [];
  private cacheTtl: number;
  /**
   * Maximum number of entries in the verification cache.
   * In production deployments, configure maxCacheSize based on expected concurrent delegations.
   * Default of 1000 is suitable for most use cases.
   */
  private maxCacheSize: number;

  constructor(options?: {
    didResolver?: DIDResolver;
    statusListResolver?: StatusListResolver;
    signatureVerifier?: SignatureVerificationFunction;
    cacheTtl?: number;
    /** Maximum cache entries. Default: 1000 */
    maxCacheSize?: number;
  }) {
    this.didResolver = options?.didResolver;
    this.statusListResolver = options?.statusListResolver;
    this.signatureVerifier = options?.signatureVerifier;
    this.cacheTtl = options?.cacheTtl || 60_000;
    this.maxCacheSize = options?.maxCacheSize ?? 1000;
  }

  /**
   * Verify a delegation credential through progressive enhancement.
   *
   * Stage 1: Fast basic checks (schema, expiry, status field)
   * Stage 2: Parallel signature and status list checks (if resolvers configured)
   * Stage 3: Combined result with timing metrics
   *
   * @param vc - The W3C Delegation Credential to verify
   * @param options - Verification options (skip cache/signature/status, custom resolvers)
   * @returns Verification result with validity, reason, stage reached, and metrics
   */
  async verifyDelegationCredential(
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions = {},
  ): Promise<DelegationVCVerificationResult> {
    const startTime = Date.now();

    if (!options.skipCache) {
      const cached = this.getFromCache(vc.id || "");
      if (cached) {
        return { ...cached, cached: true };
      }
    }

    const basicCheckStart = Date.now();
    const basicValidation = validateBasicProperties(vc);
    const basicCheckMs = Date.now() - basicCheckStart;

    if (!basicValidation.valid) {
      const result: DelegationVCVerificationResult = {
        valid: false,
        reason: basicValidation.reason,
        stage: "basic",
        metrics: {
          basicCheckMs,
          totalMs: Date.now() - startTime,
        },
        checks: {
          basicValid: false,
        },
      };
      return result;
    }

    const signaturePromise = !options.skipSignature
      ? verifySignature(
          vc,
          options.didResolver || this.didResolver,
          this.signatureVerifier,
        )
      : Promise.resolve<{
          valid: boolean;
          reason?: string;
          durationMs?: number;
        }>({
          valid: true,
          durationMs: 0,
        });

    const statusPromise =
      !options.skipStatus && vc.credentialStatus
        ? checkCredentialStatus(
            vc.credentialStatus,
            options.statusListResolver || this.statusListResolver,
          )
        : Promise.resolve<StatusCheckResult>({
            valid: true,
            durationMs: 0,
          });

    return this.finalizeVerification(
      vc,
      signaturePromise,
      statusPromise,
      basicCheckMs,
      startTime,
    );
  }

  /**
   * Verify a delegation credential presented as a compact VC-JWT — the JWT
   * serialization (W3C VC Data Model 1.1 §6.3.1), the form browser wallets
   * mint, where the JWS envelope signature over `header.payload` IS the proof.
   *
   * Parses the token, runs the same fast basic checks on the extracted
   * credential (minus the embedded-`proof` requirement — the envelope is the
   * proof), then verifies that envelope signature and the credential status in
   * parallel. Same result shape, cache, and metrics as
   * {@link verifyDelegationCredential}.
   */
  async verifyDelegationJwt(
    jwt: string,
    options: VerifyDelegationVCOptions = {},
  ): Promise<DelegationVCVerificationResult> {
    const startTime = Date.now();

    const prepared = prepareVcJwtCredential(jwt, startTime);
    if ("failure" in prepared) {
      return prepared.failure;
    }
    const { vc, issuerDid, kid, basicCheckMs } = prepared;

    if (!options.skipCache) {
      const cached = this.getFromCache(vc.id || "");
      if (cached) {
        return { ...cached, cached: true };
      }
    }

    const signaturePromise = !options.skipSignature
      ? verifyVcJwtSignature(
          jwt,
          issuerDid,
          kid,
          options.didResolver || this.didResolver,
        )
      : Promise.resolve<VcJwtSignatureResult>({ valid: true, durationMs: 0 });

    const statusPromise =
      !options.skipStatus && vc.credentialStatus
        ? checkCredentialStatus(
            vc.credentialStatus,
            options.statusListResolver || this.statusListResolver,
          )
        : Promise.resolve<StatusCheckResult>({
            valid: true,
            durationMs: 0,
          });

    return this.finalizeVerification(
      vc,
      signaturePromise,
      statusPromise,
      basicCheckMs,
      startTime,
    );
  }

  /**
   * Await the parallel signature + status checks, fold them into the final
   * result via {@link combineVerificationResult}, and cache a valid one. Shared
   * by the Data Integrity and VC-JWT paths; both reach here only after
   * `validateBasicProperties` has passed.
   */
  private async finalizeVerification(
    vc: DelegationCredential,
    signaturePromise: Promise<{
      valid: boolean;
      reason?: string;
      durationMs?: number;
    }>,
    statusPromise: Promise<StatusCheckResult>,
    basicCheckMs: number,
    startTime: number,
  ): Promise<DelegationVCVerificationResult> {
    const [signatureResult, statusResult] = await Promise.all([
      signaturePromise,
      statusPromise,
    ]);

    const result = combineVerificationResult(
      signatureResult,
      statusResult,
      basicCheckMs,
      startTime,
    );

    if (result.valid && vc.id) {
      this.setInCache(vc.id, result);
    }

    return result;
  }

  private getFromCache(id: string): DelegationVCVerificationResult | null {
    const entry = this.cache.get(id);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(id);
      return null;
    }

    return entry.result;
  }

  private setInCache(id: string, result: DelegationVCVerificationResult): void {
    // Evict oldest entry if cache exceeds maxCacheSize (simple FIFO)
    while (this.cache.size >= this.maxCacheSize && this.cacheInsertionOrder.length > 0) {
      const oldestId = this.cacheInsertionOrder.shift();
      if (oldestId) {
        this.cache.delete(oldestId);
      }
    }

    this.cache.set(id, {
      result,
      expiresAt: Date.now() + this.cacheTtl,
    });
    this.cacheInsertionOrder.push(id);
  }

  clearCache(): void {
    this.cache.clear();
    this.cacheInsertionOrder = [];
  }

  clearCacheEntry(id: string): void {
    this.cache.delete(id);
    const idx = this.cacheInsertionOrder.indexOf(id);
    if (idx !== -1) {
      this.cacheInsertionOrder.splice(idx, 1);
    }
  }
}

export function createDelegationVerifier(options?: {
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
  signatureVerifier?: SignatureVerificationFunction;
  cacheTtl?: number;
}): DelegationCredentialVerifier {
  return new DelegationCredentialVerifier(options);
}
