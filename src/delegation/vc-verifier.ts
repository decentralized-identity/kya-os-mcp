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
 * Related Spec: KYA-OS §4.3, W3C VC Data Model 1.1
 */

import type {
  DelegationCredential,
  CredentialStatus,
} from "../types/protocol.js";
import {
  isDelegationCredentialExpired,
  isDelegationCredentialNotYetValid,
  validateDelegationCredential,
} from "../types/protocol.js";

/**
 * Properties a DelegationCredential `credentialSubject` may carry. Anything
 * else is treated as a claim-intended field and rejected by default — a
 * permission credential must not smuggle claims (KYA-OS §11.6).
 */
const DELEGATION_SUBJECT_KEYS: readonly string[] = ["id", "delegation"];

// Module-level warn-once flag for the unsafe opt-out in validateSubjectShape.
// Per-process, mirroring the convention in middleware/with-kya-os.ts so
// operators see a single log line rather than one per verification.
let warnedNonDelegationSubjectFields = false;

export interface DelegationVCVerificationResult {
  valid: boolean;
  reason?: string;
  stage: "basic" | "signature" | "status" | "complete";
  cached?: boolean;
  metrics?: {
    basicCheckMs?: number;
    signatureCheckMs?: number;
    statusCheckMs?: number;
    totalMs: number;
  };
  checks?: {
    basicValid?: boolean;
    signatureValid?: boolean;
    statusValid?: boolean;
  };
}

export interface VerifyDelegationVCOptions {
  skipCache?: boolean;
  skipSignature?: boolean;
  skipStatus?: boolean;
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
  /**
   * Accept a delegation credential whose `credentialSubject` carries properties
   * beyond `id` and `delegation` (e.g. claim-bearing fields). UNSAFE: mixing
   * claim semantics into a permission credential separates designation from
   * authorization — the root of the confused-deputy class (KYA-OS §11.6).
   * Defaults to `false` (strict). When `true`, the verifier emits a one-time
   * per-process warning and accepts the credential.
   */
  allowNonDelegationSubjectFields?: boolean;
}

export interface DIDResolver {
  resolve(did: string): Promise<DIDDocument | null>;
}

export interface DIDDocument {
  '@context'?: string | string[];
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: unknown;
  publicKeyBase58?: string;
  publicKeyMultibase?: string;
}

export interface StatusListResolver {
  checkStatus(status: CredentialStatus): Promise<boolean>;
}

export interface SignatureVerificationFunction {
  (
    vc: DelegationCredential,
    publicKeyJwk: unknown,
  ): Promise<{
    valid: boolean;
    reason?: string;
  }>;
}

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
    const basicValidation = this.validateBasicProperties(vc, options);
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
      ? this.verifySignature(vc, options.didResolver || this.didResolver)
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
        ? this.checkCredentialStatus(
            vc.credentialStatus,
            options.statusListResolver || this.statusListResolver,
          )
        : Promise.resolve<{
            valid: boolean;
            reason?: string;
            durationMs?: number;
          }>({
            valid: true,
            durationMs: 0,
          });

    const [signatureResult, statusResult] = await Promise.all([
      signaturePromise,
      statusPromise,
    ]);

    const signatureCheckMs = signatureResult.durationMs || 0;
    const statusCheckMs = statusResult.durationMs || 0;

    const allValid =
      basicValidation.valid && signatureResult.valid && statusResult.valid;

    const result: DelegationVCVerificationResult = {
      valid: allValid,
      reason: !allValid
        ? signatureResult.reason || statusResult.reason || "Unknown failure"
        : undefined,
      stage: "complete",
      metrics: {
        basicCheckMs,
        signatureCheckMs,
        statusCheckMs,
        totalMs: Date.now() - startTime,
      },
      checks: {
        basicValid: basicValidation.valid,
        signatureValid: signatureResult.valid,
        statusValid: statusResult.valid,
      },
    };

    if (result.valid && vc.id) {
      this.setInCache(vc.id, result);
    }

    return result;
  }

  private validateBasicProperties(
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions,
  ): {
    valid: boolean;
    reason?: string;
  } {
    const schemaValidation = validateDelegationCredential(vc);
    if (!schemaValidation.success) {
      return {
        valid: false,
        reason: `Schema validation failed: ${schemaValidation.error?.message}`,
      };
    }

    if (isDelegationCredentialExpired(vc)) {
      return { valid: false, reason: "Delegation credential expired" };
    }

    if (isDelegationCredentialNotYetValid(vc)) {
      return { valid: false, reason: "Delegation credential not yet valid" };
    }

    const delegation = vc.credentialSubject.delegation;
    if (delegation.status === "revoked") {
      return { valid: false, reason: "Delegation status is revoked" };
    }
    if (delegation.status === "expired") {
      return { valid: false, reason: "Delegation status is expired" };
    }

    if (!delegation.issuerDid || !delegation.subjectDid) {
      return { valid: false, reason: "Missing issuer or subject DID" };
    }

    if (!vc.proof) {
      return { valid: false, reason: "Missing proof" };
    }

    const subjectShape = this.validateSubjectShape(vc, options);
    if (!subjectShape.valid) {
      return subjectShape;
    }

    return { valid: true };
  }

  /**
   * Reject a delegation credential whose `credentialSubject` carries properties
   * other than `id` and `delegation`. Claim-bearing fields in a permission
   * credential separate designation from authorization — the confused-deputy
   * class (KYA-OS §11.6). Strict by default; the unsafe opt-out emits a
   * one-time per-process warning.
   */
  private validateSubjectShape(
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions,
  ): { valid: boolean; reason?: string } {
    const extraneous = Object.keys(vc.credentialSubject).filter(
      (key) => !DELEGATION_SUBJECT_KEYS.includes(key),
    );

    if (extraneous.length === 0) {
      return { valid: true };
    }

    if (options.allowNonDelegationSubjectFields) {
      if (!warnedNonDelegationSubjectFields) {
        warnedNonDelegationSubjectFields = true;
        console.warn(
          `[DelegationCredentialVerifier] allowNonDelegationSubjectFields is enabled — ` +
            `accepting credentialSubject with non-delegation field(s): ${extraneous.join(", ")}. ` +
            `Claim-bearing fields in a permission credential are a confused-deputy risk (KYA-OS §11.6).`,
        );
      }
      return { valid: true };
    }

    return {
      valid: false,
      reason:
        `credentialSubject contains non-delegation field(s): ${extraneous.join(", ")}. ` +
        `A DelegationCredential subject MUST carry only 'id' and 'delegation' (KYA-OS §11.6).`,
    };
  }

  private async verifySignature(
    vc: DelegationCredential,
    didResolver?: DIDResolver,
  ): Promise<{ valid: boolean; reason?: string; durationMs?: number }> {
    const startTime = Date.now();

    try {
      const issuerDid =
        typeof vc.issuer === "string" ? vc.issuer : vc.issuer.id;

      if (!didResolver || !this.signatureVerifier) {
        return {
          valid: false,
          reason:
            "No DID resolver or signature verifier configured — signature cannot be verified",
          durationMs: Date.now() - startTime,
        };
      }

      const didDoc = await didResolver.resolve(issuerDid);
      if (!didDoc) {
        return {
          valid: false,
          reason: `Could not resolve issuer DID: ${issuerDid}`,
          durationMs: Date.now() - startTime,
        };
      }

      if (!vc.proof) {
        return {
          valid: false,
          reason: "Proof is missing",
          durationMs: Date.now() - startTime,
        };
      }

      const verificationMethodId = vc.proof["verificationMethod"];
      if (!verificationMethodId) {
        return {
          valid: false,
          reason: "Proof missing verificationMethod",
          durationMs: Date.now() - startTime,
        };
      }

      const verificationMethod = this.findVerificationMethod(
        didDoc,
        verificationMethodId as string,
      );
      if (!verificationMethod) {
        return {
          valid: false,
          reason: `Verification method ${verificationMethodId} not found`,
          durationMs: Date.now() - startTime,
        };
      }

      const publicKeyJwk = verificationMethod.publicKeyJwk;
      if (!publicKeyJwk) {
        return {
          valid: false,
          reason: "Verification method missing publicKeyJwk",
          durationMs: Date.now() - startTime,
        };
      }

      const verificationResult = await this.signatureVerifier(vc, publicKeyJwk);

      return {
        valid: verificationResult.valid,
        reason: verificationResult.reason,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        valid: false,
        reason: `Signature verification error: ${error instanceof Error ? error.message : "Unknown error"}`,
        durationMs: Date.now() - startTime,
      };
    }
  }

  private async checkCredentialStatus(
    status: CredentialStatus,
    statusListResolver?: StatusListResolver,
  ): Promise<{ valid: boolean; reason?: string; durationMs?: number }> {
    const startTime = Date.now();

    try {
      if (!statusListResolver) {
        return {
          valid: false,
          reason:
            "Credential has credentialStatus but no status list resolver is configured — cannot verify revocation status",
          durationMs: Date.now() - startTime,
        };
      }

      const isRevoked = await statusListResolver.checkStatus(status);

      if (isRevoked) {
        return {
          valid: false,
          reason: `Credential revoked via StatusList2021 (${status.statusPurpose})`,
          durationMs: Date.now() - startTime,
        };
      }

      return {
        valid: true,
        durationMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        valid: false,
        reason: `Status check error: ${error instanceof Error ? error.message : "Unknown error"}`,
        durationMs: Date.now() - startTime,
      };
    }
  }

  private findVerificationMethod(
    didDoc: DIDDocument,
    verificationMethodId: string,
  ): VerificationMethod | undefined {
    return didDoc.verificationMethod?.find(
      (vm) => vm.id === verificationMethodId,
    );
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
