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
 * and the per-instance SIGNATURE-result cache — revocation status and basic
 * checks (expiry) are evaluated on every call, never served from cache.
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
  SignatureVerificationResult,
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
import { canonicalizeJson } from "../utils/canonical-json.js";
import { TtlCache } from "../utils/ttl-cache.js";

// Re-export the shared type surface so existing imports of DIDResolver /
// SignatureVerificationFunction / StatusListResolver / … are unchanged.
export * from "./vc-verifier.types.js";

export class DelegationCredentialVerifier {
  private didResolver?: DIDResolver;
  private statusListResolver?: StatusListResolver;
  private signatureVerifier?: SignatureVerificationFunction;
  /**
   * Signature-result cache (FIFO eviction, TTL-bounded). Holds only REAL
   * signature verifications; size `maxCacheSize` to the expected number of
   * DISTINCT live credentials — the default of 1000 suits most deployments.
   */
  private cache: TtlCache<SignatureVerificationResult>;

  constructor(options?: {
    didResolver?: DIDResolver;
    statusListResolver?: StatusListResolver;
    signatureVerifier?: SignatureVerificationFunction;
    /** Signature-result TTL in ms. `0` disables signature caching. Default 60_000. */
    cacheTtl?: number;
    /** Maximum cache entries. Default: 1000 */
    maxCacheSize?: number;
  }) {
    this.didResolver = options?.didResolver;
    this.statusListResolver = options?.statusListResolver;
    this.signatureVerifier = options?.signatureVerifier;
    this.cache = new TtlCache<SignatureVerificationResult>({
      // `??`, not `||`: cacheTtl 0 means "no signature caching", not "the default".
      ttlMs: options?.cacheTtl ?? 60_000,
      maxEntries: options?.maxCacheSize ?? 1000,
    });
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
    const cacheKey = this.cacheKeyForCredential('di', vc, options);

    // Basic checks run on EVERY call — expiry is time-sensitive, so a warm
    // signature cache must never carry a credential past its window.
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

    // Both promises are constructed before either is awaited: a signature
    // cache hit resolves instantly ALONGSIDE the live status read; a miss
    // runs signature and status concurrently (unchanged parallelism).
    const signaturePromise = this.cachedSignature(cacheKey, () =>
      options.skipSignature
        ? Promise.resolve<SignatureVerificationResult>({
            valid: true,
            durationMs: 0,
          })
        : verifySignature(
            vc,
            options.didResolver || this.didResolver,
            this.signatureVerifier,
          ),
    );

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
    const cacheKey = this.cacheKeyForJwt(jwt, vc, options);

    // Same construction as the Data Integrity path: both promises exist
    // before either is awaited, so a cached signature races a LIVE status
    // read and a miss keeps full signature/status parallelism.
    const signaturePromise = this.cachedSignature(cacheKey, () =>
      options.skipSignature
        ? Promise.resolve<VcJwtSignatureResult>({ valid: true, durationMs: 0 })
        : verifyVcJwtSignature(
            jwt,
            issuerDid,
            kid,
            options.didResolver || this.didResolver,
          ),
    );

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
      signaturePromise,
      statusPromise,
      basicCheckMs,
      startTime,
    );
  }

  /**
   * Resolve the signature dimension: an unexpired cached result when
   * available, else `run()` — cached only when valid (failures are never
   * cached). Returned as a promise so callers can race it with the status
   * check; a hit reports `durationMs: 0` (the retrieval, not the original
   * compute).
   */
  private async cachedSignature(
    cacheKey: string | null,
    run: () => Promise<SignatureVerificationResult>,
  ): Promise<{ result: SignatureVerificationResult; cached: boolean }> {
    if (cacheKey !== null) {
      const hit = this.cache.get(cacheKey);
      if (hit) {
        return { result: { ...hit, durationMs: 0 }, cached: true };
      }
    }
    const result = await run();
    if (result.valid && cacheKey !== null) {
      this.cache.set(cacheKey, result);
    }
    return { result, cached: false };
  }

  /**
   * Await the parallel signature + status checks and fold them into the final
   * result via {@link combineVerificationResult}. The combined verdict is
   * NEVER cached — only the signature dimension is (inside
   * {@link cachedSignature}) — so revocation status is consulted on every
   * call. Shared by the Data Integrity and VC-JWT paths; both reach here only
   * after `validateBasicProperties` has passed.
   */
  private async finalizeVerification(
    signaturePromise: Promise<{
      result: SignatureVerificationResult;
      cached: boolean;
    }>,
    statusPromise: Promise<StatusCheckResult>,
    basicCheckMs: number,
    startTime: number,
  ): Promise<DelegationVCVerificationResult> {
    const [signature, statusResult] = await Promise.all([
      signaturePromise,
      statusPromise,
    ]);

    const result = combineVerificationResult(
      signature.result,
      statusResult,
      basicCheckMs,
      startTime,
    );

    if (signature.cached) {
      result.cached = true;
    }

    return result;
  }

  private cacheKeyForCredential(
    mode: 'di',
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions,
  ): string | null {
    if (!this.cacheAllowed(options)) return null;
    try {
      return `${mode}\0${vc.id ?? ''}\0${canonicalizeJson(vc)}`;
    } catch {
      return null;
    }
  }

  private cacheKeyForJwt(
    jwt: string,
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions,
  ): string | null {
    if (!this.cacheAllowed(options)) return null;
    return `jwt\0${vc.id ?? ''}\0${jwt}`;
  }

  /**
   * The cache holds only REAL signature verifications: a `skipSignature` run
   * fabricates `{ valid: true }` at zero cost, so it neither reads nor writes
   * the cache (which is what lets the key drop the old per-profile
   * dimension). Per-call resolver overrides also bypass — conservative,
   * unchanged.
   */
  private cacheAllowed(options: VerifyDelegationVCOptions): boolean {
    return !options.skipCache &&
      !options.skipSignature &&
      options.didResolver === undefined &&
      options.statusListResolver === undefined;
  }

  clearCache(): void {
    this.cache.clear();
  }

  clearCacheEntry(id: string): void {
    const diPrefix = `di\0${id}\0`;
    const jwtPrefix = `jwt\0${id}\0`;
    this.cache.deleteWhere(
      (key) => key.startsWith(diPrefix) || key.startsWith(jwtPrefix),
    );
  }
}

export function createDelegationVerifier(options?: {
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
  signatureVerifier?: SignatureVerificationFunction;
  /** Signature-result TTL in ms. `0` disables signature caching. Default 60_000. */
  cacheTtl?: number;
  /** Maximum cache entries. Default: 1000 */
  maxCacheSize?: number;
}): DelegationCredentialVerifier {
  return new DelegationCredentialVerifier(options);
}
