/**
 * Dylan Hobbs
 * Delegation Credential Verifier (Platform-Agnostic)
 *
 * Progressive enhancement verification for W3C Delegation Credentials.
 *
 * Stage 1: Fast basic checks (no network, early rejection)
 * Stage 2: Signature, then status once the signature has verified
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
  SignatureVerificationFunction,
} from "./vc-verifier.types.js";
import {
  validateBasicProperties,
  verifySignature,
  checkCredentialStatus,
  combineVerificationResult,
  type SignatureCheck,
  type StatusCheck,
} from "./vc-verification-checks.js";
import {
  credentialIssuerDid,
  verifyVcJwtSignature,
  prepareVcJwtCredential,
} from "./vc-jwt-verify.js";
import { canonicalizeJson } from "../utils/canonical-json.js";
import { coded } from "../utils/refusal.js";
import { dependencyTimeout } from "../utils/deadline.js";
import { TtlCache } from "../utils/ttl-cache.js";

// Re-export the shared type surface so existing imports of DIDResolver /
// SignatureVerificationFunction / StatusListResolver / … are unchanged.
export * from "./vc-verifier.types.js";

/** Options of {@link DelegationCredentialVerifier} and {@link createDelegationVerifier}. */
export interface DelegationCredentialVerifierOptions {
  didResolver?: DIDResolver;
  statusListResolver?: StatusListResolver;
  signatureVerifier?: SignatureVerificationFunction;
  /** Signature-result TTL in ms. `0` disables signature caching. Default 60_000. */
  cacheTtl?: number;
  /** Maximum cache entries. Default: 1000 */
  maxCacheSize?: number;
  /**
   * How long, in milliseconds, the DID resolver, the signature verifier and the status list resolver may each take to answer: a number greater than 0 and at most
   * 2,147,483,647. Default 5,000. Any other value throws a `TypeError` naming the option.
   */
  dependencyTimeoutMs?: number;
}

export class DelegationCredentialVerifier {
  private didResolver?: DIDResolver;
  private statusListResolver?: StatusListResolver;
  private signatureVerifier?: SignatureVerificationFunction;
  private readonly timeoutMs: number;
  /**
   * Signature-result cache (FIFO eviction, TTL-bounded). Holds only REAL
   * signature verifications; size `maxCacheSize` to the expected number of
   * DISTINCT live credentials — the default of 1000 suits most deployments.
   */
  private cache: TtlCache<SignatureCheck>;

  /** @throws TypeError when `dependencyTimeoutMs` is not a number of milliseconds it can wait. */
  constructor(options?: DelegationCredentialVerifierOptions) {
    this.timeoutMs = dependencyTimeout(options?.dependencyTimeoutMs);
    this.didResolver = options?.didResolver;
    this.statusListResolver = options?.statusListResolver;
    this.signatureVerifier = options?.signatureVerifier;
    this.cache = new TtlCache<SignatureCheck>({
      // `??`, not `||`: cacheTtl 0 means "no signature caching", not "the default".
      ttlMs: options?.cacheTtl ?? 60_000,
      maxEntries: options?.maxCacheSize ?? 1000,
    });
  }

  /**
   * Verify a delegation credential through progressive enhancement.
   *
   * Stage 1: Fast basic checks (schema, expiry, status field)
   * Stage 2: Signature, then status once the signature has verified (if resolvers configured)
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

    // Basic checks run on EVERY call — expiry is time-sensitive, so a warm
    // signature cache must never carry a credential past its window.
    const basicCheckStart = Date.now();
    const basicValidation = validateBasicProperties(vc);
    const basicCheckMs = Date.now() - basicCheckStart;

    if (!basicValidation.valid) {
      const result: DelegationVCVerificationResult = {
        valid: false,
        reason: basicValidation.reason,
        ...coded(basicValidation.code),
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

    // Keyed only now: a credential refused on its basic checks is never
    // looked up, so the whole of it is not canonicalized for a key.
    const cacheKey = this.cacheKeyForCredential('di', vc, options);

    // The status list is read only after the signature has verified, so a
    // credential that merely names an issuer costs no status read. A signature
    // cache hit still leaves the status read live.
    const signaturePromise = this.cachedSignature(cacheKey, () =>
      options.skipSignature
        ? Promise.resolve<SignatureCheck>({
            valid: true,
            durationMs: 0,
          })
        : verifySignature(
            vc,
            options.didResolver || this.didResolver,
            this.signatureVerifier,
            this.timeoutMs,
          ),
    );

    return this.finalizeVerification(
      signaturePromise,
      this.statusReader(vc, options),
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
   * proof), then verifies that envelope signature and, once it has verified, the
   * credential status. Same result shape, cache, and metrics as
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

    // As on the Data Integrity path, status is read only after the envelope
    // signature has verified, and live even on a signature cache hit.
    const signaturePromise = this.cachedSignature(cacheKey, () =>
      options.skipSignature
        ? Promise.resolve<SignatureCheck>({ valid: true, durationMs: 0 })
        : verifyVcJwtSignature(
            jwt,
            issuerDid,
            kid,
            options.didResolver || this.didResolver,
            this.timeoutMs,
          ),
    );

    return this.finalizeVerification(
      signaturePromise,
      this.statusReader(vc, options),
      basicCheckMs,
      startTime,
    );
  }

  /**
   * How a credential's status is read once its signature has verified, on both
   * the Data Integrity and the VC-JWT path: through the call's status-list
   * resolver, else the verifier's own, and as valid, with no read, when the
   * call skips status or the credential names none. The credential and the
   * options are read when the reader runs.
   */
  private statusReader(
    vc: DelegationCredential,
    options: VerifyDelegationVCOptions,
  ): () => Promise<StatusCheck> {
    return () =>
      !options.skipStatus && vc.credentialStatus
        ? checkCredentialStatus(
            vc.credentialStatus,
            options.statusListResolver || this.statusListResolver,
            credentialIssuerDid(vc),
            this.timeoutMs,
          )
        : Promise.resolve<StatusCheck>({
            valid: true,
            durationMs: 0,
          });
  }

  /**
   * Resolve the signature dimension: an unexpired cached result when
   * available, else `run()` — cached only when valid (failures are never
   * cached). Returned as a promise, awaited before the status is read; a hit
   * reports `durationMs: 0` (the retrieval, not the original compute).
   */
  private async cachedSignature(
    cacheKey: string | null,
    run: () => Promise<SignatureCheck>,
  ): Promise<{ result: SignatureCheck; cached: boolean }> {
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
   * Await the signature check, read the status only once the signature has
   * verified, and fold both into the final result via
   * {@link combineVerificationResult}; a status not read, after a signature
   * that failed, is reported as not checked. The combined verdict is
   * NEVER cached — only the signature dimension is (inside
   * {@link cachedSignature}) — so revocation status is consulted on every
   * call. Shared by the Data Integrity and VC-JWT paths; both reach here only
   * after `validateBasicProperties` has passed.
   */
  private async finalizeVerification(
    signaturePromise: Promise<{
      result: SignatureCheck;
      cached: boolean;
    }>,
    readStatus: () => Promise<StatusCheck>,
    basicCheckMs: number,
    startTime: number,
  ): Promise<DelegationVCVerificationResult> {
    const signature = await signaturePromise;
    const statusResult = signature.result.valid ? await readStatus() : undefined;

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

export function createDelegationVerifier(options?: DelegationCredentialVerifierOptions): DelegationCredentialVerifier {
  return new DelegationCredentialVerifier(options);
}
