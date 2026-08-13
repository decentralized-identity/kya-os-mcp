/**
 * Delegation Credential Verifier — shared types.
 *
 * The result/option/resolver shapes for the verifier + its stateless check
 * functions. Re-exported from `./vc-verifier.ts`, so existing imports of
 * `DIDResolver` / `SignatureVerificationFunction` / … are unchanged.
 */

import type { CredentialStatus } from "../types/protocol.js";

/**
 * Machine-readable outcome of the credential-status check. Both values still
 * DENY (fail-closed) — the label only tells the consumer *why*, so retry vs
 * re-consent can be decided:
 * - `revoked`: the status bit is set — a settled deny. Re-consent required.
 * - `status_unresolvable`: the status could not be read (resolver missing,
 *   threw, or infra unavailable). Deny now, but the credential may still be
 *   good; safe to retry once status resolution recovers.
 */
export type StatusOutcome = "revoked" | "status_unresolvable";

/**
 * The signature/DID-validity dimension of a verification — the expensive,
 * slow-changing half that the verifier caches. Shared by the Data Integrity
 * path (`verifySignature`) and the VC-JWT path (`verifyVcJwtSignature`,
 * whose `VcJwtSignatureResult` is structurally identical).
 */
export interface SignatureVerificationResult {
  valid: boolean;
  reason?: string;
  durationMs?: number;
}

export interface DelegationVCVerificationResult {
  valid: boolean;
  reason?: string;
  /**
   * Present only when a status check produced a deny. Distinguishes a settled
   * `revoked` from a transient `status_unresolvable` without weakening
   * fail-closed — both still deny (see {@link StatusOutcome}).
   */
  statusOutcome?: StatusOutcome;
  stage: "basic" | "signature" | "status" | "complete";
  /**
   * True when the SIGNATURE verification was served from the per-instance
   * cache. Basic checks (schema/expiry) and revocation status are always
   * evaluated fresh on every call — only the signature/DID-validity result
   * is ever cached. On a hit, `metrics.signatureCheckMs` reports the
   * near-zero cache retrieval, not the original compute.
   */
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
}

export interface DIDResolver {
  resolve(did: string): Promise<DIDDocument | null>;
}

export interface DIDDocument {
  '@context'?: string | string[];
  id: string;
  alsoKnownAs?: string[];
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

/**
 * Internal result of a credential-status check. `outcome` is set on every
 * deny (see {@link StatusOutcome}); it is surfaced as
 * `DelegationVCVerificationResult.statusOutcome`.
 */
export interface StatusCheckResult {
  valid: boolean;
  reason?: string;
  outcome?: StatusOutcome;
  durationMs?: number;
}

export interface SignatureVerificationFunction {
  (
    vc: import("../types/protocol.js").DelegationCredential,
    publicKeyJwk: unknown,
  ): Promise<{
    valid: boolean;
    reason?: string;
  }>;
}
