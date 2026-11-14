/**
 * Delegation Credential Verifier — shared types.
 *
 * The result/option/resolver shapes for the verifier + its stateless check
 * functions. Re-exported from `./vc-verifier.ts`, so existing imports of
 * `DIDResolver` / `SignatureVerificationFunction` / … are unchanged.
 */

import type { CredentialStatus } from "../types/protocol.js";
import type { StatusCheckContext } from "../utils/statuslist-acceptance.js";

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
  /**
   * On failure, the check that failed. `complete` only ever accompanies
   * `valid: true` (both signature and status ran and passed).
   */
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
    /** Absent when the status was not checked: it is read only once the signature has verified. */
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

/**
 * A DID document as a resolver returns it. Each verification relationship lists methods by
 * reference (an absolute or relative DID URL) or embeds them (W3C Controlled Identifiers v1.0 §2.3).
 */
export interface DIDDocument {
  '@context'?: string | string[];
  id: string;
  alsoKnownAs?: string[];
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  capabilityInvocation?: (string | VerificationMethod)[];
  capabilityDelegation?: (string | VerificationMethod)[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: unknown;
  publicKeyBase58?: string;
  publicKeyMultibase?: string;
}

/**
 * Resolves a credential's status: `checkStatus` returns `true` when its status bit is set, and
 * throws when the status cannot be proven, which the verifier denies as `status_unresolvable`.
 * `context` names the credential's issuer and may name its delegation chain's pinned root and the
 * status-list URL that root's own credential names. A list's proof shows only who signed it, so a
 * resolver that verifies the proof also passes
 * `acceptStatusList(list, statusListExpectationFor(status, context, statusListIssuers))`, which
 * reads a list only from the one keeper of the entry's URL: the issuer its own `statusListIssuers`
 * configuration binds the URL or its origin to, else the pinned root when its credential names the
 * URL, else the credential's issuer.
 * `CheqdStatusListResolver` holds every list to the one DID it is configured to trust.
 * A resolver that reads the one bit at an entry's `statusListIndex` first passes
 * `acceptEntrySize(status.statusSize)`, as the library's readers do, and throws its reason for an
 * entry that is not one bit wide: such an entry keeps its status in other bits of the list.
 *
 * `DelegationCredentialVerifier`, which the delegation middleware runs for each credential of a
 * chain, names the credential's own issuer alone, never the chain's root, even when
 * `trustedRootIssuers` pins it, and denies a credential that names no issuer DID without asking. So
 * on that path a list the root signed for a re-delegated credential is refused (the verifier fails
 * closed) unless the resolver's own configuration, a `statusListIssuers` map it passes to
 * `statusListExpectationFor`, binds the list's URL or its origin to the root.
 *
 * Whether a list may be read depends on the context, so a caching wrapper must key on it as well as
 * on the entry's URL, index and purpose, as `withStatusCache` does.
 *
 * The answer is read strictly: `true` is revoked, `false` is not, and any other value, which only
 * untyped code can give, denies the credential as `status_unresolvable`. So does a `checkStatus`
 * that has not answered within the deadline a DID resolver has.
 */
export interface StatusListResolver {
  checkStatus(status: CredentialStatus, context?: StatusCheckContext): Promise<boolean>;
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
