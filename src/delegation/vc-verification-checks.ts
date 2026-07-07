/**
 * Delegation Credential Verifier — stateless verification checks.
 *
 * The basic (schema/expiry/subject-shape), signature, and credential-status
 * checks, as pure functions. Extracted from `DelegationCredentialVerifier` (in
 * `./vc-verifier.ts`) so the class holds only orchestration + its cache.
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
import type {
  DIDResolver,
  DIDDocument,
  VerificationMethod,
  StatusListResolver,
  StatusCheckResult,
  SignatureVerificationFunction,
  DelegationVCVerificationResult,
} from "./vc-verifier.types.js";

/**
 * Properties a DelegationCredential `credentialSubject` may carry. Anything
 * else is treated as a claim-intended field and rejected by default — a
 * permission credential must not smuggle claims (KYA-OS §11.6).
 */
const DELEGATION_SUBJECT_KEYS: readonly string[] = ["id", "delegation"];

/**
 * Stage 1: schema, expiry, status field, and subject-shape checks (no network).
 *
 * `requireEmbeddedProof` (default `true`) demands a Data Integrity `proof`
 * block. The VC-JWT path passes `false`: a compact JWS carries no embedded
 * `proof` — its envelope signature is the proof, verified separately by
 * {@link verifyVcJwtSignature}.
 */
export function validateBasicProperties(
  vc: DelegationCredential,
  options: { requireEmbeddedProof?: boolean } = {},
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

  if ((options.requireEmbeddedProof ?? true) && !vc.proof) {
    return { valid: false, reason: "Missing proof" };
  }

  const subjectShape = validateSubjectShape(vc);
  if (!subjectShape.valid) {
    return subjectShape;
  }

  return { valid: true };
}

/**
 * Reject a delegation credential whose `credentialSubject` carries properties
 * other than `id` and `delegation`. Claim-bearing fields in a permission
 * credential separate designation from authorization — the confused-deputy
 * class (KYA-OS §11.6). Unconditional as of 1.4.0.
 */
function validateSubjectShape(vc: DelegationCredential): {
  valid: boolean;
  reason?: string;
} {
  const extraneous = Object.keys(vc.credentialSubject).filter(
    (key) => !DELEGATION_SUBJECT_KEYS.includes(key),
  );

  if (extraneous.length === 0) {
    return { valid: true };
  }

  return {
    valid: false,
    reason:
      `credentialSubject contains non-delegation field(s): ${extraneous.join(", ")}. ` +
      `A DelegationCredential subject MUST carry only 'id' and 'delegation' (KYA-OS §11.6).`,
  };
}

function findVerificationMethod(
  didDoc: DIDDocument,
  verificationMethodId: string,
): VerificationMethod | undefined {
  return didDoc.verificationMethod?.find(
    (vm) => vm.id === verificationMethodId,
  );
}

/**
 * Fold the parallel signature + status results — with the already-passed basic
 * stage — into the final verification result. Pure (no caching; the verifier
 * caches a valid result itself). Shared by the Data Integrity and VC-JWT paths,
 * which both reach here only after `validateBasicProperties` passed, so
 * `basicValid` is true.
 */
export function combineVerificationResult(
  signatureResult: { valid: boolean; reason?: string; durationMs?: number },
  statusResult: StatusCheckResult,
  basicCheckMs: number,
  startTime: number,
): DelegationVCVerificationResult {
  const allValid = signatureResult.valid && statusResult.valid;
  return {
    valid: allValid,
    reason: !allValid
      ? signatureResult.reason || statusResult.reason || "Unknown failure"
      : undefined,
    statusOutcome: statusResult.outcome,
    stage: "complete",
    metrics: {
      basicCheckMs,
      signatureCheckMs: signatureResult.durationMs || 0,
      statusCheckMs: statusResult.durationMs || 0,
      totalMs: Date.now() - startTime,
    },
    checks: {
      basicValid: true,
      signatureValid: signatureResult.valid,
      statusValid: statusResult.valid,
    },
  };
}

/** Stage 2a: resolve the issuer key and verify the embedded proof signature. */
export async function verifySignature(
  vc: DelegationCredential,
  didResolver: DIDResolver | undefined,
  signatureVerifier: SignatureVerificationFunction | undefined,
): Promise<{ valid: boolean; reason?: string; durationMs?: number }> {
  const startTime = Date.now();

  try {
    const issuerDid =
      typeof vc.issuer === "string" ? vc.issuer : vc.issuer.id;

    if (!didResolver || !signatureVerifier) {
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

    const verificationMethod = findVerificationMethod(
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

    const verificationResult = await signatureVerifier(vc, publicKeyJwk);

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

/**
 * Stage 2b: resolve a credential's revocation status, fail-closed. Every deny is
 * labelled with a {@link StatusOutcome} so consumers can tell a settled
 * `revoked` (re-consent) from a transient `status_unresolvable` (retry):
 * a missing resolver or a resolver that throws both DENY as
 * `status_unresolvable`; a set status bit DENIES as `revoked`.
 */
export async function checkCredentialStatus(
  status: CredentialStatus,
  statusListResolver: StatusListResolver | undefined,
): Promise<StatusCheckResult> {
  const startTime = Date.now();

  try {
    if (!statusListResolver) {
      return {
        valid: false,
        reason:
          "Credential has credentialStatus but no status list resolver is configured — cannot verify revocation status",
        outcome: "status_unresolvable",
        durationMs: Date.now() - startTime,
      };
    }

    const isRevoked = await statusListResolver.checkStatus(status);

    if (isRevoked) {
      return {
        valid: false,
        reason: `Credential revoked via StatusList2021 (${status.statusPurpose})`,
        outcome: "revoked",
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
      outcome: "status_unresolvable",
      durationMs: Date.now() - startTime,
    };
  }
}
