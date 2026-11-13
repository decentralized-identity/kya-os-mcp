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
  isSupportedCredentialProofType,
  validateDelegationCredential,
} from "../types/protocol.js";
import { describeValue } from "../utils/describe-value.js";
import { issuerOf } from "../utils/guards.js";
import { sanitizeForMessage } from "../utils/message-text.js";
import { credentialIssuerRefusal } from "./credential-issuer.js";
import type {
  DIDResolver,
  StatusListResolver,
  StatusCheckResult,
  SignatureVerificationFunction,
  DelegationVCVerificationResult,
} from "./vc-verifier.types.js";
import { verificationMethodJwk } from "./verification-method-key.js";
import {
  ASSERTION_METHOD,
  assertionMethodRefusal,
  proofPurposeMismatch,
  selectAssertionMethod,
} from "./verification-relationship.js";

/**
 * Properties a DelegationCredential `credentialSubject` may carry. Anything
 * else is treated as a claim-intended field and rejected by default — a
 * permission credential must not smuggle claims (KYA-OS §11.6).
 */
const DELEGATION_SUBJECT_KEYS: readonly string[] = ["id", "delegation"];

/**
 * Stage 1: schema, issuer, expiry, status field, and subject-shape checks (no network).
 * The credential must name its issuer by a DID (./credential-issuer), so every
 * later stage, the key lookup included, holds the issuer's DID as a string.
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

  const issuerRefusal = credentialIssuerRefusal(vc);
  if (issuerRefusal) {
    return { valid: false, reason: issuerRefusal };
  }

  if (isDelegationCredentialExpired(vc)) {
    return { valid: false, reason: "Delegation credential expired" };
  }

  if (isDelegationCredentialNotYetValid(vc)) {
    return { valid: false, reason: "Delegation credential not yet valid" };
  }

  // Only an active delegation authorizes anything: a status outside the
  // schema's enum, or none at all, is not "active" and fails closed.
  const delegation = vc.credentialSubject.delegation;
  if (delegation.status !== "active") {
    return {
      valid: false,
      reason:
        delegation.status === undefined
          ? "Delegation status is missing"
          : `Delegation status is ${describeValue(delegation.status)}`,
    };
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
      `credentialSubject contains non-delegation field(s): ${describeValue(extraneous.join(", "))}. ` +
      `A DelegationCredential subject MUST carry only 'id' and 'delegation' (KYA-OS §11.6).`,
  };
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
  // A failed verdict names the check that failed (signature first, since a
  // bad signature makes the status answer moot); "complete" is reserved for
  // a verdict where both checks ran and passed.
  const stage: DelegationVCVerificationResult["stage"] = allValid
    ? "complete"
    : signatureResult.valid
      ? "status"
      : "signature";
  return {
    valid: allValid,
    reason: !allValid
      ? signatureResult.reason || statusResult.reason || "Unknown failure"
      : undefined,
    statusOutcome: statusResult.outcome,
    stage,
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

/**
 * Stage 2a: resolve the issuer key and verify the embedded proof signature.
 * A delegation is an assertion by its issuer, so the key is the verification
 * method `proof.verificationMethod` names, and only when the issuer's DID
 * document lists it under `assertionMethod` (W3C Controlled Identifiers v1.0
 * §3.3): a key the issuer keeps for signing in does not issue its
 * delegations. The proof options are outside the signature (SPEC.md §6.2), so
 * a `proofPurpose` binds nothing; one that names another purpose is still
 * rejected, since the proof was not made as an assertion, and one that is
 * absent is read as an assertion.
 */
export async function verifySignature(
  vc: DelegationCredential,
  didResolver: DIDResolver | undefined,
  signatureVerifier: SignatureVerificationFunction | undefined,
): Promise<{ valid: boolean; reason?: string; durationMs?: number }> {
  const startTime = Date.now();

  try {
    const issuerDid = issuerOf(vc.issuer);
    if (issuerDid === undefined) {
      return {
        valid: false,
        reason: credentialIssuerRefusal(vc),
        durationMs: Date.now() - startTime,
      };
    }

    if (!didResolver || !signatureVerifier) {
      return {
        valid: false,
        reason:
          "No DID resolver or signature verifier configured — signature cannot be verified",
        durationMs: Date.now() - startTime,
      };
    }

    // Bind the declared proof suite to one this path can actually verify. The
    // embedded-proof signature check below authenticates an Ed25519 signature
    // over `proofValue`; a credential naming an unsupported/unknown `proof.type`
    // must not verify merely because that signature happens to validate (#151).
    // Checked here, before resolving the issuer DID, so an unrecognized suite
    // fails fast without a network round-trip. The VC-JWT path skips signature
    // verification entirely (its envelope JWS is the proof), so it never reaches
    // this check and its `JwtProof2020` marker is correctly exempt.
    if (vc.proof && !isSupportedCredentialProofType(vc.proof.type)) {
      return {
        valid: false,
        reason: `Unsupported credential proof.type: ${describeValue(vc.proof.type)}`,
        durationMs: Date.now() - startTime,
      };
    }

    const purposeMismatch = proofPurposeMismatch(vc.proof, ASSERTION_METHOD);
    if (purposeMismatch) {
      return {
        valid: false,
        reason: purposeMismatch,
        durationMs: Date.now() - startTime,
      };
    }

    const didDoc = await didResolver.resolve(issuerDid);
    if (!didDoc) {
      return {
        valid: false,
        reason: `Could not resolve issuer DID: ${describeValue(issuerDid)}`,
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

    // A Data Integrity proof names its key: a DID URL of the issuer, or a `#fragment` read against it.
    const verificationMethodId: unknown = vc.proof["verificationMethod"];
    const selection = verificationMethodId === undefined
      ? undefined
      : selectAssertionMethod(didDoc, issuerDid, verificationMethodId);
    if (selection === undefined || !("method" in selection)) {
      return {
        valid: false,
        reason: selection === undefined
          ? "Proof missing verificationMethod"
          : assertionMethodRefusal(selection, "Proof verificationMethod", verificationMethodId, issuerDid),
        durationMs: Date.now() - startTime,
      };
    }

    const publicKeyJwk = verificationMethodJwk(selection.method);
    if (!publicKeyJwk) {
      return {
        valid: false,
        reason:
          "Verification method has no usable public key (publicKeyJwk / publicKeyMultibase / publicKeyBase58)",
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
      reason: `Signature verification error: ${error instanceof Error ? sanitizeForMessage(error.message) : "Unknown error"}`,
      durationMs: Date.now() - startTime,
    };
  }
}

/**
 * Stage 2b: resolve a credential's revocation status, fail-closed. Every deny is
 * labelled with a {@link StatusOutcome} so consumers can tell a settled
 * `revoked` (re-consent) from a transient `status_unresolvable` (retry):
 * a missing resolver or a resolver that throws both DENY as
 * `status_unresolvable`; a set status bit DENIES as `revoked`. The resolver is
 * told `credentialIssuer`, the issuer DID of the credential, and holds the
 * status list to it; a credential that names none cannot be held to anyone, so
 * it DENIES as `status_unresolvable` without a read.
 */
export async function checkCredentialStatus(
  status: CredentialStatus,
  statusListResolver: StatusListResolver | undefined,
  credentialIssuer: string | undefined,
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

    if (!credentialIssuer) {
      return {
        valid: false,
        reason:
          "Credential names no issuer DID to hold its status list to, so its revocation status cannot be verified",
        outcome: "status_unresolvable",
        durationMs: Date.now() - startTime,
      };
    }

    const isRevoked = await statusListResolver.checkStatus(status, { credentialIssuer });

    if (isRevoked) {
      return {
        valid: false,
        reason: `Credential revoked via ${describeValue(status.type)} (${describeValue(status.statusPurpose)})`,
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
      reason: `Status check error: ${error instanceof Error ? sanitizeForMessage(error.message) : "Unknown error"}`,
      outcome: "status_unresolvable",
      durationMs: Date.now() - startTime,
    };
  }
}
