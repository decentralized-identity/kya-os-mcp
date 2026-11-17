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
import { answerWithinDeadline } from "../utils/deadline.js";
import { describeValue } from "../utils/describe-value.js";
import { issuerOf } from "../utils/guards.js";
import { carryingContext } from "../utils/status-check-carrier.js";
import { readVerdict } from "../utils/verdict.js";
import { coded, refusal, refusalCodeOf, type Checked, type Refusal } from "../utils/refusal.js";
import type { RefusalCode } from "../refusal-codes.js";
import { credentialIssuerRefusal } from "./credential-issuer.js";
import { DID_RESOLUTION_TIMEOUT_MS } from "./did-resource-limits.js";
import { resolveExplained, unresolvedIssuer, type ExplainedResolution } from "./did-resolution-failure.js";
import { WRAPPED_REASON_LENGTH, readRevoked, unreadableStatusReason } from "../utils/revocation-answer.js";
import { thrownReason, unreadStatusList } from "../utils/thrown-words.js";
import type {
  DIDResolver,
  StatusListResolver,
  StatusOutcome,
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

/** What the signature check comes to, with how long it took. */
export type SignatureCheck = Checked & { readonly durationMs: number };

/** What the status check comes to, with how long it took; a refusal also says whether the status is settled. */
export type StatusCheck =
  | { readonly valid: true; readonly durationMs: number }
  | (Refusal & { readonly outcome: StatusOutcome; readonly durationMs: number });

/**
 * Stage 1: schema, issuer, expiry, status field, and subject-shape checks (no network).
 * The credential must name its issuer by a DID (./credential-issuer), so every
 * later stage, the key lookup included, holds the issuer's DID as a string.
 *
 * `requireEmbeddedProof` (default `true`) demands a Data Integrity `proof`
 * block. The VC-JWT path passes `false`: a compact JWS carries no embedded
 * `proof` — its envelope signature is the proof, verified separately by
 * `checkVcJwtSignature` (./vc-jwt-signature).
 */
export function validateBasicProperties(
  vc: DelegationCredential,
  options: { requireEmbeddedProof?: boolean } = {},
): Checked {
  const schemaValidation = validateDelegationCredential(vc);
  if (!schemaValidation.success) {
    return refusal("delegation_malformed", `Schema validation failed: ${schemaValidation.error?.message}`);
  }

  const issuerRefusal = credentialIssuerRefusal(vc);
  if (issuerRefusal) {
    return refusal("delegation_malformed", issuerRefusal);
  }

  if (isDelegationCredentialExpired(vc)) {
    return refusal("delegation_expired", "Delegation credential expired");
  }

  if (isDelegationCredentialNotYetValid(vc)) {
    return refusal("delegation_not_yet_valid", "Delegation credential not yet valid");
  }

  // Only an active delegation authorizes anything: a status outside the
  // schema's enum, or none at all, is not "active" and fails closed.
  const delegation = vc.credentialSubject.delegation;
  if (delegation.status !== "active") {
    return delegation.status === undefined
      ? refusal("delegation_malformed", "Delegation status is missing")
      : refusal(delegationStatusCode(delegation.status), `Delegation status is ${describeValue(delegation.status)}`);
  }

  if (!delegation.issuerDid || !delegation.subjectDid) {
    return refusal("delegation_malformed", "Missing issuer or subject DID");
  }

  if ((options.requireEmbeddedProof ?? true) && !vc.proof) {
    return refusal("delegation_malformed", "Missing proof");
  }

  return validateSubjectShape(vc);
}

/**
 * The code of a delegation whose `status` is `status`, not `active`: a revoked or an expired one is
 * refused as such, and any other status, which the schema does not know, is malformed.
 */
function delegationStatusCode(status: unknown): RefusalCode {
  if (status === "revoked") return "delegation_revoked";
  if (status === "expired") return "delegation_expired";
  return "delegation_malformed";
}

/**
 * Reject a delegation credential whose `credentialSubject` carries properties
 * other than `id` and `delegation`. Claim-bearing fields in a permission
 * credential separate designation from authorization — the confused-deputy
 * class (KYA-OS §11.6). Unconditional as of 1.4.0.
 */
function validateSubjectShape(vc: DelegationCredential): Checked {
  const extraneous = Object.keys(vc.credentialSubject).filter(
    (key) => !DELEGATION_SUBJECT_KEYS.includes(key),
  );

  if (extraneous.length === 0) {
    return { valid: true };
  }

  return refusal(
    "delegation_malformed",
    `credentialSubject contains non-delegation field(s): ${describeValue(extraneous.join(", "))}. ` +
      `A DelegationCredential subject MUST carry only 'id' and 'delegation' (KYA-OS §11.6).`,
  );
}

/**
 * Fold the signature result, the status result read after it, and the
 * already-passed basic stage into the final verification result. Pure (no caching; the verifier
 * caches a valid result itself). Shared by the Data Integrity and VC-JWT paths,
 * which both reach here only after `validateBasicProperties` passed, so
 * `basicValid` is true. A status left unread (`undefined`, after a signature
 * that failed) is not checked: `checks` then has no `statusValid`. A refusal
 * carries the code of the check that refused.
 */
export function combineVerificationResult(
  signatureResult: SignatureCheck,
  statusResult: StatusCheck | undefined,
  basicCheckMs: number,
  startTime: number,
): DelegationVCVerificationResult {
  const allValid = signatureResult.valid && statusResult?.valid === true;
  const refused = !signatureResult.valid ? signatureResult : statusResult?.valid === false ? statusResult : undefined;
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
    reason: !allValid ? refused?.reason || "Unknown failure" : undefined,
    // A status that was never read, after a signature that verified, cannot happen; were it to,
    // the verification faulted and reached no verdict.
    ...(!allValid && coded(refused?.code ?? "runtime_error")),
    statusOutcome: statusResult?.valid === false ? statusResult.outcome : undefined,
    stage,
    metrics: {
      basicCheckMs,
      signatureCheckMs: signatureResult.durationMs || 0,
      statusCheckMs: statusResult?.durationMs || 0,
      totalMs: Date.now() - startTime,
    },
    checks: {
      basicValid: true,
      signatureValid: signatureResult.valid,
      ...(statusResult && { statusValid: statusResult.valid }),
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
 * absent is read as an assertion. The DID resolver and the signature verifier
 * each get `timeoutMs` to answer, by default 5,000 ms.
 */
export async function verifySignature(
  vc: DelegationCredential,
  didResolver: DIDResolver | undefined,
  signatureVerifier: SignatureVerificationFunction | undefined,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
): Promise<SignatureCheck> {
  const startTime = Date.now();
  const timed = (check: Checked): SignatureCheck => ({ ...check, durationMs: Date.now() - startTime });
  const refused = (code: RefusalCode, reason: string | undefined): SignatureCheck =>
    timed({ valid: false, reason, ...coded(code) });

  try {
    const issuerDid = issuerOf(vc.issuer);
    if (issuerDid === undefined) {
      return refused("delegation_malformed", credentialIssuerRefusal(vc));
    }

    if (!didResolver || !signatureVerifier) {
      return refused(
        "configuration_error",
        "No DID resolver or signature verifier configured \u2014 signature cannot be verified",
      );
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
      return refused("invalid_proof", `Unsupported credential proof.type: ${describeValue(vc.proof.type)}`);
    }

    const purposeMismatch = proofPurposeMismatch(vc.proof, ASSERTION_METHOD);
    if (purposeMismatch) {
      return refused("key_not_authorized", purposeMismatch);
    }

    const keyId = typeof vc.proof?.verificationMethod === "string" ? vc.proof.verificationMethod : undefined;
    let resolved: ExplainedResolution;
    try {
      resolved = await resolveExplained(didResolver, issuerDid, keyId, timeoutMs);
    } catch (error) {
      // A resolver that throws, or does not answer in time, leaves the document unread.
      return refused(refusalCodeOf(error, "did_unavailable"), signatureErrorReason(error, unresolvedIssuer(issuerDid)));
    }
    if (resolved.document === null) {
      return refused(resolved.code, `${unresolvedIssuer(issuerDid)}${resolved.why}`);
    }
    const didDoc = resolved.document;

    if (!vc.proof) {
      return refused("delegation_malformed", "Proof is missing");
    }

    // A Data Integrity proof names its key: a DID URL of the issuer, or a `#fragment` read against it.
    const verificationMethodId: unknown = vc.proof["verificationMethod"];
    const selection = verificationMethodId === undefined
      ? undefined
      : selectAssertionMethod(didDoc, issuerDid, verificationMethodId);
    if (selection === undefined || !("method" in selection)) {
      return refused(
        "key_not_authorized",
        selection === undefined
          ? "Proof missing verificationMethod"
          : assertionMethodRefusal(selection, "Proof verificationMethod", verificationMethodId, issuerDid),
      );
    }

    const publicKeyJwk = verificationMethodJwk(selection.method);
    if (!publicKeyJwk) {
      return refused(
        "did_invalid",
        "Verification method has no usable public key (publicKeyJwk / publicKeyMultibase / publicKeyBase58)",
      );
    }

    // The verifier is the host's code: its answer verifies only as the literal `true`.
    const answer: unknown = await answerWithinDeadline("the signature verifier", () =>
      signatureVerifier(vc, publicKeyJwk),
    timeoutMs);

    return timed(readVerdict("the signature verifier", answer, "invalid_proof"));
  } catch (error) {
    return refused(refusalCodeOf(error, "runtime_error"), signatureErrorReason(error, UNCHECKED_SIGNATURE));
  }
}

/** What a refusal of a signature check says where a step threw words that may not reach it. */
const UNCHECKED_SIGNATURE = "Signature verification error: the signature could not be checked";

/**
 * The reason a signature check that threw `error` is refused with: `Signature verification error:`
 * and its words, where they may reach whoever presented the credential (`utils/thrown-words.ts`),
 * as a `RefusalError`'s or a deadline's may; otherwise `withheld`, with the words logged, since a
 * DID resolver or a signature verifier the host gave may have thrown its transport's words.
 */
function signatureErrorReason(error: unknown, withheld: string): string {
  return thrownReason(error, { withheld, shown: (words) => `Signature verification error: ${words}`, tag: "[kya-os]" });
}

/**
 * Stage 2b: resolve a credential's revocation status, fail-closed. Every deny is
 * labelled with a {@link StatusOutcome} so consumers can tell a settled
 * `revoked` (re-consent) from a transient `status_unresolvable` (retry):
 * a missing resolver, a resolver that throws and one that has not answered
 * within `timeoutMs` all DENY as `status_unresolvable`, and so
 * does a resolver whose answer is not a boolean;
 * only a literal `true` DENIES as `revoked`. The resolver is
 * told `credentialIssuer`, the issuer DID of the credential, and holds the
 * status list to it; a credential that names none cannot be held to anyone, so
 * it DENIES as `status_unresolvable` without a read. The context is passed as
 * the second argument and carried by the copy of the entry passed as the first
 * (`carryingContext`). A resolver that throws a `RefusalError` is refused with
 * its code and its message, at most `WRAPPED_REASON_LENGTH` UTF-16 code units
 * of it, so a library checker's reason it wrapped in words of its own still
 * ends whole; any other throw is refused naming the list and saying only that
 * it could not be read, its message logged (`utils/thrown-words.ts`).
 */
export async function checkCredentialStatus(
  status: CredentialStatus,
  statusListResolver: StatusListResolver | undefined,
  credentialIssuer: string | undefined,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
): Promise<StatusCheck> {
  const startTime = Date.now();
  const refused = (code: RefusalCode, reason: string, outcome: StatusOutcome = "status_unresolvable"): StatusCheck => ({
    ...refusal(code, reason),
    outcome,
    durationMs: Date.now() - startTime,
  });

  try {
    if (!statusListResolver) {
      return refused(
        "configuration_error",
        "Credential has credentialStatus but no status list resolver is configured \u2014 cannot verify revocation status",
      );
    }

    if (!credentialIssuer) {
      return refused(
        "delegation_malformed",
        "Credential names no issuer DID to hold its status list to, so its revocation status cannot be verified",
      );
    }

    const context = { credentialIssuer };
    const answer: unknown = await answerWithinDeadline("the status list resolver", () =>
      statusListResolver.checkStatus(carryingContext(status, context), context),
    timeoutMs);
    const revoked = readRevoked(answer);

    if (revoked === undefined) {
      return refused("status_unavailable", unreadableStatusReason(answer));
    }

    if (revoked) {
      return refused(
        "delegation_revoked",
        `Credential revoked via ${describeValue(status.type)} (${describeValue(status.statusPurpose)})`,
        "revoked",
      );
    }

    return {
      valid: true,
      durationMs: Date.now() - startTime,
    };
  } catch (error) {
    return refused(
      refusalCodeOf(error, "status_unavailable"),
      `Status check error: ${thrownReason(error, { withheld: unreadStatusList(status.statusListCredential), tag: "[kya-os]", maxLength: WRAPPED_REASON_LENGTH })}`,
    );
  }
}
