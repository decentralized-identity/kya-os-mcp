/**
 * VC-JWT (compact JWS) delegation verification — the high-level check.
 *
 * `utils.ts` already provides the VC-JWT PRIMITIVES (`createUnsignedVCJWT`,
 * `completeVCJWT`, `parseVCJWT`). What was missing is the high-level VERIFY:
 * resolving the issuer DID and checking the envelope signature against its
 * published key, so {@link DelegationCredentialVerifier} can accept the JWT
 * serialization of a Verifiable Credential (W3C VC Data Model 1.1 §6.3.1) — the
 * compact JWS a browser wallet mints, where the envelope signature over
 * `header.payload` IS the proof and there is no embedded Data Integrity `proof`
 * block. A verifier that only accepts embedded-proof VCs rejects that wire
 * format as "Missing proof".
 *
 * This module adds only the envelope-signature check; parsing stays in
 * `parseVCJWT`, and the extracted credential flows through the SAME downstream
 * checks (basic shape, expiry, status) as a Data Integrity VC.
 *
 * Related: W3C VC Data Model 1.1 §6.3.1 (JWT), KYA-OS §4.3
 */

import { DID_RESOLUTION_TIMEOUT_MS } from "./did-resource-limits.js";
import { checkVcJwtSignature } from "./vc-jwt-signature.js";
import type { DelegationCredential } from "../types/protocol.js";
import type {
  DIDResolver,
  DelegationVCVerificationResult,
} from "./vc-verifier.types.js";
import { credentialIssuerDid, isIssuerUrl } from "./credential-issuer.js";
import { isRecord } from "../utils/guards.js";
import { parseVCJWT, type VCJWTPayload } from "./utils.js";
import { validateBasicProperties } from "./vc-verification-checks.js";
import { describeValue } from "../utils/describe-value.js";
import { coded, refusal, type Refusal } from "../utils/refusal.js";
import type { RefusalCode } from "../refusal-codes.js";

export { credentialIssuerDid };

/** The result of a VC-JWT refused at the basic stage, as `refused` says, with how long it took. */
function jwtBasicFailure(
  refused: Refusal,
  startTime: number,
  basicCheckMs?: number,
): DelegationVCVerificationResult {
  return {
    valid: false,
    reason: refused.reason,
    ...coded(refused.code),
    stage: "basic",
    metrics:
      basicCheckMs !== undefined
        ? { basicCheckMs, totalMs: Date.now() - startTime }
        : { totalMs: Date.now() - startTime },
    checks: { basicValid: false },
  };
}

/**
 * Clock-skew allowance for `nbf` (RFC 7519 section 4.1.5 permits "some small
 * leeway"). A wallet that stamps `nbf` at issuance must not fail on a verifier
 * whose clock runs a few seconds behind. `exp` gets no leeway.
 */
export const JWT_NBF_LEEWAY_SECONDS = 30;

/**
 * JWT time claims are independent of the embedded VC's constraints (RFC 7519
 * sections 4.1.4/4.1.5). Check them on every invocation, outside the signature
 * cache. Missing claims remain compatible; a present claim must be NumericDate.
 */
function validateJwtTimeBounds(payload: VCJWTPayload, nowMs: number): Refusal | undefined {
  for (const claim of ["exp", "nbf"] as const) {
    const value = payload[claim];
    if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
      return refusal("delegation_malformed", `JWT ${claim} must be a finite NumericDate`);
    }
  }
  const nowSeconds = nowMs / 1000;
  if (payload.exp !== undefined && nowSeconds >= payload.exp) return refusal("delegation_expired", "JWT expired (exp)");
  if (payload.nbf !== undefined && nowSeconds + JWT_NBF_LEEWAY_SECONDS < payload.nbf) {
    return refusal("delegation_not_yet_valid", "JWT not yet valid (nbf)");
  }
  return undefined;
}

/**
 * Why the basic stage refuses a VC-JWT's `iss` claim, or `undefined` when it is
 * absent or a URL by the rule the credential's issuer is held to
 * ({@link isIssuerUrl}, VC Data Model 2.0 §4.7), since the issuer DID is taken
 * from `iss`. An absent `iss` is left to the consistency check, which refuses
 * it: the basic stage lets through only a credential whose issuer names a DID.
 */
function jwtIssuerRefusal(iss: unknown): Refusal | undefined {
  if (iss === undefined || (typeof iss === "string" && isIssuerUrl(iss))) return undefined;
  return refusal("delegation_malformed", `JWT iss ${describeValue(iss)} is not a URL`);
}

/** A parsed, structurally-valid VC-JWT plus the coordinates to look up its key. */
export type PreparedVcJwt =
  | {
      vc: DelegationCredential;
      issuerDid: string;
      kid: string | undefined;
      basicCheckMs: number;
    }
  | { failure: DelegationVCVerificationResult };

/**
 * Parse a VC-JWT and run the no-network fast checks: 3-part structure, the
 * basic property checks (with no embedded-`proof` requirement — the envelope is
 * the proof), and issuer↔`iss` consistency (the credential must not name an
 * issuer other than the key that signs it). Returns the validated credential
 * and its key-lookup coordinates, or a terminal `failure` at the `basic` stage.
 * The issuer DID is taken from the `iss` claim, never the inner `vc.issuer`.
 * A present `iss` must be a string, and the credential must name its issuer by
 * one (./credential-issuer), so the issuer DID returned is always a string.
 */
export function prepareVcJwtCredential(
  jwt: string,
  startTime: number,
): PreparedVcJwt {
  const parsed = parseVCJWT(jwt);
  // A JOSE header and a JWT claims set are JSON objects (RFC 7515 §4, RFC 7519 §7.2). Both
  // segments are attacker-supplied, and `null` or an array parses as valid JSON, so each is
  // checked before a member is read.
  if (
    !parsed ||
    !isRecord(parsed.header) ||
    !isRecord(parsed.payload) ||
    (parsed.header.kid !== undefined && typeof parsed.header.kid !== "string")
  ) {
    return { failure: jwtBasicFailure(refusal("delegation_malformed", "Not a valid VC-JWT (parse failed)"), startTime) };
  }

  const basicCheckStart = Date.now();
  const claimFailure =
    validateJwtTimeBounds(parsed.payload, basicCheckStart) ?? jwtIssuerRefusal(parsed.payload.iss);
  if (claimFailure) {
    return { failure: jwtBasicFailure(claimFailure, startTime, Date.now() - basicCheckStart) };
  }
  const vc = parsed.payload.vc as DelegationCredential;
  const basicValidation = validateBasicProperties(vc, {
    requireEmbeddedProof: false,
  });
  const basicCheckMs = Date.now() - basicCheckStart;

  if (!basicValidation.valid) {
    return {
      failure: jwtBasicFailure(basicValidation, startTime, basicCheckMs),
    };
  }

  if (credentialIssuerDid(vc) !== parsed.payload.iss) {
    return {
      failure: jwtBasicFailure(
        refusal("delegation_malformed", "Credential `issuer` does not match the JWT `iss` (the verified signer)"),
        startTime,
        basicCheckMs,
      ),
    };
  }

  return {
    vc,
    issuerDid: parsed.payload.iss,
    kid: parsed.header.kid,
    basicCheckMs,
  };
}

/**
 * What {@link verifyVcJwtSignature} answers: whether the envelope signature verified, and when it did
 * not, why, with the refusal's code and whether it is transient.
 */
export interface VcJwtSignatureResult {
  valid: boolean;
  reason?: string;
  durationMs: number;
  /** Why the signature was refused, as a stable value to branch on; set on every refusal. */
  code?: RefusalCode;
  /** Whether the refusal is transient; set on every refusal. */
  transient?: boolean;
}

/**
 * Verify a VC-JWT's EdDSA envelope signature against the issuer's published
 * key. Resolves `issuerDid`, selects the verification method named by `kid`
 * among those its DID document lists under `assertionMethod` (or the first of
 * those when `kid` is absent; an empty `kid` names none and is refused),
 * imports its `publicKeyJwk`, and checks
 * the compact JWS with `jose` — `algorithms` pinned to `EdDSA`, so a token
 * cannot downgrade the suite or claim `alg: none`. Fail-closed: any
 * resolution, key-import, or verification problem denies, and none throws.
 * The DID resolver gets `timeoutMs` to answer, 5,000 ms unless the caller
 * passes another. A refusal carries its code: a key the issuer's document does
 * not provide is `did_invalid`, and a signature that does not hold under it is
 * `invalid_proof`.
 */
export async function verifyVcJwtSignature(
  jwt: string,
  issuerDid: string,
  kid: string | undefined,
  didResolver: DIDResolver | undefined,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
): Promise<VcJwtSignatureResult> {
  return checkVcJwtSignature(jwt, issuerDid, kid, didResolver, timeoutMs);
}
