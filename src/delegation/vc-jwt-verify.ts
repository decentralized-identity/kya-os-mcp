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

import { compactVerify, importJWK } from "jose";
import type { JWK } from "jose";
import type { DelegationCredential } from "../types/protocol.js";
import type {
  DIDDocument,
  DIDResolver,
  DelegationVCVerificationResult,
} from "./vc-verifier.types.js";
import { credentialIssuerDid, isIssuerUrl } from "./credential-issuer.js";
import { parseVCJWT, type VCJWTPayload } from "./utils.js";
import { validateBasicProperties } from "./vc-verification-checks.js";
import { verificationMethodJwk } from "./verification-method-key.js";
import { assertionMethodRefusal, selectAssertionMethod } from "./verification-relationship.js";
import { isSmallOrderEd25519CryptoKey } from "../utils/ed25519-public-key.js";
import { describeValue } from "../utils/describe-value.js";
import { sanitizeForMessage } from "../utils/message-text.js";

/** The text of an error the verifier did not write, as a reason holds it: bounded and well-formed. */
function errMsg(err: unknown): string {
  return sanitizeForMessage(err instanceof Error ? err.message : String(err));
}

export { credentialIssuerDid };

function jwtBasicFailure(
  reason: string | undefined,
  startTime: number,
  basicCheckMs?: number,
): DelegationVCVerificationResult {
  return {
    valid: false,
    reason,
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
function validateJwtTimeBounds(payload: VCJWTPayload, nowMs: number): string | undefined {
  for (const claim of ["exp", "nbf"] as const) {
    const value = payload[claim];
    if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
      return `JWT ${claim} must be a finite NumericDate`;
    }
  }
  const nowSeconds = nowMs / 1000;
  if (payload.exp !== undefined && nowSeconds >= payload.exp) return "JWT expired (exp)";
  if (payload.nbf !== undefined && nowSeconds + JWT_NBF_LEEWAY_SECONDS < payload.nbf) {
    return "JWT not yet valid (nbf)";
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
function jwtIssuerRefusal(iss: unknown): string | undefined {
  if (iss === undefined || (typeof iss === "string" && isIssuerUrl(iss))) return undefined;
  return `JWT iss ${describeValue(iss)} is not a URL`;
}

/**
 * A JOSE header and a JWT claims set are JSON objects (RFC 7515 §4,
 * RFC 7519 §7.2). Both segments are attacker-supplied, and `null` or an array
 * parses as valid JSON, so check before reading a member.
 */
function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
  if (
    !parsed ||
    !isJsonObject(parsed.header) ||
    !isJsonObject(parsed.payload) ||
    (parsed.header.kid !== undefined && typeof parsed.header.kid !== "string")
  ) {
    return { failure: jwtBasicFailure("Not a valid VC-JWT (parse failed)", startTime) };
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
      failure: jwtBasicFailure(basicValidation.reason, startTime, basicCheckMs),
    };
  }

  if (credentialIssuerDid(vc) !== parsed.payload.iss) {
    return {
      failure: jwtBasicFailure(
        "Credential `issuer` does not match the JWT `iss` (the verified signer)",
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

export interface VcJwtSignatureResult {
  valid: boolean;
  reason?: string;
  durationMs: number;
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
 */
export async function verifyVcJwtSignature(
  jwt: string,
  issuerDid: string,
  kid: string | undefined,
  didResolver: DIDResolver | undefined,
): Promise<VcJwtSignatureResult> {
  const startTime = Date.now();
  const done = (valid: boolean, reason?: string): VcJwtSignatureResult => ({
    valid,
    reason,
    durationMs: Date.now() - startTime,
  });

  if (!didResolver) {
    return done(
      false,
      "No DID resolver configured — signature cannot be verified",
    );
  }

  const issuer = describeValue(issuerDid);
  let didDoc: DIDDocument | null;
  try {
    didDoc = await didResolver.resolve(issuerDid);
  } catch (err) {
    return done(false, `Could not resolve issuer DID ${issuer}: ${errMsg(err)}`);
  }
  if (!didDoc) {
    return done(false, `Could not resolve issuer DID: ${issuer}`);
  }

  // VC-JOSE-COSE §4.1.1 makes `kid` a hint to the key that secured the credential; the relationship
  // is what lets that key issue it (W3C Controlled Identifiers v1.0 §3.3).
  const selection = selectAssertionMethod(didDoc, issuerDid, kid);
  if (!("method" in selection)) {
    return done(false, assertionMethodRefusal(selection, "JWT kid", kid, issuerDid));
  }
  const publicKeyJwk = verificationMethodJwk(selection.method);
  if (!publicKeyJwk) {
    return done(
      false,
      "Verification method has no usable public key (publicKeyJwk / publicKeyMultibase / publicKeyBase58)",
    );
  }

  try {
    const key = await importJWK(publicKeyJwk as JWK, "EdDSA");
    // jose verifies under a small-order key, where one signature fits every payload.
    if (await isSmallOrderEd25519CryptoKey(key)) {
      return done(false, "Verification method key is a small-order Ed25519 point");
    }
    await compactVerify(jwt, key, { algorithms: ["EdDSA"] });
    return done(true);
  } catch (err) {
    return done(false, `JWT envelope signature is not valid: ${errMsg(err)}`);
  }
}
