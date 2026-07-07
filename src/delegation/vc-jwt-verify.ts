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
  DIDResolver,
  VerificationMethod,
  DelegationVCVerificationResult,
} from "./vc-verifier.types.js";
import { parseVCJWT } from "./utils.js";
import { validateBasicProperties } from "./vc-verification-checks.js";

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The credential's own declared issuer as a DID string (VC `issuer` may be a
 * string or an object with `id`). `undefined` when absent/malformed. The
 * verifier requires this to equal the JWT `iss` — a credential must not claim
 * an issuer other than the key that actually signed the envelope.
 */
export function credentialIssuerDid(
  credential: DelegationCredential,
): string | undefined {
  const iss = credential.issuer;
  if (typeof iss === "string") return iss;
  if (iss && typeof iss === "object" && typeof iss.id === "string") {
    return iss.id;
  }
  return undefined;
}

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
 */
export function prepareVcJwtCredential(
  jwt: string,
  startTime: number,
): PreparedVcJwt {
  const parsed = parseVCJWT(jwt);
  if (!parsed) {
    return { failure: jwtBasicFailure("Not a valid VC-JWT (parse failed)", startTime) };
  }

  const basicCheckStart = Date.now();
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

function selectVerificationMethod(
  methods: VerificationMethod[],
  kid: string | undefined,
): VerificationMethod | undefined {
  return kid ? methods.find((m) => m.id === kid) : methods[0];
}

/**
 * Verify a VC-JWT's EdDSA envelope signature against the issuer's published
 * key. Resolves `issuerDid`, selects the verification method named by `kid`
 * (or the first when `kid` is absent), imports its `publicKeyJwk`, and checks
 * the compact JWS with `jose` — `algorithms` pinned to `EdDSA`, so a token
 * cannot downgrade the suite or claim `alg: none`. Fail-closed: any
 * resolution, key-import, or verification problem denies.
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

  const didDoc = await didResolver.resolve(issuerDid);
  if (!didDoc) {
    return done(false, `Could not resolve issuer DID: ${issuerDid}`);
  }

  const vm = selectVerificationMethod(didDoc.verificationMethod ?? [], kid);
  if (!vm) {
    return done(
      false,
      kid
        ? `Verification method ${kid} not found in DID Document`
        : "DID Document has no verification method",
    );
  }
  if (!vm.publicKeyJwk) {
    return done(false, "Verification method missing publicKeyJwk");
  }

  try {
    const key = await importJWK(vm.publicKeyJwk as JWK, "EdDSA");
    await compactVerify(jwt, key, { algorithms: ["EdDSA"] });
    return done(true);
  } catch (err) {
    return done(false, `JWT envelope signature is not valid: ${errMsg(err)}`);
  }
}
