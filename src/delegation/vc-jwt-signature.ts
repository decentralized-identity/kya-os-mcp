/**
 * The VC-JWT envelope-signature check, with a refusal that cannot be built without its code. The
 * credential verifier reads it through {@link checkVcJwtSignature}, so the code of a refusal is typed
 * as always present; adopters call it as `verifyVcJwtSignature` (./vc-jwt-verify), whose result keeps
 * the shape it had in 1.22.0.
 */

import { compactVerify, importJWK } from "jose";
import type { JWK } from "jose";
import { DID_RESOLUTION_TIMEOUT_MS } from "./did-resource-limits.js";
import { resolveExplained, unresolvedIssuer, type ExplainedResolution } from "./did-resolution-failure.js";
import type { DIDResolver } from "./vc-verifier.types.js";
import type { SignatureCheck } from "./vc-verification-checks.js";
import { verificationMethodJwk } from "./verification-method-key.js";
import { assertionMethodRefusal, selectAssertionMethod } from "./verification-relationship.js";
import { isSmallOrderEd25519CryptoKey } from "../utils/ed25519-public-key.js";
import { describeValue } from "../utils/describe-value.js";
import { sanitizeForMessage } from "../utils/message-text.js";
import { refusal, refusalCodeOf } from "../utils/refusal.js";
import { thrownReason } from "../utils/thrown-words.js";
import type { RefusalCode } from "../refusal-codes.js";

/** The text of an error the verifier did not write, as a reason holds it: bounded and well-formed. */
function errMsg(err: unknown): string {
  return sanitizeForMessage(err instanceof Error ? err.message : String(err));
}

/**
 * Check a VC-JWT's EdDSA envelope signature against the issuer's published key, as
 * `verifyVcJwtSignature` documents, with the refusal's code and whether it is transient typed as
 * always present.
 */
export async function checkVcJwtSignature(
  jwt: string,
  issuerDid: string,
  kid: string | undefined,
  didResolver: DIDResolver | undefined,
  timeoutMs: number = DID_RESOLUTION_TIMEOUT_MS,
): Promise<SignatureCheck> {
  const startTime = Date.now();
  const durationMs = (): number => Date.now() - startTime;
  const refused = (code: RefusalCode, reason: string): SignatureCheck => ({
    ...refusal(code, reason),
    durationMs: durationMs(),
  });

  if (!didResolver) {
    return refused("configuration_error", "No DID resolver configured \u2014 signature cannot be verified");
  }

  const issuer = describeValue(issuerDid);
  let resolved: ExplainedResolution;
  try {
    resolved = await resolveExplained(didResolver, issuerDid, kid, timeoutMs);
  } catch (err) {
    // A resolver the host gave may throw its transport's words, which only the operator's log is told.
    const reason = thrownReason(err, {
      withheld: unresolvedIssuer(issuerDid),
      shown: (words) => `Could not resolve issuer DID ${issuer}: ${words}`,
      tag: "[kya-os]",
    });
    return refused(refusalCodeOf(err, "did_unavailable"), reason);
  }
  if (resolved.document === null) {
    return refused(resolved.code, `${unresolvedIssuer(issuerDid)}${resolved.why}`);
  }
  const didDoc = resolved.document;

  // VC-JOSE-COSE §4.1.1 makes `kid` a hint to the key that secured the credential; the relationship
  // is what lets that key issue it (W3C Controlled Identifiers v1.0 §3.3).
  const selection = selectAssertionMethod(didDoc, issuerDid, kid);
  if (!("method" in selection)) {
    return refused("key_not_authorized", assertionMethodRefusal(selection, "JWT kid", kid, issuerDid));
  }
  const publicKeyJwk = verificationMethodJwk(selection.method);
  if (!publicKeyJwk) {
    return refused(
      "did_invalid",
      "Verification method has no usable public key (publicKeyJwk / publicKeyMultibase / publicKeyBase58)",
    );
  }

  let key: Awaited<ReturnType<typeof importJWK>>;
  try {
    // Imported extractable whatever the JWK's own `ext` member says: a key that
    // cannot be read back escapes the small-order check below.
    key = await importJWK(publicKeyJwk as JWK, "EdDSA", { extractable: true });
  } catch (err) {
    return refused("did_invalid", `JWT envelope signature is not valid: ${errMsg(err)}`);
  }
  try {
    // jose verifies under a small-order key, where one signature fits every payload.
    if (await isSmallOrderEd25519CryptoKey(key)) {
      return refused("did_invalid", "Verification method key is a small-order Ed25519 point");
    }
    await compactVerify(jwt, key, { algorithms: ["EdDSA"] });
    return { valid: true, durationMs: durationMs() };
  } catch (err) {
    return refused("invalid_proof", `JWT envelope signature is not valid: ${errMsg(err)}`);
  }
}
