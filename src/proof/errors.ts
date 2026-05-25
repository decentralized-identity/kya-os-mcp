/**
 * Proof Verification Error Codes and Types
 *
 * Specific error codes for proof verification failures to enable
 * better error handling and debugging.
 */

/**
 * Error codes for proof verification
 */
export const PROOF_VERIFICATION_ERROR_CODES = {
  // Proof structure errors
  INVALID_PROOF_STRUCTURE: "INVALID_PROOF_STRUCTURE",
  MISSING_REQUIRED_FIELD: "MISSING_REQUIRED_FIELD",

  // Security errors
  NONCE_REPLAY_DETECTED: "NONCE_REPLAY_DETECTED",
  TIMESTAMP_SKEW_EXCEEDED: "TIMESTAMP_SKEW_EXCEEDED",
  TIMESTAMP_INVALID: "TIMESTAMP_INVALID",

  // Signature errors
  INVALID_JWS_SIGNATURE: "INVALID_JWS_SIGNATURE",
  INVALID_JWS_FORMAT: "INVALID_JWS_FORMAT",
  INVALID_JWS_HEADER: "INVALID_JWS_HEADER",
  INVALID_JWS_PAYLOAD: "INVALID_JWS_PAYLOAD",
  INVALID_JWS_SIGNATURE_BASE64: "INVALID_JWS_SIGNATURE_BASE64",
  UNSUPPORTED_ALGORITHM: "UNSUPPORTED_ALGORITHM",

  // JWK errors
  INVALID_JWK_FORMAT: "INVALID_JWK_FORMAT",
  INVALID_JWK_KTY: "INVALID_JWK_KTY",
  INVALID_JWK_CRV: "INVALID_JWK_CRV",
  INVALID_JWK_X_FIELD: "INVALID_JWK_X_FIELD",
  INVALID_JWK_KEY_LENGTH: "INVALID_JWK_KEY_LENGTH",
  JWK_KID_MISMATCH: "JWK_KID_MISMATCH",

  // DID resolution errors
  DID_RESOLUTION_FAILED: "DID_RESOLUTION_FAILED",
  DID_DOCUMENT_NOT_FOUND: "DID_DOCUMENT_NOT_FOUND",
  VERIFICATION_METHOD_NOT_FOUND: "VERIFICATION_METHOD_NOT_FOUND",
  PUBLIC_KEY_NOT_FOUND: "PUBLIC_KEY_NOT_FOUND",
  UNSUPPORTED_DID_METHOD: "UNSUPPORTED_DID_METHOD",

  // Meta policy errors
  META_POLICY_VIOLATION: "META_POLICY_VIOLATION",

  // Generic errors
  VERIFICATION_ERROR: "VERIFICATION_ERROR",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;

export type ProofVerificationErrorCode =
  typeof PROOF_VERIFICATION_ERROR_CODES[keyof typeof PROOF_VERIFICATION_ERROR_CODES];

/**
 * Proof verification error with specific error code
 */
export class ProofVerificationError extends Error {
  constructor(
    public readonly code: ProofVerificationErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "ProofVerificationError";
  }
}

/**
 * Create a proof verification error
 */
export function createProofVerificationError(
  code: ProofVerificationErrorCode,
  message: string,
  details?: Record<string, unknown>
): ProofVerificationError {
  return new ProofVerificationError(code, message, details);
}
