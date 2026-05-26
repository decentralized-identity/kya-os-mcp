/**
 * KYA-OS Canonical Error Codes
 *
 * Single source of truth for all wire-format error codes.
 * Aligned with the error catalog at kya-os.ai/mcp.
 *
 * Naming convention: snake_case, no protocol prefix.
 * Follows OAuth 2.0 / Stripe conventions for readability and portability.
 */

export const KYA_OS_ERROR_CODES = {
  // Proof errors
  invalid_proof: "invalid_proof",
  invalid_jws: "invalid_jws",
  nonce_replay: "nonce_replay",
  timestamp_skew: "timestamp_skew",

  // Identity / DID errors
  did_not_found: "did_not_found",
  invalid_public_key: "invalid_public_key",

  // Session / Handshake errors
  handshake_failed: "handshake_failed",
  session_expired: "session_expired",
  invalid_request: "invalid_request",

  // Delegation errors
  needs_authorization: "needs_authorization",
  insufficient_scope: "insufficient_scope",
  delegation_expired: "delegation_expired",
  delegation_not_yet_valid: "delegation_not_yet_valid",
  delegation_revoked: "delegation_revoked",
  delegation_invalid: "delegation_invalid",
  budget_exceeded: "budget_exceeded",
  rate_limit_exceeded: "rate_limit_exceeded",

  // Token errors
  invalid_token: "invalid_token",
  token_expired: "token_expired",

  // Registry errors
  mirror_pending: "mirror_pending",
  claim_failed: "claim_failed",

  // System errors
  configuration_error: "configuration_error",
  runtime_error: "runtime_error",
} as const;

export type KyaOsErrorCode =
  (typeof KYA_OS_ERROR_CODES)[keyof typeof KYA_OS_ERROR_CODES];

export interface KyaOsErrorResponse {
  code: KyaOsErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

export function createKyaOsError(
  code: KyaOsErrorCode,
  message: string,
  details?: Record<string, unknown>,
): KyaOsErrorResponse {
  return details ? { code, message, details } : { code, message };
}
