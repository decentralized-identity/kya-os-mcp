/**
 * Reading a proof from a result's `_meta`: the keys KYA-OS tolerates beside its own, the meta
 * policy, and the extraction of the proof. `./verifier.ts` re-exports these, so imports from there
 * are unchanged.
 */

import {
  validateDetachedProof,
  type DetachedProof,
  type MetaPolicy,
} from "../types/protocol.js";
import { PROOF_VERIFICATION_ERROR_CODES } from "./errors.js";
import {
  KYA_OS_PROOF_META_KEY,
  LEGACY_NAMESPACED_PROOF_META_KEY,
  LEGACY_PROOF_META_KEY,
} from "./generator.js";
import { signedProofMeta } from "./payload.js";

/**
 * MCP-reserved / standard `_meta` keys a KYA-OS verifier MUST tolerate but
 * never hash or trust (MCP 2026-07-28 / SEP-414): the `io.modelcontextprotocol/*`
 * reverse-DNS namespace reserved by the MCP maintainers, and the W3C Trace
 * Context propagation keys. Allowlisted so their presence is unambiguously not a
 * cause for rejection under any policy.
 */
const RESERVED_MCP_META_PREFIXES = ['io.modelcontextprotocol/'] as const;
const RESERVED_MCP_META_KEYS = ['traceparent', 'tracestate', 'baggage'] as const;

/**
 * Whether `key` is an MCP-reserved / standard `_meta` key (SEP-414) that KYA-OS
 * tolerates: never hashed, never trusted, never a cause for rejection. Exposed
 * so adopters can classify coexisting `_meta` keys with the same allowlist the
 * verifier uses. See {@link validateMetaStructure}.
 */
export function isReservedMcpMetaKey(key: string): boolean {
  return (
    (RESERVED_MCP_META_KEYS as readonly string[]).includes(key) ||
    RESERVED_MCP_META_PREFIXES.some((prefix) => key.startsWith(prefix))
  );
}

/**
 * Validate _meta structure according to meta policy.
 *
 * The KYA-OS proof rides under {@link KYA_OS_PROOF_META_KEY} (reverse-DNS,
 * SEP-414); the prior {@link LEGACY_NAMESPACED_PROOF_META_KEY} and the legacy
 * bare {@link LEGACY_PROOF_META_KEY} are still accepted for back-compat. All
 * three are treated as the proof key. Every other key is a
 * non-KYA-OS `_meta` key.
 *
 * Under MCP 2026-07-28 `_meta` is shared real estate (it also carries
 * `io.modelcontextprotocol/*` and W3C trace-context keys), so NEITHER policy
 * rejects foreign keys: the prior `strict` reject-extras behavior would have
 * made a conformant KYA-OS verifier reject conformant RC traffic. Both policies
 * carry the identical zero-trust boundary: only the proof key is ever hashed or
 * trusted; reserved/foreign keys ({@link isReservedMcpMetaKey} and any other)
 * pass through untouched.
 *
 * - `strict` (default): non-KYA-OS keys are IGNORED (discarded): never hashed,
 *   trusted, or rejected.
 * - `allow-extensions`: identical trust boundary, but the non-KYA-OS keys are
 *   surfaced back to the caller (`extraKeys`) instead of discarded.
 *
 * @param meta - The _meta object from a response
 * @param policy - Meta policy ('strict' or 'allow-extensions')
 * @returns Validation result; always valid. Under 'allow-extensions' any
 *   non-KYA-OS keys are surfaced in `extraKeys`.
 */
export function validateMetaStructure(
  meta: Record<string, unknown>,
  policy: MetaPolicy = 'strict'
): { valid: boolean; reason?: string; extraKeys?: string[] } {
  const extraKeys = Object.keys(meta).filter(
    k =>
      k !== KYA_OS_PROOF_META_KEY &&
      k !== LEGACY_NAMESPACED_PROOF_META_KEY &&
      k !== LEGACY_PROOF_META_KEY,
  );

  // allow-extensions surfaces coexisting keys; strict discards them. Neither
  // rejects: a reserved key (io.modelcontextprotocol/*, traceparent, …) or any
  // other foreign key never fails verification.
  if (policy === 'allow-extensions' && extraKeys.length > 0) {
    return { valid: true, extraKeys };
  }

  return { valid: true };
}

/**
 * Extract proof from _meta with policy validation.
 *
 * @param meta - The _meta object from a response
 * @param policy - Meta policy ('strict' or 'allow-extensions')
 * @returns Extracted proof, with only the meta its signature covers, or error result
 */
export function extractProofFromMeta(
  meta: Record<string, unknown>,
  policy: MetaPolicy = 'strict'
): { success: true; proof: DetachedProof } | { success: false; reason: string; errorCode: string } {
  // Check for the proof field first. Prefer the canonical role-named key,
  // then the prior namespaced key, then the legacy bare key; the newest
  // canonical form wins when several are present (SPEC §7.6).
  const proof =
    meta[KYA_OS_PROOF_META_KEY] ??
    meta[LEGACY_NAMESPACED_PROOF_META_KEY] ??
    meta[LEGACY_PROOF_META_KEY];
  if (!proof) {
    return {
      success: false,
      reason: '_meta does not contain a proof',
      errorCode: PROOF_VERIFICATION_ERROR_CODES.MISSING_REQUIRED_FIELD,
    };
  }

  // Run the policy check for its semantics (strict ignores / allow-extensions
  // surfaces coexisting keys). Under MCP 2026-07-28 (SEP-414) it never rejects,
  // so it cannot block extraction; there is no policy-violation path here.
  validateMetaStructure(meta, policy);

  const proofValidation = validateDetachedProof(proof);
  if (!proofValidation.success) {
    return {
      success: false,
      reason: proofValidation.error?.message ?? 'Invalid proof structure',
      errorCode: PROOF_VERIFICATION_ERROR_CODES.INVALID_PROOF_STRUCTURE,
    };
  }

  // Only the meta the signature covers is handed on (SPEC §7.4).
  const { jws, meta: proofMeta } = proofValidation.data!;
  return { success: true, proof: { jws, meta: signedProofMeta(proofMeta) } };
}
