/**
 * KYA-OS Protocol Types
 *
 * Inlined type definitions for the KYA-OS protocol reference implementation.
 * All types are pure TypeScript — no external dependencies.
 *
 * Related Spec: KYA-OS §3, §4, §5, §6
 */

export {
  DELEGATION_CREDENTIAL_CONTEXT,
  wrapDelegationAsVC,
  readCredentialProofValue,
  SUPPORTED_CREDENTIAL_PROOF_TYPES,
  isSupportedCredentialProofType,
  extractDelegationFromVC,
  isDelegationCredentialExpired,
  isDelegationCredentialNotYetValid,
  validateDelegationCredential,
} from './delegation-credential.js';
export type {
  CrispBudget,
  CrispScope,
  DelegationConstraints,
  DelegationStatus,
  DelegationRecord,
  Proof,
  CredentialStatus,
  DelegationCredentialSubject,
  DelegationCredential,
  StatusList2021Credential,
} from './delegation-credential.js';

// ============================================================================
// Handshake and Session (KYA-OS §4.5–4.9)
// ============================================================================

export interface MCPClientInfo {
  name: string;
  title?: string;
  version?: string;
  platform?: string;
  vendor?: string;
  persistentId?: string;
}

export interface MCPClientSessionInfo extends MCPClientInfo {
  clientId: string;
  protocolVersion?: string;
  capabilities?: Record<string, unknown>;
}

export interface HandshakeRequest {
  nonce: string;
  audience: string;
  timestamp: number;
  agentDid?: string;
  clientInfo?: MCPClientInfo & { clientId?: string };
  clientProtocolVersion?: string;
  clientCapabilities?: Record<string, unknown>;
}

export type SessionIdentityState = 'anonymous' | 'authenticated';

export interface SessionContext {
  sessionId: string;
  audience: string;
  nonce: string;
  timestamp: number;
  createdAt: number;
  lastActivity: number;
  ttlMinutes: number;
  agentDid?: string;
  serverDid?: string;
  clientDid?: string;
  userDid?: string;
  clientInfo?: MCPClientSessionInfo;
  identityState: SessionIdentityState;
  /** Policy for _meta field validation (default: 'strict') */
  metaPolicy?: MetaPolicy;
  oauthIdentity?: {
    provider: string;
    subject: string;
    email?: string;
    name?: string;
  };
  delegationRef?: string;
  delegationChain?: string;
  delegationScopes?: string[];
  [key: string]: unknown;
}

/**
 * Nonce cache interface for replay prevention.
 */
export interface NonceCache {
  /**
   * Optional atomic test-and-set; see NonceCacheProvider.consume. When absent,
   * handshakes fall back to has() then add() unless requireAtomicNonce is set.
   */
  consume?(nonce: string, ttlSeconds: number, agentDid?: string): Promise<boolean>;
  has(nonce: string, agentDid?: string): Promise<boolean>;
  add(nonce: string, ttl: number, agentDid?: string): Promise<void>;
  cleanup(): Promise<void>;
}

export const DEFAULT_SESSION_TTL_MINUTES = 30;
export const DEFAULT_TIMESTAMP_SKEW_SECONDS = 120;
export const NONCE_LENGTH_BYTES = 16;

/** Nonce TTL for authenticated handshakes (with agentDid) */
export const AUTH_NONCE_TTL_MS = 120_000;
/** Nonce TTL for anonymous handshakes (without agentDid) */
export const ANON_NONCE_TTL_MS = 60_000;

/**
 * Policy for non-KYA-OS `_meta` keys during proof verification (MCP 2026-07-28 /
 * SEP-414). `_meta` is shared real estate, so both policies share one zero-trust
 * boundary — only the KYA-OS proof key is ever hashed or trusted, and no foreign
 * key is ever a cause for rejection.
 * - 'strict' (default): non-KYA-OS keys (including reserved
 *   `io.modelcontextprotocol/*` and W3C trace-context keys) are ignored — never
 *   hashed, trusted, or rejected.
 * - 'allow-extensions': identical trust boundary, but non-KYA-OS keys are
 *   surfaced to the application layer instead of discarded.
 */
export type MetaPolicy = 'strict' | 'allow-extensions';

// ============================================================================
// Proof types (KYA-OS §5)
// ============================================================================

/**
 * The body profile — the implicit original response-proof profile. A body-profile proof carries
 * NO `prf` claim (its wire shape predates the discriminator); `responseHash`
 * covers the response BODY only (`response.data` = the MCP `content` array).
 * The identifier exists so configuration can name the profile explicitly.
 */
export const RESPONSE_PROOF_PROFILE_BODY = 'org.kya-os/response-proof.body';

/**
 * The envelope profile (SPEC §7.3). `responseHash`
 * covers the ENTIRE MCP result object with the top-level `_meta` member removed,
 * mirroring the request side's `{method, params minus _meta}` rule, so result
 * members like `structuredContent`, `isError`, and `resultType` are
 * authenticated. The profile is discriminated by a signature-covered `prf`
 * claim: stripping it breaks the signature, so an envelope-profile proof cannot be silently
 * downgraded to body-only semantics.
 */
export const RESPONSE_PROOF_PROFILE_ENVELOPE = 'org.kya-os/response-proof.envelope';

export type ResponseProofProfile =
  | typeof RESPONSE_PROOF_PROFILE_BODY
  | typeof RESPONSE_PROOF_PROFILE_ENVELOPE;

export interface ProofMeta {
  did: string;
  kid: string;
  ts: number;
  nonce: string;
  audience: string;
  sessionId: string;
  requestHash: string;
  responseHash?: string;
  scopeId?: string;
  /** Reference of the delegation credential the call presented (SPEC §7.8), whatever the `outcome`. */
  delegationRef?: string;
  /** Signature-covered digest of the delegation chain the server evaluated, root to leaf (SPEC §7.8). */
  delegationChainDigest?: string;
  clientDid?: string;
  outcome?: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization';
  reason?: string;
  /**
   * Response-proof profile discriminator, COVERED by the JWS signature. Present
   * with the {@link RESPONSE_PROOF_PROFILE_ENVELOPE} literal on envelope-profile proofs; ABSENT on
   * body-profile proofs (their wire shape is byte-identical to earlier releases). Verifiers
   * select the response-hash canonicalization from this claim and MUST reject
   * any other value (fail-closed — no unknown profile falls back to weaker
   * semantics).
   */
  prf?: typeof RESPONSE_PROOF_PROFILE_ENVELOPE;
}

export interface DetachedProof {
  jws: string;
  meta: ProofMeta;
}

export interface CanonicalHashes {
  requestHash: string;
  responseHash: string;
}

export interface AuditRecord {
  version: 'audit.v1';
  ts: number;
  session: string;
  audience: string;
  did: string;
  kid: string;
  reqHash: string;
  resHash: string;
  verified: 'yes' | 'no';
  scope: string;
}

// ============================================================================
// Audit types
// ============================================================================

export interface AuditContext {
  identity: {
    did: string;
    kid: string;
    [key: string]: unknown;
  };
  session: {
    sessionId: string;
    audience: string;
    [key: string]: unknown;
  };
  requestHash: string;
  responseHash?: string;
  verified: 'yes' | 'no';
  scopeId?: string;
}

export interface AuditEventContext {
  eventType: string;
  identity: {
    did: string;
    kid: string;
    [key: string]: unknown;
  };
  session: {
    sessionId: string;
    audience: string;
    [key: string]: unknown;
  };
  eventData?: Record<string, unknown>;
}

// ============================================================================
// Authorization error types (KYA-OS §6)
// ============================================================================

export interface AuthorizationDisplay {
  title?: string;
  hint?: Array<'link' | 'qr' | 'code'>;
  authorizationCode?: string;
  qrUrl?: string;
  [key: string]: unknown;
}

export interface NeedsAuthorizationError {
  error: 'needs_authorization';
  message: string;
  authorizationUrl: string;
  resumeToken: string;
  expiresAt: number;
  scopes: string[];
  display?: AuthorizationDisplay;
  context?: Record<string, unknown>;
  [key: string]: unknown;
}

export function createNeedsAuthorizationError(config: {
  message: string;
  authorizationUrl: string;
  resumeToken: string;
  expiresAt: number;
  scopes: string[];
  display?: AuthorizationDisplay;
}): NeedsAuthorizationError {
  return {
    error: 'needs_authorization',
    ...config,
  };
}

export function isNeedsAuthorizationError(error: unknown): error is NeedsAuthorizationError {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as Record<string, unknown>)['error'] === 'needs_authorization'
  );
}

/**
 * Returned when an in-scope action is high-risk and requires per-action,
 * N-of-M human (or second-identity) approval before it may proceed. The
 * client collects approval grants bound to `requestHash` and resumes via
 * `resumeToken`. Mirrors NeedsAuthorizationError, but gates a specific
 * destructive action rather than session-level authorization.
 */
export interface NeedsApprovalError {
  error: 'needs_approval';
  message: string;
  resumeToken: string;
  expiresAt: number;
  /** Approval grants MUST be bound to this requestHash (TOCTOU guard). */
  requestHash: string;
  quorum: { n: number; approvers: string[] };
  context?: Record<string, unknown>;
  [key: string]: unknown;
}

export function createNeedsApprovalError(config: {
  message: string;
  resumeToken: string;
  expiresAt: number;
  requestHash: string;
  quorum: { n: number; approvers: string[] };
  context?: Record<string, unknown>;
}): NeedsApprovalError {
  return {
    error: 'needs_approval',
    ...config,
  };
}

export function isNeedsApprovalError(error: unknown): error is NeedsApprovalError {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as Record<string, unknown>)['error'] === 'needs_approval'
  );
}

// ============================================================================
// DetachedProof validation
// ============================================================================

const HASH_REGEX = /^sha256:[a-f0-9]{64}$/;

/**
 * Validate a DetachedProof structure.
 * Returns a Zod-compatible result shape.
 */
export function validateDetachedProof(proof: unknown): {
  success: boolean;
  error?: { message: string; errors?: Array<{ message: string }> };
  data?: DetachedProof;
} {
  if (!proof || typeof proof !== 'object') {
    return { success: false, error: { message: 'Not an object' } };
  }

  const p = proof as Record<string, unknown>;

  // Validate jws
  if (typeof p['jws'] !== 'string' || p['jws'].length < 1) {
    return { success: false, error: { message: 'jws must be a non-empty string' } };
  }

  // Validate meta
  const meta = p['meta'];
  if (!meta || typeof meta !== 'object') {
    return { success: false, error: { message: 'meta must be an object' } };
  }

  const m = meta as Record<string, unknown>;

  // Required string fields
  const requiredStrings = ['did', 'kid', 'nonce', 'audience', 'sessionId'] as const;
  for (const field of requiredStrings) {
    if (typeof m[field] !== 'string' || (m[field] as string).length < 1) {
      return { success: false, error: { message: `meta.${field} must be a non-empty string` } };
    }
  }

  // Validate ts (positive integer)
  if (typeof m['ts'] !== 'number' || !Number.isInteger(m['ts']) || m['ts'] <= 0) {
    return { success: false, error: { message: 'meta.ts must be a positive integer' } };
  }

  // Validate hash fields: requestHash is always required. responseHash (absent on
  // denial / step-up proofs) and delegationChainDigest are validated only when present.
  if (typeof m['requestHash'] !== 'string' || !HASH_REGEX.test(m['requestHash'] as string)) {
    return { success: false, error: { message: 'meta.requestHash must match sha256:<64 hex chars>' } };
  }
  for (const field of ['responseHash', 'delegationChainDigest'] as const) {
    if (m[field] !== undefined && (typeof m[field] !== 'string' || !HASH_REGEX.test(m[field] as string))) {
      return { success: false, error: { message: `meta.${field} must match sha256:<64 hex chars> when present` } };
    }
  }

  // Optional string fields
  const optionalStrings = ['scopeId', 'delegationRef', 'clientDid', 'reason'] as const;
  for (const field of optionalStrings) {
    if (m[field] !== undefined && typeof m[field] !== 'string') {
      return { success: false, error: { message: `meta.${field} must be a string if present` } };
    }
  }

  // Optional outcome enum (present on denial / step-up / needs-authorization proofs)
  if (
    m['outcome'] !== undefined &&
    !['allowed', 'denied', 'step_up_required', 'needs_authorization'].includes(m['outcome'] as string)
  ) {
    return {
      success: false,
      error: {
        message:
          'meta.outcome must be one of allowed | denied | step_up_required | needs_authorization',
      },
    };
  }

  // Optional profile discriminator (envelope-profile proofs only). FAIL-CLOSED: any value
  // other than the known envelope-profile literal is rejected outright — an unknown profile
  // must never fall back to the weaker body-only response-hash semantics.
  if (m['prf'] !== undefined && m['prf'] !== RESPONSE_PROOF_PROFILE_ENVELOPE) {
    return {
      success: false,
      error: {
        message: `meta.prf must be "${RESPONSE_PROOF_PROFILE_ENVELOPE}" when present (unknown response-proof profiles are rejected fail-closed)`,
      },
    };
  }

  return {
    success: true,
    data: proof as DetachedProof,
  };
}
