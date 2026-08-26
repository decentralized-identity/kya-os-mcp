/**
 * KYA-OS Protocol Types
 *
 * Inlined type definitions for the KYA-OS protocol reference implementation.
 * All types are pure TypeScript — no external dependencies.
 *
 * Related Spec: KYA-OS §3, §4, §5, §6
 */

// ============================================================================
// CRISP Delegation Constraints (KYA-OS §4.2)
// ============================================================================

export interface CrispBudget {
  unit: 'USD' | 'ops' | 'points';
  cap: number;
  window?: {
    kind: 'rolling' | 'fixed';
    durationSec: number;
  };
}

export interface CrispScope {
  resource: string;
  matcher: 'exact' | 'prefix' | 'regex';
  constraints?: Record<string, unknown>;
}

export interface DelegationConstraints {
  notBefore?: number;
  notAfter?: number;
  scopes?: string[];
  audience?: string | string[];
  crisp?: {
    budget?: CrispBudget;
    scopes: CrispScope[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

// ============================================================================
// Delegation Record (KYA-OS §4.1)
// ============================================================================

export type DelegationStatus = 'active' | 'revoked' | 'expired';

export interface DelegationRecord {
  id: string;
  issuerDid: string;
  subjectDid: string;
  controller?: string;
  vcId: string;
  parentId?: string;
  constraints: DelegationConstraints;
  signature: string;
  status: DelegationStatus;
  createdAt?: number;
  revokedAt?: number;
  revokedReason?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

// ============================================================================
// W3C Verifiable Credential types
// ============================================================================

export interface Proof {
  type: string;
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  jws?: string;
  [key: string]: unknown;
}

export interface CredentialStatus {
  id: string;
  type: 'StatusList2021Entry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
  [key: string]: unknown;
}

export interface DelegationCredentialSubject {
  id: string;
  delegation: {
    id: string;
    issuerDid: string;
    subjectDid: string;
    userDid?: string;
    userIdentifier?: string;
    sessionId?: string;
    scopes?: string[];
    controller?: string;
    parentId?: string;
    constraints: DelegationConstraints;
    status: DelegationStatus;
    createdAt?: number;
    metadata?: Record<string, unknown>;
  };
}

export interface DelegationCredential {
  '@context': (string | Record<string, unknown>)[];
  id?: string;
  type: string[];
  issuer: string | { id: string; [key: string]: unknown };
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: DelegationCredentialSubject;
  credentialStatus?: CredentialStatus;
  proof?: Proof;
  [key: string]: unknown;
}

export const DELEGATION_CREDENTIAL_CONTEXT =
  'https://schema.kya-os.org/v1/protocol/delegation/context/v1.0.0' as const;

// ============================================================================
// StatusList2021 (W3C)
// ============================================================================

export interface StatusList2021Credential {
  '@context': (string | Record<string, unknown>)[];
  id: string;
  type: string[];
  issuer: string | { id: string };
  issuanceDate: string;
  credentialSubject: {
    id?: string;
    type: 'StatusList2021';
    statusPurpose: 'revocation' | 'suspension';
    encodedList: string;
  };
  proof?: Record<string, unknown>;
  [key: string]: unknown;
}

// ============================================================================
// Delegation VC utility functions
// ============================================================================

/**
 * Wrap a DelegationRecord in an unsigned W3C VC structure.
 */
export function wrapDelegationAsVC(
  delegation: DelegationRecord,
  options?: {
    id?: string;
    issuanceDate?: string;
    expirationDate?: string;
    credentialStatus?: CredentialStatus;
    userDid?: string;
    userIdentifier?: string;
    sessionId?: string;
    scopes?: string[];
  }
): Omit<DelegationCredential, 'proof'> {
  const now = new Date().toISOString();
  const expirationDate = delegation.constraints.notAfter
    ? new Date(delegation.constraints.notAfter * 1000).toISOString()
    : options?.expirationDate;

  let issuanceDate = options?.issuanceDate || now;
  if (!options?.issuanceDate && delegation.createdAt) {
    issuanceDate = new Date(delegation.createdAt).toISOString();
  }

  const scopes = options?.scopes || delegation.constraints.scopes;

  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      DELEGATION_CREDENTIAL_CONTEXT,
    ],
    id: options?.id || delegation.vcId || `urn:uuid:${delegation.id}`,
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: delegation.issuerDid,
    issuanceDate,
    ...(expirationDate !== undefined && { expirationDate }),
    credentialSubject: {
      id: delegation.subjectDid,
      delegation: {
        id: delegation.id,
        issuerDid: delegation.issuerDid,
        subjectDid: delegation.subjectDid,
        ...(options?.userDid && { userDid: options.userDid }),
        ...(options?.userIdentifier && { userIdentifier: options.userIdentifier }),
        ...(options?.sessionId && { sessionId: options.sessionId }),
        ...(scopes && scopes.length > 0 && { scopes }),
        ...(delegation.controller !== undefined && { controller: delegation.controller }),
        ...(delegation.parentId !== undefined && { parentId: delegation.parentId }),
        constraints: delegation.constraints,
        status: delegation.status,
        ...(delegation.createdAt !== undefined && { createdAt: delegation.createdAt }),
        ...(delegation.metadata !== undefined && { metadata: delegation.metadata }),
      },
    },
    ...(options?.credentialStatus !== undefined && { credentialStatus: options.credentialStatus }),
  };
}

/**
 * Read the signature from a credential's embedded proof.
 *
 * Per SPEC.md a delegation credential's proof carries its signature in
 * `proofValue`. `jws` is the field on the *detached* per-request tool-response
 * proof (a separate object) and never appears on a credential proof. Reading any
 * other field here would let extraction accept a proof shape the verifier rejects,
 * so extraction and verification share this one definition and cannot drift.
 */
export function readCredentialProofValue(
  proof: Record<string, unknown> | null | undefined,
): string {
  const value = proof?.['proofValue'];
  return typeof value === 'string' ? value : '';
}

/**
 * The credential-proof signature suites a verifier can actually check here: an
 * Ed25519 signature over the RFC 8785 (JCS) canonical credential, carried in
 * `proofValue`. `Ed25519Signature2020` and `DataIntegrityProof` (the `eddsa-jcs`
 * cryptosuite) are the two labels the reference implementation emits for that one
 * construction. A credential naming any other `proof.type` must be rejected rather
 * than pass merely because its Ed25519 signature happens to validate, so the suite
 * named in the credential is bound to the suite actually used (#151).
 */
export const SUPPORTED_CREDENTIAL_PROOF_TYPES: ReadonlySet<string> = new Set([
  'Ed25519Signature2020',
  'DataIntegrityProof',
]);

/** True iff `type` names a credential-proof suite this verifier can verify. */
export function isSupportedCredentialProofType(type: unknown): type is string {
  return typeof type === 'string' && SUPPORTED_CREDENTIAL_PROOF_TYPES.has(type);
}

/**
 * Extract a DelegationRecord from a DelegationCredential.
 */
export function extractDelegationFromVC(vc: DelegationCredential): DelegationRecord {
  // Defensive: callers may pass an untrusted/loosely-typed value. Fail with a
  // clear, controlled error instead of a cryptic "Cannot read properties of
  // undefined (reading 'delegation')" when the credential is structurally
  // malformed. validate*-style callers should shape-check first and return
  // { valid, reason } rather than relying on this throw — see
  // validateDelegationChain, which never throws on a malformed leaf.
  const delegation = vc?.credentialSubject?.delegation;
  if (!delegation || typeof delegation !== 'object') {
    throw new Error(
      'extractDelegationFromVC: credential is missing credentialSubject.delegation',
    );
  }

  const signature = readCredentialProofValue(vc.proof as Record<string, unknown> | undefined);

  return {
    id: delegation.id,
    issuerDid: delegation.issuerDid,
    subjectDid: delegation.subjectDid,
    controller: delegation.controller,
    vcId: vc.id || `vc:${delegation.id}`,
    parentId: delegation.parentId,
    constraints: delegation.constraints,
    signature,
    status: delegation.status,
    createdAt: delegation.createdAt,
    revokedAt: undefined,
    revokedReason: undefined,
    metadata: delegation.metadata,
  };
}

/**
 * Check if a DelegationCredential is expired.
 */
export function isDelegationCredentialExpired(vc: DelegationCredential): boolean {
  if (vc.expirationDate) {
    if (new Date(vc.expirationDate) < new Date()) {
      return true;
    }
  }

  const delegation = vc.credentialSubject.delegation;
  if (delegation.constraints.notAfter) {
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec > delegation.constraints.notAfter) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a DelegationCredential is not yet valid.
 */
export function isDelegationCredentialNotYetValid(vc: DelegationCredential): boolean {
  const delegation = vc.credentialSubject.delegation;

  if (delegation.constraints.notBefore) {
    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec < delegation.constraints.notBefore) {
      return true;
    }
  }

  return false;
}

/**
 * Validate a DelegationCredential.
 * Returns a Zod-compatible result shape.
 */
export function validateDelegationCredential(vc: unknown): {
  success: boolean;
  error?: { message: string };
  data?: DelegationCredential;
} {
  if (!vc || typeof vc !== 'object') {
    return { success: false, error: { message: 'Not an object' } };
  }

  const v = vc as Record<string, unknown>;

  // Check @context
  if (!Array.isArray(v['@context']) || v['@context'].length === 0) {
    return { success: false, error: { message: 'Missing or invalid @context' } };
  }
  if (v['@context'][0] !== 'https://www.w3.org/2018/credentials/v1') {
    return { success: false, error: { message: 'First @context must be W3C VC context' } };
  }

  // Check type
  if (!Array.isArray(v['type'])) {
    return { success: false, error: { message: 'Missing type array' } };
  }
  if (!v['type'].includes('VerifiableCredential') || !v['type'].includes('DelegationCredential')) {
    return { success: false, error: { message: 'type must include VerifiableCredential and DelegationCredential' } };
  }

  // Check issuer
  if (!v['issuer'] || (typeof v['issuer'] !== 'string' && typeof v['issuer'] !== 'object')) {
    return { success: false, error: { message: 'Missing or invalid issuer' } };
  }

  // Check issuanceDate
  if (!v['issuanceDate'] || typeof v['issuanceDate'] !== 'string') {
    return { success: false, error: { message: 'Missing issuanceDate' } };
  }

  // Check credentialSubject
  const cs = v['credentialSubject'] as Record<string, unknown> | undefined;
  if (!cs || typeof cs !== 'object') {
    return { success: false, error: { message: 'Missing credentialSubject' } };
  }

  if (!cs['id'] || typeof cs['id'] !== 'string') {
    return { success: false, error: { message: 'credentialSubject.id missing' } };
  }

  const del = cs['delegation'] as Record<string, unknown> | undefined;
  if (!del || typeof del !== 'object') {
    return { success: false, error: { message: 'credentialSubject.delegation missing' } };
  }

  if (!del['id'] || !del['issuerDid'] || !del['subjectDid'] || !del['constraints']) {
    return { success: false, error: { message: 'delegation fields missing' } };
  }

  return { success: true, data: vc as DelegationCredential };
}

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
  delegationRef?: string;
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

  // Validate hash fields: requestHash is always required. responseHash is
  // absent on denial / step-up proofs (no response) and validated only when present.
  if (typeof m['requestHash'] !== 'string' || !HASH_REGEX.test(m['requestHash'] as string)) {
    return { success: false, error: { message: 'meta.requestHash must match sha256:<64 hex chars>' } };
  }
  if (
    m['responseHash'] !== undefined &&
    (typeof m['responseHash'] !== 'string' || !HASH_REGEX.test(m['responseHash'] as string))
  ) {
    return {
      success: false,
      error: { message: 'meta.responseHash must match sha256:<64 hex chars> when present' },
    };
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
