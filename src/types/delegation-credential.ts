/**
 * KYA-OS Delegation Credential Types
 *
 * The delegation record and its CRISP constraints, its W3C Verifiable Credential form, and the
 * StatusList2021 credential, with the utilities that wrap, read and check a delegation credential.
 * `protocol.ts` re-exports each of them, so `@kya-os/mcp/types` still offers them all.
 *
 * Related Spec: KYA-OS §4.2, §6
 */

import { parseDateTime } from '../utils/rfc3339.js';
import { DEFAULT_MAX_CLOCK_SKEW_MS, windowBreach } from '../utils/validity-window.js';

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
  matcher: 'exact' | 'prefix' | 'path-prefix' | 'regex';
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

/**
 * `credentialStatus` on a delegation credential. The wire schema
 * (`DelegationCredentialStatusSchema` in `card/delegation.ts`) accepts the
 * W3C Bitstring Status List v1.0 entry, the StatusList2021 successor; this
 * type matches it. `StatusList2021Entry` stays accepted for credentials
 * minted before the successor landed. `id` is optional per the Bitstring
 * spec; `statusPurpose` is required by both specs and the purpose-parity
 * check relies on it.
 */
export interface CredentialStatus {
  id?: string;
  type: 'BitstringStatusListEntry' | 'StatusList2021Entry';
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
  // { valid, reason } rather than relying on this throw; see
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

/** A bound in epoch seconds must be a finite number; anything else is unreadable. */
function isEpochSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Check if a DelegationCredential is expired. A present `expirationDate` or
 * `constraints.notAfter` that cannot be read (an impossible date, a
 * non-numeric bound) counts as expired: it is a bound, just an unreadable
 * one, and must not read as "no expiry". An `expirationDate` is read as an
 * RFC 3339 date-time with its zone (`utils/rfc3339.ts`), so it names one
 * instant on every verifier; one with no zone, which `Date.parse` would read
 * in the zone of the machine it runs on, cannot be read. It is held exactly,
 * with no clock tolerance, as a VC-JWT's `exp` is.
 */
export function isDelegationCredentialExpired(vc: DelegationCredential): boolean {
  if (vc.expirationDate !== undefined) {
    const expiresAt = parseDateTime(vc.expirationDate);
    if (expiresAt === undefined || expiresAt < Date.now()) {
      return true;
    }
  }

  const notAfter = vc.credentialSubject.delegation.constraints?.notAfter;
  if (notAfter !== undefined) {
    const nowSec = Math.floor(Date.now() / 1000);
    if (!isEpochSeconds(notAfter) || nowSec > notAfter) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a DelegationCredential is not yet valid: before its `issuanceDate`,
 * "the date and time the credential becomes valid" (VC Data Model 1.1 §4.6),
 * or before `constraints.notBefore`. An `issuanceDate` is read as
 * `expirationDate` is, and one that cannot be read counts as not yet valid. An
 * issuer stamps it with the moment it signs, so it is held with the tolerance
 * the start of a status list's window is (`utils/validity-window.ts`). A
 * present `constraints.notBefore` that is not a finite number counts as not
 * yet valid.
 */
export function isDelegationCredentialNotYetValid(vc: DelegationCredential): boolean {
  const issuedAt = parseDateTime(vc.issuanceDate);
  if (issuedAt === undefined || windowBreach(issuedAt, undefined, Date.now(), DEFAULT_MAX_CLOCK_SKEW_MS) !== undefined) {
    return true;
  }

  const notBefore = vc.credentialSubject.delegation.constraints?.notBefore;
  if (notBefore === undefined) {
    return false;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  return !isEpochSeconds(notBefore) || nowSec < notBefore;
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
