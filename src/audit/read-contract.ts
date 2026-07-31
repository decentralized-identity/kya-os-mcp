import { z } from 'zod';
import {
  auditBundleConsistencyProofSchema,
  auditBundleInclusionProofSchema,
  decimalStringSchema,
  digestSchema,
  signedAuditEntrySchema,
} from './schemas.js';
import { MAX_READ_ENTRIES_LIMIT, type AuditReadEntriesPage } from './read-service.js';
import type {
  AuditBundleConsistencyProofV1,
  AuditBundleInclusionProofV1,
  AuditHead,
  AuditLedgerRef,
  DecimalString,
  SignedAuditEntryV1,
} from './types.js';

/**
 * Network wire contract for the operator-facing audit READ/replay API - the
 * request and response envelopes an HTTP or RPC transport carries. Each
 * envelope is schema-tagged (like the producer event and recorder receipt) so
 * versioning and validation are explicit at the boundary. Responses embed the
 * recorder's own signed artifacts, so a client validates the envelope here and
 * then re-verifies the artifacts with {@link AuditArtifactVerifier}.
 */

export const AUDIT_HEAD_REQUEST_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/head-request/v1.0.0' as const;
export const AUDIT_HEAD_RESPONSE_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/head-response/v1.0.0' as const;
export const AUDIT_LIST_ENTRIES_REQUEST_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/list-entries-request/v1.0.0' as const;
export const AUDIT_LIST_ENTRIES_RESPONSE_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/list-entries-response/v1.0.0' as const;
export const AUDIT_INCLUSION_PROOF_REQUEST_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/inclusion-proof-request/v1.0.0' as const;
export const AUDIT_INCLUSION_PROOF_RESPONSE_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/inclusion-proof-response/v1.0.0' as const;
export const AUDIT_CONSISTENCY_PROOF_REQUEST_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/consistency-proof-request/v1.0.0' as const;
export const AUDIT_CONSISTENCY_PROOF_RESPONSE_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/consistency-proof-response/v1.0.0' as const;

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

const ledgerRefSchema = z.object({
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
}).strict();

export const auditHeadSchema = z.object({
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  sequence: decimalStringSchema,
  entryDigest: digestSchema,
}).strict();

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

// ---------------------------------------------------------------------------
// getHead
// ---------------------------------------------------------------------------

export interface AuditHeadRequestV1 {
  schema: typeof AUDIT_HEAD_REQUEST_SCHEMA_ID;
  ledger: AuditLedgerRef;
}

export interface AuditHeadResponseV1 {
  schema: typeof AUDIT_HEAD_RESPONSE_SCHEMA_ID;
  head: AuditHead | null;
}

export const auditHeadRequestSchema = z.object({
  schema: z.literal(AUDIT_HEAD_REQUEST_SCHEMA_ID),
  ledger: ledgerRefSchema,
}).strict();

export const auditHeadResponseSchema = z.object({
  schema: z.literal(AUDIT_HEAD_RESPONSE_SCHEMA_ID),
  head: auditHeadSchema.nullable(),
}).strict();

// ---------------------------------------------------------------------------
// listEntries
// ---------------------------------------------------------------------------

export interface AuditListEntriesRequestV1 {
  schema: typeof AUDIT_LIST_ENTRIES_REQUEST_SCHEMA_ID;
  ledger: AuditLedgerRef;
  afterSequence?: DecimalString;
  limit?: number;
}

export interface AuditListEntriesResponseV1 {
  schema: typeof AUDIT_LIST_ENTRIES_RESPONSE_SCHEMA_ID;
  entries: SignedAuditEntryV1[];
  head: AuditHead | null;
  nextAfterSequence: DecimalString | null;
}

export const auditListEntriesRequestSchema = z.object({
  schema: z.literal(AUDIT_LIST_ENTRIES_REQUEST_SCHEMA_ID),
  ledger: ledgerRefSchema,
  afterSequence: decimalStringSchema.optional(),
  limit: z.number().int().positive().max(MAX_READ_ENTRIES_LIMIT).optional(),
}).strict();

export const auditListEntriesResponseSchema = z.object({
  schema: z.literal(AUDIT_LIST_ENTRIES_RESPONSE_SCHEMA_ID),
  entries: z.array(signedAuditEntrySchema),
  head: auditHeadSchema.nullable(),
  nextAfterSequence: decimalStringSchema.nullable(),
}).strict();

// ---------------------------------------------------------------------------
// getInclusionProof
// ---------------------------------------------------------------------------

export interface AuditInclusionProofRequestV1 {
  schema: typeof AUDIT_INCLUSION_PROOF_REQUEST_SCHEMA_ID;
  ledger: AuditLedgerRef;
  sequence: DecimalString;
}

export interface AuditInclusionProofResponseV1 {
  schema: typeof AUDIT_INCLUSION_PROOF_RESPONSE_SCHEMA_ID;
  proof: AuditBundleInclusionProofV1;
}

export const auditInclusionProofRequestSchema = z.object({
  schema: z.literal(AUDIT_INCLUSION_PROOF_REQUEST_SCHEMA_ID),
  ledger: ledgerRefSchema,
  sequence: decimalStringSchema,
}).strict();

export const auditInclusionProofResponseSchema = z.object({
  schema: z.literal(AUDIT_INCLUSION_PROOF_RESPONSE_SCHEMA_ID),
  proof: auditBundleInclusionProofSchema,
}).strict();

// ---------------------------------------------------------------------------
// getConsistencyProof
// ---------------------------------------------------------------------------

export interface AuditConsistencyProofRequestV1 {
  schema: typeof AUDIT_CONSISTENCY_PROOF_REQUEST_SCHEMA_ID;
  ledger: AuditLedgerRef;
  oldTreeSize: DecimalString;
}

export interface AuditConsistencyProofResponseV1 {
  schema: typeof AUDIT_CONSISTENCY_PROOF_RESPONSE_SCHEMA_ID;
  proof: AuditBundleConsistencyProofV1;
}

export const auditConsistencyProofRequestSchema = z.object({
  schema: z.literal(AUDIT_CONSISTENCY_PROOF_REQUEST_SCHEMA_ID),
  ledger: ledgerRefSchema,
  oldTreeSize: decimalStringSchema,
}).strict();

export const auditConsistencyProofResponseSchema = z.object({
  schema: z.literal(AUDIT_CONSISTENCY_PROOF_RESPONSE_SCHEMA_ID),
  proof: auditBundleConsistencyProofSchema,
}).strict();

// ---------------------------------------------------------------------------
// Parsers - validate untrusted wire input, then freeze.
// ---------------------------------------------------------------------------

export function parseAuditHeadRequest(input: unknown): AuditHeadRequestV1 {
  return deepFreeze(auditHeadRequestSchema.parse(input) as AuditHeadRequestV1);
}
export function parseAuditHeadResponse(input: unknown): AuditHeadResponseV1 {
  return deepFreeze(auditHeadResponseSchema.parse(input) as AuditHeadResponseV1);
}
export function parseAuditListEntriesRequest(input: unknown): AuditListEntriesRequestV1 {
  return deepFreeze(auditListEntriesRequestSchema.parse(input) as AuditListEntriesRequestV1);
}
export function parseAuditListEntriesResponse(input: unknown): AuditListEntriesResponseV1 {
  return deepFreeze(auditListEntriesResponseSchema.parse(input) as AuditListEntriesResponseV1);
}
export function parseAuditInclusionProofRequest(input: unknown): AuditInclusionProofRequestV1 {
  return deepFreeze(auditInclusionProofRequestSchema.parse(input) as AuditInclusionProofRequestV1);
}
export function parseAuditInclusionProofResponse(input: unknown): AuditInclusionProofResponseV1 {
  return deepFreeze(auditInclusionProofResponseSchema.parse(input) as AuditInclusionProofResponseV1);
}
export function parseAuditConsistencyProofRequest(input: unknown): AuditConsistencyProofRequestV1 {
  return deepFreeze(auditConsistencyProofRequestSchema.parse(input) as AuditConsistencyProofRequestV1);
}
export function parseAuditConsistencyProofResponse(input: unknown): AuditConsistencyProofResponseV1 {
  return deepFreeze(auditConsistencyProofResponseSchema.parse(input) as AuditConsistencyProofResponseV1);
}

// ---------------------------------------------------------------------------
// Serializers - wrap a read-service result in its wire envelope. A transport
// (e.g. an HTTP recorder) calls these to answer a request.
// ---------------------------------------------------------------------------

export function toAuditHeadResponse(head: AuditHead | null): AuditHeadResponseV1 {
  return { schema: AUDIT_HEAD_RESPONSE_SCHEMA_ID, head };
}

export function toAuditListEntriesResponse(page: AuditReadEntriesPage): AuditListEntriesResponseV1 {
  return {
    schema: AUDIT_LIST_ENTRIES_RESPONSE_SCHEMA_ID,
    entries: page.entries,
    head: page.head,
    nextAfterSequence: page.nextAfterSequence,
  };
}

export function toAuditInclusionProofResponse(
  proof: AuditBundleInclusionProofV1,
): AuditInclusionProofResponseV1 {
  return { schema: AUDIT_INCLUSION_PROOF_RESPONSE_SCHEMA_ID, proof };
}

export function toAuditConsistencyProofResponse(
  proof: AuditBundleConsistencyProofV1,
): AuditConsistencyProofResponseV1 {
  return { schema: AUDIT_CONSISTENCY_PROOF_RESPONSE_SCHEMA_ID, proof };
}
