import { z } from 'zod';
import type {
  AuditBundleManifestCoreV1,
  AuditCheckpointCoreV1,
  AuditEntryCoreV1,
  AuditEventFamily,
  AuditProducerEventCoreV1,
  AuditRecorderReceiptCoreV1,
  AuditObservationReceiptV1,
  AuditReplayBundleV1,
  AuditVerificationPolicyV1,
  SignedAuditEntryV1,
  SignedAuditCheckpointV1,
} from './types.js';
import { AUDIT_EVENT_TYPES } from './types.js';
import { assertCanonicalJsonValue } from '../utils/canonical-json.js';

export const AUDIT_EVENT_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0' as const;
export const AUDIT_ENTRY_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0' as const;
export const AUDIT_RECEIPT_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0' as const;
export const AUDIT_INTEGRITY_SUITE = 'KYA-AUDIT-JCS-SHA256-JWS-2026' as const;
export const AUDIT_CHECKPOINT_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/checkpoint/v1.0.0' as const;
export const AUDIT_CHECKPOINT_INTEGRITY_SUITE =
  'KYA-AUDIT-RFC9162-SHA256-JWS-2026' as const;
export const AUDIT_BUNDLE_MANIFEST_SCHEMA_ID =
  'https://schema.kya-os.org/v1/protocol/audit/bundle-manifest/v1.0.0' as const;
export const AUDIT_BUNDLE_INTEGRITY_SUITE =
  'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026' as const;

const MAX_DECIMAL_LENGTH = 20;
const MAX_REFERENCE_LENGTH = 256;
const MAX_DID_LENGTH = 2048;
const MAX_JWS_LENGTH = 4096;
const MAX_RECEIPT_DATA_LENGTH = 65_536;

const decimalStringSchema = z.string().max(MAX_DECIMAL_LENGTH).regex(/^(0|[1-9][0-9]*)$/);
export const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const didSchema = z.string()
  .min(5)
  .max(MAX_DID_LENGTH)
  .regex(/^did:[^\r\n]+$/);

export const signerRefSchema = z.object({
  did: didSchema,
  kid: z.string().min(1).max(MAX_DID_LENGTH + MAX_REFERENCE_LENGTH),
  alg: z.enum(['EdDSA', 'ES256']),
}).strict();

export const evidenceRefSchema: z.ZodType = z.object({
  objectId: z.string().min(1).max(MAX_REFERENCE_LENGTH),
  ciphertextDigest: digestSchema,
  plaintextCommitment: digestSchema.optional(),
  mediaType: z.string().min(1).max(MAX_REFERENCE_LENGTH),
  size: decimalStringSchema,
  encryption: z.object({
    suite: z.literal('A256GCM'),
    keyId: z.string().min(1).max(MAX_REFERENCE_LENGTH),
    nonce: z.string().min(1).max(MAX_REFERENCE_LENGTH),
    aadDigest: digestSchema,
  }).strict(),
}).strict();

export const partyRefSchema: z.ZodType = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('public_did'), did: didSchema }).strict(),
  z.object({ kind: z.literal('pairwise_did'), did: didSchema }).strict(),
  z.object({
    kind: z.literal('keyed_commitment'),
    value: digestSchema,
    keyId: z.string().min(1).max(MAX_REFERENCE_LENGTH),
  }).strict(),
  z.object({ kind: z.literal('evidence_ref'), ref: evidenceRefSchema }).strict(),
]);

const detailsSchemas = [
  z.object({
    family: z.literal('session'),
    phase: z.enum(['established', 'rejected', 'expired', 'replay_rejected']),
    reasonCode: z.string().min(1).max(128).optional(),
  }).strict(),
  z.object({
    family: z.literal('tool'),
    phase: z.enum(['started', 'completed', 'failed', 'denied', 'challenged']),
    attempt: decimalStringSchema,
    idempotencyRef: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  }).strict(),
  z.object({
    family: z.literal('proof'),
    phase: z.enum(['generated', 'verified', 'rejected']),
    proofDigest: digestSchema.optional(),
    verificationCode: z.string().min(1).max(128).optional(),
  }).strict(),
  z.object({
    family: z.literal('delegation'),
    phase: z.enum(['issued', 'verified', 'rejected', 'revoked', 'cascade_revoked', 'outbound_attached']),
    delegationRef: z.string().min(1).max(MAX_REFERENCE_LENGTH),
    parentRef: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
    statusEvidence: z.array(evidenceRefSchema).max(256).optional(),
  }).strict(),
  z.object({
    family: z.literal('authorization'),
    phase: z.enum(['evaluated', 'approved', 'denied', 'step_up_required', 'grant_used']),
    policyDigest: digestSchema.optional(),
    grantRef: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  }).strict(),
  z.object({
    family: z.literal('consent'),
    phase: z.enum(['requested', 'approved', 'denied', 'credential_required', 'credential_verified', 'credential_failed']),
    consentRef: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  }).strict(),
  z.object({
    family: z.literal('key'),
    phase: z.enum(['rotated', 'policy_changed', 'configuration_changed', 'integrity_suite_transitioned']),
    previousSigner: signerRefSchema.optional(),
    nextSigner: signerRefSchema.optional(),
    configurationDigest: digestSchema.optional(),
  }).strict(),
  z.object({
    family: z.literal('ledger'),
    phase: z.enum(['epoch_started', 'epoch_transitioned', 'checkpoint_created', 'checkpoint_anchored', 'checkpoint_anchor_failed', 'evidence_disposed', 'projection_reconciled']),
    checkpointDigest: digestSchema.optional(),
    previousEpochId: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
    previousTerminalCheckpointDigest: digestSchema.optional(),
    successorEpochIds: z.array(z.string().min(1).max(MAX_REFERENCE_LENGTH)).max(256).optional(),
    targetEvidenceRef: evidenceRefSchema.optional(),
  }).strict(),
  z.object({
    family: z.literal('administration'),
    phase: z.enum(['source_high_water', 'accessed', 'exported', 'legal_hold_applied', 'retention_executed']),
    purpose: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
    sourceSequence: decimalStringSchema.optional(),
    selectionDigest: digestSchema.optional(),
  }).strict(),
] as const;

const auditEventDetailsSchema = z.discriminatedUnion('family', detailsSchemas);

const authorizationEvidenceSchema = z.object({
  source: z.enum(['delegation', 'grant', 'anonymous', 'policy']),
  decision: z.enum(['allowed', 'denied', 'step_up_required', 'needs_authorization']),
  scopeId: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  delegationRef: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  delegationCredentialDigest: digestSchema.optional(),
  delegationChainDigests: z.array(digestSchema).max(256).optional(),
  statusEvidence: z.array(evidenceRefSchema).max(256).optional(),
  grantRef: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  policyId: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  policyVersion: z.string().min(1).max(MAX_REFERENCE_LENGTH).optional(),
  policyDigest: digestSchema.optional(),
  verificationCode: z.string().min(1).max(128).optional(),
}).strict();

function expectedFamily(eventType: string): AuditEventFamily {
  if (eventType.startsWith('session.')) return 'session';
  if (eventType.startsWith('tool.')) return 'tool';
  if (eventType.startsWith('proof.')) return 'proof';
  if (eventType.startsWith('delegation.')) return 'delegation';
  if (eventType.startsWith('authorization.') || eventType === 'grant.used') return 'authorization';
  if (eventType.startsWith('consent.') || eventType.startsWith('credential.')) return 'consent';
  if (
    eventType.startsWith('key.') ||
    eventType.startsWith('policy.') ||
    eventType.startsWith('configuration.') ||
    eventType.startsWith('integrity_suite.')
  ) return 'key';
  if (
    eventType.startsWith('ledger.') ||
    eventType.startsWith('checkpoint.') ||
    eventType.startsWith('evidence.') ||
    eventType.startsWith('projection.')
  ) return 'ledger';
  return 'administration';
}

export const auditProducerEventSchema = z.object({
  schema: z.literal(AUDIT_EVENT_SCHEMA_ID),
  eventId: z.string().min(1).max(256),
  eventType: z.enum(AUDIT_EVENT_TYPES),
  eventVersion: z.literal('1.0.0'),
  binding: z.string().max(MAX_REFERENCE_LENGTH)
    .regex(/^urn:kya-os:audit-binding:[a-z0-9][a-z0-9._:-]*$/),
  occurredAt: z.number().int().nonnegative(),
  tenantRef: partyRefSchema,
  source: z.object({
    producer: partyRefSchema,
    sourceId: z.string().min(1).max(256),
    sourceSequence: decimalStringSchema.optional(),
    previousSourceEventDigest: digestSchema.optional(),
  }).strict(),
  correlationId: z.string().min(1).max(256).optional(),
  causationId: z.string().min(1).max(256).optional(),
  trace: z.object({
    traceId: z.string().regex(/^[a-f0-9]{32}$/).optional(),
    spanId: z.string().regex(/^[a-f0-9]{16}$/).optional(),
  }).strict().optional(),
  session: z.object({
    ref: partyRefSchema,
    handshakeNonceCommitment: digestSchema.optional(),
  }).strict().optional(),
  actor: partyRefSchema.optional(),
  responsibleParty: partyRefSchema.optional(),
  resource: partyRefSchema.optional(),
  action: z.object({
    category: z.string().min(1).max(128),
    name: z.string().min(1).max(256).optional(),
    detailRef: evidenceRefSchema.optional(),
  }).strict(),
  outcome: z.enum(['succeeded', 'failed', 'denied', 'challenged', 'unknown']),
  reason: z.object({
    code: z.string().min(1).max(128),
    detailRef: evidenceRefSchema.optional(),
  }).strict().optional(),
  authorization: authorizationEvidenceSchema.optional(),
  proof: evidenceRefSchema.optional(),
  evidence: z.array(evidenceRefSchema).max(256),
  details: auditEventDetailsSchema,
  privacy: z.object({
    classification: z.enum(['public', 'internal', 'confidential', 'restricted']),
    retentionClass: z.string().min(1).max(128),
    legalHold: z.string().min(1).max(256).optional(),
  }).strict(),
}).strict().superRefine((event, context) => {
  if (event.details.family !== expectedFamily(event.eventType)) {
    context.addIssue({
      code: 'custom',
      path: ['details', 'family'],
      message: `Event detail family ${event.details.family} does not match ${event.eventType}`,
    });
  }
});

export const auditEntryCoreSchema = z.object({
  schema: z.literal(AUDIT_ENTRY_SCHEMA_ID),
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  sequence: decimalStringSchema,
  previousEntryDigest: digestSchema.nullable(),
  recordedAt: z.number().int().nonnegative(),
  recorder: signerRefSchema,
  eventDigest: digestSchema,
  event: auditProducerEventSchema,
  evidenceManifestDigest: digestSchema,
  integritySuite: z.literal(AUDIT_INTEGRITY_SUITE),
}).strict();

export const auditRecorderReceiptCoreSchema = z.object({
  schema: z.literal(AUDIT_RECEIPT_SCHEMA_ID),
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  sequence: decimalStringSchema,
  eventId: z.string().min(1).max(256),
  entryDigest: digestSchema,
  previousEntryDigest: digestSchema.nullable(),
  recordedAt: z.number().int().nonnegative(),
  recorder: signerRefSchema,
  integritySuite: z.literal(AUDIT_INTEGRITY_SUITE),
}).strict();

export const auditCheckpointCoreSchema = z.object({
  schema: z.literal(AUDIT_CHECKPOINT_SCHEMA_ID),
  checkpointId: z.string().min(1).max(512),
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  treeSize: decimalStringSchema,
  firstSequence: decimalStringSchema,
  lastSequence: decimalStringSchema,
  rootDigest: digestSchema,
  headEntryDigest: digestSchema,
  previousCheckpointDigest: digestSchema.nullable(),
  createdAt: z.number().int().nonnegative(),
  issuer: signerRefSchema,
  integritySuite: z.literal(AUDIT_CHECKPOINT_INTEGRITY_SUITE),
}).strict().superRefine((checkpoint, context) => {
  if (BigInt(checkpoint.treeSize) === 0n ||
    BigInt(checkpoint.lastSequence) < BigInt(checkpoint.firstSequence)) {
    context.addIssue({ code: 'custom', message: 'Checkpoint range must be non-empty and ordered' });
  }
});

export const signedAuditCheckpointSchema = z.object({
  core: auditCheckpointCoreSchema,
  checkpointDigest: digestSchema,
  jws: z.string().min(1).max(MAX_JWS_LENGTH),
}).strict();

export const signedAuditEntrySchema = z.object({
  core: auditEntryCoreSchema,
  eventDigest: digestSchema,
  entryDigest: digestSchema,
  recorderReceipt: z.object({
    core: auditRecorderReceiptCoreSchema,
    jws: z.string().min(1).max(MAX_JWS_LENGTH),
  }).strict(),
}).strict();

export const auditObservationReceiptSchema = z.object({
  core: z.object({
    schema: z.literal('https://schema.kya-os.org/v1/protocol/audit/observation/v1.0.0'),
    observerId: z.string().min(1).max(256),
    observer: signerRefSchema,
    ledgerId: z.string().min(1).max(256),
    ledgerEpochId: z.string().min(1).max(256),
    checkpointDigest: digestSchema,
    treeSize: decimalStringSchema,
    observedAt: z.number().int().nonnegative(),
    previousObservationDigest: digestSchema.nullable(),
  }).strict(),
  observationDigest: digestSchema,
  jws: z.string().min(1).max(MAX_JWS_LENGTH),
}).strict();

export const auditAnchorReceiptSchema = z.object({
  schema: z.literal('https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0'),
  kind: z.enum(['worm', 'rfc3161', 'scitt']),
  providerId: z.string().min(1).max(256),
  checkpointDigest: digestSchema,
  issuedAt: z.number().int().nonnegative(),
  receiptData: z.string().min(1).max(MAX_RECEIPT_DATA_LENGTH).optional(),
}).strict();

export const auditMerkleInclusionProofSchema = z.object({
  leafIndex: decimalStringSchema,
  treeSize: decimalStringSchema,
  auditPath: z.array(digestSchema),
}).strict();

export const auditMerkleConsistencyProofSchema = z.object({
  oldTreeSize: decimalStringSchema,
  newTreeSize: decimalStringSchema,
  auditPath: z.array(digestSchema),
}).strict();

export const auditBundleInclusionProofSchema = z.object({
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  sequence: decimalStringSchema,
  entryDigest: digestSchema,
  checkpointDigest: digestSchema,
  proof: auditMerkleInclusionProofSchema,
}).strict();

export const auditBundleConsistencyProofSchema = z.object({
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  oldCheckpointDigest: digestSchema,
  newCheckpointDigest: digestSchema,
  proof: auditMerkleConsistencyProofSchema,
}).strict();

const auditBundleSelectionSchema = z.object({
  ledgerId: z.string().min(1).max(256),
  ledgerEpochId: z.string().min(1).max(256),
  firstSequence: decimalStringSchema,
  lastSequence: decimalStringSchema,
  expectedHeadDigest: digestSchema,
  checkpointTreeSizes: z.array(decimalStringSchema).max(256),
}).strict().superRefine((selection, context) => {
  if (BigInt(selection.lastSequence) < BigInt(selection.firstSequence)) {
    context.addIssue({ code: 'custom', message: 'Bundle selection range is reversed' });
  }
});

const auditBundleInventoryItemSchema = z.object({
  path: z.string().min(1).max(1024),
  mediaType: z.string().min(1).max(256),
  disposition: z.enum(['included', 'redacted', 'disposed', 'unavailable', 'policy_excluded']),
  digest: digestSchema.optional(),
  size: decimalStringSchema.optional(),
  reasonCode: z.string().min(1).max(128).optional(),
}).strict().superRefine((item, context) => {
  if (item.disposition === 'included') {
    if (item.digest === undefined || item.size === undefined || item.reasonCode !== undefined) {
      context.addIssue({ code: 'custom', message: 'Included inventory requires digest/size only' });
    }
  } else if (item.reasonCode === undefined || item.digest !== undefined || item.size !== undefined) {
    context.addIssue({ code: 'custom', message: 'Excluded inventory requires only a reason code' });
  }
});

export const auditBundleManifestCoreSchema = z.object({
  schema: z.literal(AUDIT_BUNDLE_MANIFEST_SCHEMA_ID),
  bundleId: z.string().min(1).max(256),
  formatVersion: z.literal('1.0.0'),
  selections: z.array(auditBundleSelectionSchema).min(1),
  exporter: signerRefSchema,
  purpose: z.string().min(1).max(256),
  exportedAt: z.number().int().nonnegative(),
  verificationPolicyDigest: digestSchema,
  inventory: z.array(auditBundleInventoryItemSchema).max(10_000),
  integritySuite: z.literal(AUDIT_BUNDLE_INTEGRITY_SUITE),
}).strict().superRefine((manifest, context) => {
  const paths = manifest.inventory.map((item) => item.path);
  if (new Set(paths).size !== paths.length) {
    context.addIssue({ code: 'custom', path: ['inventory'], message: 'Inventory paths must be unique' });
  }
});

const auditBundleComponentSchema = auditBundleInventoryItemSchema.extend({
  content: z.unknown().optional(),
}).strict().superRefine((component, context) => {
  const hasContent = Object.prototype.hasOwnProperty.call(component, 'content');
  if (component.disposition === 'included' ? !hasContent : hasContent) {
    context.addIssue({
      code: 'custom',
      path: ['content'],
      message: component.disposition === 'included'
        ? 'Included component content is required'
        : 'Excluded component content is forbidden',
    });
  }
  if (hasContent) {
    try {
      assertCanonicalJsonValue(component.content);
    } catch (error) {
      context.addIssue({
        code: 'custom',
        path: ['content'],
        message: error instanceof Error ? error.message : 'Content is not canonical JSON',
      });
    }
  }
});

export const auditReplayBundleSchema = z.object({
  manifest: z.object({
    core: auditBundleManifestCoreSchema,
    manifestDigest: digestSchema,
    jws: z.string().min(1).max(MAX_JWS_LENGTH),
  }).strict(),
  components: z.array(auditBundleComponentSchema),
}).strict();

const historicalAuditKeyPolicySchema = z.object({
  signer: signerRefSchema,
  validFrom: z.number().int().nonnegative().optional(),
  validUntil: z.number().int().nonnegative().optional(),
  validFromCheckpoint: digestSchema.optional(),
  validUntilCheckpoint: digestSchema.optional(),
}).strict().superRefine((value, context) => {
  if (value.validFrom !== undefined && value.validUntil !== undefined &&
    value.validFrom > value.validUntil) {
    context.addIssue({ code: 'custom', message: 'Key validity interval is reversed' });
  }
});

export const auditVerificationPolicySchema = z.object({
  policyId: z.string().min(1).max(256),
  trustedLedgerEpochs: z.array(z.object({
    ledgerId: z.string().min(1).max(256),
    ledgerEpochId: z.string().min(1).max(256),
    recorderKeys: z.array(historicalAuditKeyPolicySchema).min(1),
    validFromCheckpoint: digestSchema.optional(),
    validUntilCheckpoint: digestSchema.optional(),
  }).strict()),
  trustedObservers: z.array(historicalAuditKeyPolicySchema),
  trustedSupportingAnchors: z.array(z.object({
    kind: z.enum(['worm', 'rfc3161', 'scitt']),
    providerId: z.string().min(1).max(256),
    validFrom: z.number().int().nonnegative().optional(),
    validUntil: z.number().int().nonnegative().optional(),
  }).strict()).optional(),
  authorizedExporters: z.array(z.object({
    signerKeys: z.array(historicalAuditKeyPolicySchema).min(1),
    allowedLedgerIds: z.array(z.string().min(1).max(256)).min(1),
    allowedPurposes: z.array(z.string().min(1).max(256)).min(1),
  }).strict()),
  acceptedIntegritySuites: z.array(z.string().min(1).max(128)).min(1),
  acceptedAlgorithms: z.array(z.enum(['EdDSA', 'ES256'])).min(1),
  keyRevocationMode: z.enum(['as_observed', 'current', 'both']),
  requiredCheckpointFreshnessMs: z.number().int().nonnegative().optional(),
  requiredAuditProfile: z.enum(['AAP-0', 'AAP-1', 'AAP-2', 'AAP-3', 'AAP-4']).optional(),
}).strict();

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  if (seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function cloneAndFreeze<T>(value: T): T {
  return deepFreeze(structuredClone(value));
}

export function parseAuditProducerEvent(input: unknown): AuditProducerEventCoreV1 {
  return cloneAndFreeze(auditProducerEventSchema.parse(input) as AuditProducerEventCoreV1);
}

export function parseAuditEntryCore(input: unknown): AuditEntryCoreV1 {
  return cloneAndFreeze(auditEntryCoreSchema.parse(input) as AuditEntryCoreV1);
}

export function parseSignedAuditEntry(input: unknown): SignedAuditEntryV1 {
  return cloneAndFreeze(signedAuditEntrySchema.parse(input) as SignedAuditEntryV1);
}

export function parseAuditRecorderReceiptCore(input: unknown): AuditRecorderReceiptCoreV1 {
  return cloneAndFreeze(auditRecorderReceiptCoreSchema.parse(input) as AuditRecorderReceiptCoreV1);
}

export function parseAuditCheckpointCore(input: unknown): AuditCheckpointCoreV1 {
  return cloneAndFreeze(auditCheckpointCoreSchema.parse(input) as AuditCheckpointCoreV1);
}

export function parseSignedAuditCheckpoint(input: unknown): SignedAuditCheckpointV1 {
  return cloneAndFreeze(signedAuditCheckpointSchema.parse(input) as SignedAuditCheckpointV1);
}

export function parseAuditObservationReceipt(input: unknown): AuditObservationReceiptV1 {
  return cloneAndFreeze(
    auditObservationReceiptSchema.parse(input) as AuditObservationReceiptV1,
  );
}

export function parseAuditBundleManifestCore(input: unknown): AuditBundleManifestCoreV1 {
  return cloneAndFreeze(
    auditBundleManifestCoreSchema.parse(input) as AuditBundleManifestCoreV1,
  );
}

export function parseAuditReplayBundle(input: unknown): AuditReplayBundleV1 {
  return cloneAndFreeze(auditReplayBundleSchema.parse(input) as AuditReplayBundleV1);
}

export function parseAuditVerificationPolicy(input: unknown): AuditVerificationPolicyV1 {
  return cloneAndFreeze(
    auditVerificationPolicySchema.parse(input) as AuditVerificationPolicyV1,
  );
}
