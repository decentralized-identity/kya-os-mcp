/** Wire-level types for the KYA-OS Auditability Protocol v1. */

export type Digest = `sha256:${string}`;
export type DecimalString = string;
export type ProtocolBindingId = `urn:kya-os:audit-binding:${string}`;

export type PartyRef =
  | { kind: 'public_did'; did: string }
  | { kind: 'pairwise_did'; did: string }
  | { kind: 'keyed_commitment'; value: Digest; keyId: string }
  | { kind: 'evidence_ref'; ref: EvidenceRef };

/** A cryptographically resolvable signer; never substitute a privacy PartyRef. */
export interface SignerRef {
  did: string;
  kid: string;
  alg: 'EdDSA' | 'ES256';
}

export interface EvidenceEncryptionMetadata {
  suite: 'A256GCM';
  keyId: string;
  nonce: string;
  aadDigest: Digest;
}

export interface EvidenceRef {
  objectId: string;
  ciphertextDigest: Digest;
  plaintextCommitment?: Digest;
  mediaType: string;
  size: DecimalString;
  encryption: EvidenceEncryptionMetadata;
}

export const AUDIT_EVENT_TYPES = [
  'session.established',
  'session.rejected',
  'session.expired',
  'session.replay_rejected',
  'tool.call.started',
  'tool.call.completed',
  'tool.call.failed',
  'tool.call.denied',
  'tool.call.challenged',
  'proof.generated',
  'proof.verified',
  'proof.rejected',
  'delegation.issued',
  'delegation.verified',
  'delegation.rejected',
  'delegation.revoked',
  'delegation.cascade_revoked',
  'delegation.outbound_attached',
  'authorization.evaluated',
  'authorization.approved',
  'authorization.denied',
  'authorization.step_up_required',
  'grant.used',
  'consent.requested',
  'consent.approved',
  'consent.denied',
  'credential.required',
  'credential.verified',
  'credential.failed',
  'key.rotated',
  'policy.changed',
  'configuration.changed',
  'integrity_suite.transitioned',
  'ledger.epoch.started',
  'ledger.epoch.transitioned',
  'checkpoint.created',
  'checkpoint.anchored',
  'checkpoint.anchor_failed',
  'evidence.disposed',
  'projection.reconciled',
  'audit.source_high_water',
  'audit.accessed',
  'audit.exported',
  'legal_hold.applied',
  'retention.executed',
] as const;

export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number];
export type AuditEventFamily =
  | 'session'
  | 'tool'
  | 'proof'
  | 'delegation'
  | 'authorization'
  | 'consent'
  | 'key'
  | 'ledger'
  | 'administration';

export type AuditEventDetails =
  | {
      family: 'session';
      phase: 'established' | 'rejected' | 'expired' | 'replay_rejected';
      reasonCode?: string;
    }
  | {
      family: 'tool';
      phase: 'started' | 'completed' | 'failed' | 'denied' | 'challenged';
      attempt: DecimalString;
      idempotencyRef?: string;
    }
  | {
      family: 'proof';
      phase: 'generated' | 'verified' | 'rejected';
      proofDigest?: Digest;
      verificationCode?: string;
    }
  | {
      family: 'delegation';
      phase: 'issued' | 'verified' | 'rejected' | 'revoked' | 'cascade_revoked' | 'outbound_attached';
      delegationRef: string;
      parentRef?: string;
      statusEvidence?: EvidenceRef[];
    }
  | {
      family: 'authorization';
      phase: 'evaluated' | 'approved' | 'denied' | 'step_up_required' | 'grant_used';
      policyDigest?: Digest;
      grantRef?: string;
    }
  | {
      family: 'consent';
      phase: 'requested' | 'approved' | 'denied' | 'credential_required' | 'credential_verified' | 'credential_failed';
      consentRef?: string;
    }
  | {
      family: 'key';
      phase: 'rotated' | 'policy_changed' | 'configuration_changed' | 'integrity_suite_transitioned';
      previousSigner?: SignerRef;
      nextSigner?: SignerRef;
      configurationDigest?: Digest;
    }
  | {
      family: 'ledger';
      phase: 'epoch_started' | 'epoch_transitioned' | 'checkpoint_created' | 'checkpoint_anchored' | 'checkpoint_anchor_failed' | 'evidence_disposed' | 'projection_reconciled';
      checkpointDigest?: Digest;
      previousEpochId?: string;
      previousTerminalCheckpointDigest?: Digest;
      successorEpochIds?: string[];
      targetEvidenceRef?: EvidenceRef;
    }
  | {
      family: 'administration';
      phase: 'source_high_water' | 'accessed' | 'exported' | 'legal_hold_applied' | 'retention_executed';
      purpose?: string;
      sourceSequence?: DecimalString;
      selectionDigest?: Digest;
    };

export interface AuthorizationEvidence {
  source: 'delegation' | 'grant' | 'anonymous' | 'policy';
  decision: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization';
  scopeId?: string;
  delegationRef?: string;
  delegationCredentialDigest?: Digest;
  delegationChainDigests?: Digest[];
  statusEvidence?: EvidenceRef[];
  grantRef?: string;
  policyId?: string;
  policyVersion?: string;
  policyDigest?: Digest;
  verificationCode?: string;
}

export interface AuditProducerEventCoreV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0';
  eventId: string;
  eventType: AuditEventType;
  eventVersion: '1.0.0';
  binding: ProtocolBindingId;
  occurredAt: number;
  tenantRef: PartyRef;
  source: {
    producer: PartyRef;
    sourceId: string;
    sourceSequence?: DecimalString;
    previousSourceEventDigest?: Digest;
  };
  correlationId?: string;
  causationId?: string;
  trace?: { traceId?: string; spanId?: string };
  session?: { ref: PartyRef; handshakeNonceCommitment?: Digest };
  actor?: PartyRef;
  responsibleParty?: PartyRef;
  resource?: PartyRef;
  action: { category: string; name?: string; detailRef?: EvidenceRef };
  outcome: 'succeeded' | 'failed' | 'denied' | 'challenged' | 'unknown';
  reason?: { code: string; detailRef?: EvidenceRef };
  authorization?: AuthorizationEvidence;
  proof?: EvidenceRef;
  evidence: EvidenceRef[];
  details: AuditEventDetails;
  privacy: {
    classification: 'public' | 'internal' | 'confidential' | 'restricted';
    retentionClass: string;
    legalHold?: string;
  };
}

export interface AuditEntryCoreV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0';
  ledgerId: string;
  ledgerEpochId: string;
  sequence: DecimalString;
  previousEntryDigest: Digest | null;
  recordedAt: number;
  recorder: SignerRef;
  eventDigest: Digest;
  event: AuditProducerEventCoreV1;
  evidenceManifestDigest: Digest;
  integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026';
}

export interface AuditRecorderReceiptCoreV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0';
  ledgerId: string;
  ledgerEpochId: string;
  sequence: DecimalString;
  eventId: string;
  entryDigest: Digest;
  previousEntryDigest: Digest | null;
  recordedAt: number;
  recorder: SignerRef;
  integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026';
}

export interface SignedAuditEntryV1 {
  core: AuditEntryCoreV1;
  eventDigest: Digest;
  entryDigest: Digest;
  recorderReceipt: { core: AuditRecorderReceiptCoreV1; jws: string };
}

export interface AuditHead {
  ledgerId: string;
  ledgerEpochId: string;
  sequence: DecimalString;
  entryDigest: Digest;
}

export interface AuditLedgerRef {
  ledgerId: string;
  ledgerEpochId: string;
}

export type AuditVerdict = 'valid' | 'invalid' | 'indeterminate';

export interface AuditVerificationDimension {
  verdict: AuditVerdict;
  reasonCodes: string[];
}

export interface HistoricalAuditKeyPolicy {
  signer: SignerRef;
  validFrom?: number;
  validUntil?: number;
  validFromCheckpoint?: Digest;
  validUntilCheckpoint?: Digest;
}

export interface AuditVerificationPolicyV1 {
  policyId: string;
  trustedLedgerEpochs: Array<{
    ledgerId: string;
    ledgerEpochId: string;
    recorderKeys: HistoricalAuditKeyPolicy[];
    validFromCheckpoint?: Digest;
    validUntilCheckpoint?: Digest;
  }>;
  trustedObservers: HistoricalAuditKeyPolicy[];
  trustedSupportingAnchors?: Array<{
    kind: AuditAnchorReceipt['kind'];
    providerId: string;
    validFrom?: number;
    validUntil?: number;
  }>;
  authorizedExporters: Array<{
    signerKeys: HistoricalAuditKeyPolicy[];
    allowedLedgerIds: string[];
    allowedPurposes: string[];
  }>;
  acceptedIntegritySuites: string[];
  acceptedAlgorithms: Array<'EdDSA' | 'ES256'>;
  keyRevocationMode: 'as_observed' | 'current' | 'both';
  requiredCheckpointFreshnessMs?: number;
  requiredAuditProfile?: 'AAP-0' | 'AAP-1' | 'AAP-2' | 'AAP-3' | 'AAP-4';
}

export interface AuditVerificationReportV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/verification-report/v1.0.0';
  policyId: string;
  verifiedAt?: number;
  cryptographicIntegrity: AuditVerificationDimension;
  chainIntegrity: AuditVerificationDimension;
  checkpointIntegrity: AuditVerificationDimension;
  anchorIntegrity: AuditVerificationDimension;
  scopeEvidenceCompleteness: AuditVerificationDimension;
  authorizedAsObserved: AuditVerificationDimension;
  currentAuthorization: AuditVerificationDimension;
}

export interface AuditCheckpointCoreV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/checkpoint/v1.0.0';
  checkpointId: string;
  ledgerId: string;
  ledgerEpochId: string;
  treeSize: DecimalString;
  firstSequence: DecimalString;
  lastSequence: DecimalString;
  rootDigest: Digest;
  headEntryDigest: Digest;
  previousCheckpointDigest: Digest | null;
  createdAt: number;
  issuer: SignerRef;
  integritySuite: 'KYA-AUDIT-RFC9162-SHA256-JWS-2026';
}

export interface SignedAuditCheckpointV1 {
  core: AuditCheckpointCoreV1;
  checkpointDigest: Digest;
  jws: string;
}

export interface AuditMerkleInclusionProofV1 {
  leafIndex: DecimalString;
  treeSize: DecimalString;
  auditPath: Digest[];
}

export interface AuditMerkleConsistencyProofV1 {
  oldTreeSize: DecimalString;
  newTreeSize: DecimalString;
  auditPath: Digest[];
}

export interface AuditBundleInclusionProofV1 extends AuditLedgerRef {
  sequence: DecimalString;
  entryDigest: Digest;
  checkpointDigest: Digest;
  proof: AuditMerkleInclusionProofV1;
}

export interface AuditBundleConsistencyProofV1 extends AuditLedgerRef {
  oldCheckpointDigest: Digest;
  newCheckpointDigest: Digest;
  proof: AuditMerkleConsistencyProofV1;
}

export interface AuditObservationReceiptCoreV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/observation/v1.0.0';
  observerId: string;
  observer: SignerRef;
  ledgerId: string;
  ledgerEpochId: string;
  checkpointDigest: Digest;
  treeSize: DecimalString;
  observedAt: number;
  previousObservationDigest: Digest | null;
}

export interface AuditObservationReceiptV1 {
  core: AuditObservationReceiptCoreV1;
  observationDigest: Digest;
  jws: string;
}

export interface ObservedAuditCheckpoint {
  checkpoint: SignedAuditCheckpointV1;
  receipt: AuditObservationReceiptV1;
}

export interface AuditAnchorReceipt {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/anchor-receipt/v1.0.0';
  kind: 'worm' | 'rfc3161' | 'scitt';
  providerId: string;
  checkpointDigest: Digest;
  issuedAt: number;
  receiptData?: string;
}

export type AuditBundleDisposition =
  | 'included'
  | 'redacted'
  | 'disposed'
  | 'unavailable'
  | 'policy_excluded';

export interface AuditBundleSelectionV1 extends AuditLedgerRef {
  firstSequence: DecimalString;
  lastSequence: DecimalString;
  expectedHeadDigest: Digest;
  checkpointTreeSizes: DecimalString[];
}

export interface AuditBundleInventoryItemV1 {
  path: string;
  mediaType: string;
  disposition: AuditBundleDisposition;
  digest?: Digest;
  size?: DecimalString;
  reasonCode?: string;
}

export interface AuditBundleManifestCoreV1 {
  schema: 'https://schema.kya-os.org/v1/protocol/audit/bundle-manifest/v1.0.0';
  bundleId: string;
  formatVersion: '1.0.0';
  selections: AuditBundleSelectionV1[];
  exporter: SignerRef;
  purpose: string;
  exportedAt: number;
  verificationPolicyDigest: Digest;
  inventory: AuditBundleInventoryItemV1[];
  integritySuite: 'KYA-AUDIT-BUNDLE-JCS-SHA256-JWS-2026';
}

export interface SignedAuditBundleManifestV1 {
  core: AuditBundleManifestCoreV1;
  manifestDigest: Digest;
  jws: string;
}

export interface AuditBundleComponentV1 extends AuditBundleInventoryItemV1 {
  content?: unknown;
}

export interface AuditReplayBundleV1 {
  manifest: SignedAuditBundleManifestV1;
  components: AuditBundleComponentV1[];
}
