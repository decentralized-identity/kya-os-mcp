import type { AuditHasher } from './crypto.js';
import { hashAuditValue } from './crypto.js';
import type {
  AuditEntryCoreV1,
  AuditProducerEventCoreV1,
  AuditRecorderReceiptCoreV1,
  Digest,
  EvidenceRef,
  PartyRef,
} from './types.js';

function partyEvidence(party: PartyRef | undefined): EvidenceRef[] {
  return party?.kind === 'evidence_ref' ? [party.ref] : [];
}

export function collectAuditEvidenceRefs(event: AuditProducerEventCoreV1): EvidenceRef[] {
  const detailsEvidence = event.details.family === 'delegation'
    ? event.details.statusEvidence ?? []
    : event.details.family === 'ledger' && event.details.targetEvidenceRef !== undefined
      ? [event.details.targetEvidenceRef]
      : [];
  return [
    ...partyEvidence(event.tenantRef),
    ...partyEvidence(event.source.producer),
    ...partyEvidence(event.session?.ref),
    ...partyEvidence(event.actor),
    ...partyEvidence(event.responsibleParty),
    ...partyEvidence(event.resource),
    ...(event.proof === undefined ? [] : [event.proof]),
    ...event.evidence,
    ...(event.action.detailRef === undefined ? [] : [event.action.detailRef]),
    ...(event.reason?.detailRef === undefined ? [] : [event.reason.detailRef]),
    ...(event.authorization?.statusEvidence ?? []),
    ...detailsEvidence,
  ];
}

export const AUDIT_DIGEST_DOMAINS = Object.freeze({
  event: 'org.kya-os.audit.event.v1',
  entry: 'org.kya-os.audit.entry.v1',
  evidenceManifest: 'org.kya-os.audit.evidence-manifest.v1',
  idempotency: 'org.kya-os.audit.idempotency.v1',
  checkpoint: 'org.kya-os.audit.checkpoint.v1',
  observation: 'org.kya-os.audit.observation.v1',
  bundleManifest: 'org.kya-os.audit.bundle-manifest.v1',
  bundleComponent: 'org.kya-os.audit.bundle-component.v1',
});

export function collectAuditEvidenceManifest(event: AuditProducerEventCoreV1): unknown {
  return {
    refs: collectAuditEvidenceRefs(event),
  };
}

export function buildAuditRecorderReceiptCore(
  core: AuditEntryCoreV1,
  entryDigest: Digest,
): AuditRecorderReceiptCoreV1 {
  return {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0',
    ledgerId: core.ledgerId,
    ledgerEpochId: core.ledgerEpochId,
    sequence: core.sequence,
    eventId: core.event.eventId,
    entryDigest,
    previousEntryDigest: core.previousEntryDigest,
    recordedAt: core.recordedAt,
    recorder: core.recorder,
    integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
  };
}

export async function digestAuditEvent(
  hasher: AuditHasher,
  event: AuditProducerEventCoreV1,
): Promise<Digest> {
  return hashAuditValue(hasher, AUDIT_DIGEST_DOMAINS.event, event);
}

export async function digestAuditEntry(
  hasher: AuditHasher,
  entry: AuditEntryCoreV1,
): Promise<Digest> {
  return hashAuditValue(hasher, AUDIT_DIGEST_DOMAINS.entry, entry);
}

export async function digestAuditEvidenceManifest(
  hasher: AuditHasher,
  event: AuditProducerEventCoreV1,
): Promise<Digest> {
  return hashAuditValue(
    hasher,
    AUDIT_DIGEST_DOMAINS.evidenceManifest,
    collectAuditEvidenceManifest(event),
  );
}
