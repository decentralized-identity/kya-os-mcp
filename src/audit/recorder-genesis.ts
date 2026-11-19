import { AUDIT_ERROR_CODES, AuditProtocolError } from './errors.js';
import type { AuditRecorderServiceConfig } from './recorder-config.js';
import { sameSigner } from './key-trust.js';
import { sameParty } from './recorder-authority.js';
import {
  AUDIT_EVENT_SCHEMA_ID,
  parseAuditProducerEvent,
  parseSignedAuditEntry,
} from './schemas.js';
import type { AuditProducerEventCoreV1, SignedAuditEntryV1 } from './types.js';

/** What an epoch's genesis is built from and checked against. */
export type RecorderGenesisConfig = Pick<
  AuditRecorderServiceConfig,
  | 'ledgerId'
  | 'ledgerEpochId'
  | 'tenantRef'
  | 'binding'
  | 'sourceId'
  | 'signer'
  | 'clock'
  | 'previousEpochId'
  | 'previousTerminalCheckpointDigest'
>;

/** The stored genesis, when it is the one this recorder configuration would have written. */
export function validateExistingGenesis(
  candidate: SignedAuditEntryV1,
  config: RecorderGenesisConfig,
): SignedAuditEntryV1 {
  try {
    const entry = parseSignedAuditEntry(candidate);
    const details = entry.core.event.details;
    const valid = entry.core.sequence === '0' &&
      entry.core.previousEntryDigest === null &&
      entry.core.ledgerId === config.ledgerId &&
      entry.core.ledgerEpochId === config.ledgerEpochId &&
      sameSigner(entry.core.recorder, config.signer.ref) &&
      entry.core.event.eventType === 'ledger.epoch.started' &&
      entry.core.event.binding === config.binding &&
      entry.core.event.source.sourceId === config.sourceId &&
      entry.core.event.source.producer.kind === 'public_did' &&
      entry.core.event.source.producer.did === config.signer.ref.did &&
      sameParty(entry.core.event.tenantRef, config.tenantRef) &&
      details.family === 'ledger' &&
      details.phase === 'epoch_started' &&
      details.previousEpochId === config.previousEpochId &&
      details.previousTerminalCheckpointDigest ===
        config.previousTerminalCheckpointDigest;
    if (!valid) throw new Error('Genesis does not match recorder epoch configuration');
    return entry;
  } catch (error) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.JOURNAL_FAILURE,
      'Existing ledger genesis does not match the authoritative recorder configuration',
      undefined,
      { cause: error },
    );
  }
}

export function genesisEvent(config: RecorderGenesisConfig): AuditProducerEventCoreV1 {
  return parseAuditProducerEvent({
    schema: AUDIT_EVENT_SCHEMA_ID,
    eventId: `genesis:${config.ledgerId}:${config.ledgerEpochId}`,
    eventType: 'ledger.epoch.started',
    eventVersion: '1.0.0',
    binding: config.binding,
    occurredAt: config.clock.now(),
    tenantRef: config.tenantRef,
    source: {
      producer: { kind: 'public_did', did: config.signer.ref.did },
      sourceId: config.sourceId,
      sourceSequence: '0',
    },
    resource: { kind: 'public_did', did: config.signer.ref.did },
    action: { category: 'ledger.epoch' },
    outcome: 'succeeded',
    evidence: [],
    details: {
      family: 'ledger',
      phase: 'epoch_started',
      ...(config.previousEpochId
        ? {
            previousEpochId: config.previousEpochId,
            previousTerminalCheckpointDigest:
              config.previousTerminalCheckpointDigest,
          }
        : {}),
    },
    privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
  });
}
