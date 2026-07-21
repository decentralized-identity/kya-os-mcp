import type { EncryptedEvidenceInput } from './evidence.js';
import type { AuditProducerEventCoreV1, SignedAuditEntryV1 } from '../types.js';
import {
  AuditRecorderService,
  type AuditRecorderServiceConfig,
  type AuthenticatedAuditSubmissionContext,
} from '../recorder-service.js';

export interface AuditRecorderSubmission {
  ledgerId: string;
  expectedLedgerEpochId?: string;
  producerEvent: AuditProducerEventCoreV1;
  encryptedEvidence: readonly EncryptedEvidenceInput[];
}

/** Producer-facing port. Authority fields are deliberately absent. */
export interface AuditRecorderClient {
  submit(input: AuditRecorderSubmission): Promise<SignedAuditEntryV1>;
}

export class LocalAuditRecorderClient implements AuditRecorderClient {
  constructor(
    private readonly recorder: AuditRecorderService,
    private readonly context: () =>
      | AuthenticatedAuditSubmissionContext
      | Promise<AuthenticatedAuditSubmissionContext>,
  ) {}

  async submit(input: AuditRecorderSubmission): Promise<SignedAuditEntryV1> {
    return this.recorder.submitAuthenticated(input, await this.context());
  }
}

/** One-call composition helper for an in-process authoritative recorder. */
export function createLocalAuditRecorder(
  configuration: AuditRecorderServiceConfig,
  context: () =>
    | AuthenticatedAuditSubmissionContext
    | Promise<AuthenticatedAuditSubmissionContext>,
): AuditRecorderClient {
  return new LocalAuditRecorderClient(new AuditRecorderService(configuration), context);
}
