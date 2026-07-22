import { AuditLogProvider } from '../../providers/audit-log.js';
import type { AuditContext, AuditEventContext } from '../../types/protocol.js';
import type { AuditTrailEventInput, AuditTrailService } from '../service.js';

export interface LegacyAuditSinkAdapterOptions {
  identityKind?: 'public_did' | 'pairwise_did';
  resourceKind?: 'public_did' | 'pairwise_did';
}

/**
 * 1.x compatibility bridge. It captures legacy calls in the new ledger but can
 * claim only legacy/capture coverage because the old shape lacks lifecycle data.
 */
export class LegacyAuditSinkAdapter extends AuditLogProvider {
  readonly capability = 'legacy-capture' as const;

  constructor(
    private readonly trail: Pick<AuditTrailService, 'record'>,
    private readonly options: LegacyAuditSinkAdapterOptions = {},
  ) {
    super();
  }

  async logAuditRecord(context: AuditContext): Promise<void> {
    const verified = context.verified === 'yes';
    await this.trail.record({
      eventType: verified ? 'proof.verified' : 'proof.rejected',
      actor: { kind: this.options.identityKind ?? 'public_did', did: context.identity.did },
      resource: { kind: this.options.resourceKind ?? 'public_did', did: context.session.audience },
      action: { category: 'legacy.audit-record' },
      outcome: verified ? 'succeeded' : 'failed',
      ...(verified ? {} : { reason: { code: 'LEGACY_VERIFICATION_FAILED' } }),
      ...(context.scopeId === undefined ? {} : {
        authorization: {
          source: 'policy' as const,
          decision: verified ? 'allowed' as const : 'denied' as const,
          scopeId: context.scopeId,
        },
      }),
      evidence: [],
      details: {
        family: 'proof',
        phase: verified ? 'verified' : 'rejected',
        verificationCode: verified ? 'LEGACY_VERIFIED_CLAIM' : 'LEGACY_REJECTED_CLAIM',
      },
    });
  }

  async logEvent(context: AuditEventContext): Promise<void> {
    const input: AuditTrailEventInput = {
      eventType: 'configuration.changed',
      actor: { kind: this.options.identityKind ?? 'public_did', did: context.identity.did },
      resource: { kind: this.options.resourceKind ?? 'public_did', did: context.session.audience },
      action: { category: 'legacy.event' },
      outcome: 'unknown',
      reason: { code: 'LEGACY_EVENT_CAPTURE' },
      evidence: [],
      details: {
        family: 'key',
        phase: 'configuration_changed',
      },
    };
    await this.trail.record(input);
  }
}
