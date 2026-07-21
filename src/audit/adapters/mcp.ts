import type { AuditTrailService } from '../service.js';
import type {
  AuditEventDetails,
  AuthorizationEvidence,
  Digest,
  PartyRef,
} from '../types.js';

export interface McpAuditContext {
  actor?: PartyRef;
  responsibleParty?: PartyRef;
  authorization?: AuthorizationEvidence;
  correlationId?: string;
  causationId?: string;
}

export interface McpAuditEventAdapterOptions {
  includeToolNames?: boolean;
}

/** Privacy-minimal translation from MCP lifecycle signals to binding-neutral events. */
export class McpAuditEventAdapter {
  constructor(
    private readonly trail: Pick<AuditTrailService, 'record'>,
    private readonly options: McpAuditEventAdapterOptions = {},
  ) {}

  async session(
    phase: Extract<AuditEventDetails, { family: 'session' }>['phase'],
    input: { succeeded: boolean; reasonCode?: string; context?: McpAuditContext },
  ): Promise<void> {
    await this.trail.record({
      eventType: `session.${phase}` as 'session.established',
      ...this.context(input.context),
      action: { category: 'session' },
      outcome: input.succeeded ? 'succeeded' : 'failed',
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'session', phase,
        ...(input.reasonCode === undefined ? {} : { reasonCode: input.reasonCode }),
      },
    });
  }

  async tool(
    phase: Extract<AuditEventDetails, { family: 'tool' }>['phase'],
    input: {
      toolName: string;
      outcome: 'succeeded' | 'failed' | 'denied' | 'challenged' | 'unknown';
      attempt?: string;
      reasonCode?: string;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    await this.trail.record({
      eventType: `tool.call.${phase}` as 'tool.call.completed',
      ...this.context(input.context),
      action: {
        category: 'tool.call',
        ...(this.options.includeToolNames ? { name: input.toolName } : {}),
      },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: { family: 'tool', phase, attempt: input.attempt ?? '1' },
    });
  }

  async proof(
    phase: Extract<AuditEventDetails, { family: 'proof' }>['phase'],
    input: {
      outcome: 'succeeded' | 'failed';
      proofDigest?: Digest;
      verificationCode?: string;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    await this.trail.record({
      eventType: `proof.${phase}` as 'proof.generated',
      ...this.context(input.context),
      action: { category: 'proof' },
      outcome: input.outcome,
      evidence: [],
      details: {
        family: 'proof', phase,
        ...(input.proofDigest === undefined ? {} : { proofDigest: input.proofDigest }),
        ...(input.verificationCode === undefined
          ? {}
          : { verificationCode: input.verificationCode }),
      },
    });
  }

  async authorization(
    phase: Extract<AuditEventDetails, { family: 'authorization' }>['phase'],
    input: {
      outcome: 'succeeded' | 'denied' | 'challenged';
      reasonCode?: string;
      policyDigest?: Digest;
      grantRef?: string;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    const eventType = phase === 'grant_used'
      ? 'grant.used'
      : `authorization.${phase}` as const;
    await this.trail.record({
      eventType,
      ...this.context(input.context),
      action: { category: 'authorization' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'authorization', phase,
        ...(input.policyDigest === undefined ? {} : { policyDigest: input.policyDigest }),
        ...(input.grantRef === undefined ? {} : { grantRef: input.grantRef }),
      },
    });
  }

  async delegation(
    phase: Extract<AuditEventDetails, { family: 'delegation' }>['phase'],
    input: {
      delegationRef: string;
      outcome: 'succeeded' | 'failed' | 'denied';
      reasonCode?: string;
      parentRef?: string;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    await this.trail.record({
      eventType: `delegation.${phase}` as 'delegation.verified',
      ...this.context(input.context),
      action: { category: 'delegation' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'delegation', phase, delegationRef: input.delegationRef,
        ...(input.parentRef === undefined ? {} : { parentRef: input.parentRef }),
      },
    });
  }

  async consent(
    phase: Extract<AuditEventDetails, { family: 'consent' }>['phase'],
    input: {
      outcome: 'succeeded' | 'failed' | 'denied' | 'challenged';
      consentRef?: string;
      reasonCode?: string;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    const eventType = phase.startsWith('credential_')
      ? `credential.${phase.slice('credential_'.length)}`
      : `consent.${phase}`;
    await this.trail.record({
      eventType: eventType as 'consent.requested',
      ...this.context(input.context),
      action: { category: 'consent' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'consent', phase,
        ...(input.consentRef === undefined ? {} : { consentRef: input.consentRef }),
      },
    });
  }

  async key(
    phase: Extract<AuditEventDetails, { family: 'key' }>['phase'],
    input: {
      outcome: 'succeeded' | 'failed';
      reasonCode?: string;
      previousSigner?: Extract<AuditEventDetails, { family: 'key' }>['previousSigner'];
      nextSigner?: Extract<AuditEventDetails, { family: 'key' }>['nextSigner'];
      configurationDigest?: Digest;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    const eventTypes = {
      rotated: 'key.rotated',
      policy_changed: 'policy.changed',
      configuration_changed: 'configuration.changed',
      integrity_suite_transitioned: 'integrity_suite.transitioned',
    } as const;
    await this.trail.record({
      eventType: eventTypes[phase],
      ...this.context(input.context),
      action: { category: 'configuration' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'key', phase,
        ...(input.previousSigner === undefined ? {} : { previousSigner: input.previousSigner }),
        ...(input.nextSigner === undefined ? {} : { nextSigner: input.nextSigner }),
        ...(input.configurationDigest === undefined
          ? {}
          : { configurationDigest: input.configurationDigest }),
      },
    });
  }

  async ledger(
    phase: Extract<AuditEventDetails, { family: 'ledger' }>['phase'],
    input: {
      outcome: 'succeeded' | 'failed';
      reasonCode?: string;
      checkpointDigest?: Digest;
      previousEpochId?: string;
      previousTerminalCheckpointDigest?: Digest;
      successorEpochIds?: string[];
      context?: McpAuditContext;
    },
  ): Promise<void> {
    const eventTypes = {
      epoch_started: 'ledger.epoch.started',
      epoch_transitioned: 'ledger.epoch.transitioned',
      checkpoint_created: 'checkpoint.created',
      checkpoint_anchored: 'checkpoint.anchored',
      checkpoint_anchor_failed: 'checkpoint.anchor_failed',
      evidence_disposed: 'evidence.disposed',
      projection_reconciled: 'projection.reconciled',
    } as const;
    await this.trail.record({
      eventType: eventTypes[phase],
      ...this.context(input.context),
      action: { category: 'audit.ledger' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'ledger', phase,
        ...(input.checkpointDigest === undefined
          ? {}
          : { checkpointDigest: input.checkpointDigest }),
        ...(input.previousEpochId === undefined ? {} : { previousEpochId: input.previousEpochId }),
        ...(input.previousTerminalCheckpointDigest === undefined
          ? {}
          : { previousTerminalCheckpointDigest: input.previousTerminalCheckpointDigest }),
        ...(input.successorEpochIds === undefined
          ? {}
          : { successorEpochIds: input.successorEpochIds }),
      },
    });
  }

  async administration(
    phase: Extract<AuditEventDetails, { family: 'administration' }>['phase'],
    input: {
      outcome: 'succeeded' | 'failed' | 'denied';
      reasonCode?: string;
      purpose?: string;
      sourceSequence?: string;
      selectionDigest?: Digest;
      context?: McpAuditContext;
    },
  ): Promise<void> {
    const eventTypes = {
      source_high_water: 'audit.source_high_water',
      accessed: 'audit.accessed',
      exported: 'audit.exported',
      legal_hold_applied: 'legal_hold.applied',
      retention_executed: 'retention.executed',
    } as const;
    await this.trail.record({
      eventType: eventTypes[phase],
      ...this.context(input.context),
      action: { category: 'audit.administration' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'administration', phase,
        ...(input.purpose === undefined ? {} : { purpose: input.purpose }),
        ...(input.sourceSequence === undefined
          ? {}
          : { sourceSequence: input.sourceSequence }),
        ...(input.selectionDigest === undefined
          ? {}
          : { selectionDigest: input.selectionDigest }),
      },
    });
  }

  private context(context: McpAuditContext | undefined): McpAuditContext {
    if (context === undefined) return {};
    return {
      ...(context.actor === undefined ? {} : { actor: context.actor }),
      ...(context.responsibleParty === undefined
        ? {}
        : { responsibleParty: context.responsibleParty }),
      ...(context.authorization === undefined
        ? {}
        : { authorization: context.authorization }),
      ...(context.correlationId === undefined ? {} : { correlationId: context.correlationId }),
      ...(context.causationId === undefined ? {} : { causationId: context.causationId }),
    };
  }
}
