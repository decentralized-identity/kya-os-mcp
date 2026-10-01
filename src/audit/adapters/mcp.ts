import type { AuditTrailService } from '../service.js';
import type {
  AuditEventDetails,
  AuthorizationEvidence,
  Digest,
  PartyRef,
} from '../types.js';
import { boundedAuditReference } from './references.js';

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

/** Bounds every caller-supplied reference so a hostile one cannot keep the event out of the ledger. */
async function boundedAuthorization(
  authorization: AuthorizationEvidence,
): Promise<AuthorizationEvidence> {
  const bounded = { ...authorization };
  for (const field of ['scopeId', 'delegationRef', 'grantRef', 'policyId', 'policyVersion'] as const) {
    const value = authorization[field];
    if (value !== undefined) bounded[field] = await boundedAuditReference(value);
  }
  if (authorization.verificationCode !== undefined) {
    bounded.verificationCode = await boundedAuditReference(authorization.verificationCode, 128);
  }
  return bounded;
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
      ...(await this.context(input.context)),
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
      ...(await this.context(input.context)),
      action: {
        category: 'tool.call',
        ...(this.options.includeToolNames
          ? { name: await boundedAuditReference(input.toolName) }
          : {}),
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
      ...(await this.context(input.context)),
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
      ...(await this.context(input.context)),
      action: { category: 'authorization' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'authorization', phase,
        ...(input.policyDigest === undefined ? {} : { policyDigest: input.policyDigest }),
        ...(input.grantRef === undefined
          ? {}
          : { grantRef: await boundedAuditReference(input.grantRef) }),
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
      ...(await this.context(input.context)),
      action: { category: 'delegation' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'delegation', phase,
        delegationRef: await boundedAuditReference(input.delegationRef),
        ...(input.parentRef === undefined
          ? {}
          : { parentRef: await boundedAuditReference(input.parentRef) }),
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
      ...(await this.context(input.context)),
      action: { category: 'consent' },
      outcome: input.outcome,
      ...(input.reasonCode === undefined ? {} : { reason: { code: input.reasonCode } }),
      evidence: [],
      details: {
        family: 'consent', phase,
        ...(input.consentRef === undefined
          ? {}
          : { consentRef: await boundedAuditReference(input.consentRef) }),
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
      ...(await this.context(input.context)),
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
      ...(await this.context(input.context)),
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
      ...(await this.context(input.context)),
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

  private async context(context: McpAuditContext | undefined): Promise<McpAuditContext> {
    if (context === undefined) return {};
    return {
      ...(context.actor === undefined ? {} : { actor: context.actor }),
      ...(context.responsibleParty === undefined
        ? {}
        : { responsibleParty: context.responsibleParty }),
      ...(context.authorization === undefined
        ? {}
        : { authorization: await boundedAuthorization(context.authorization) }),
      ...(context.correlationId === undefined
        ? {}
        : { correlationId: await boundedAuditReference(context.correlationId) }),
      ...(context.causationId === undefined
        ? {}
        : { causationId: await boundedAuditReference(context.causationId) }),
    };
  }
}
