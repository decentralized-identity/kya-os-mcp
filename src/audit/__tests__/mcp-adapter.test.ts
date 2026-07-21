import { describe, expect, it } from 'vitest';
import { McpAuditEventAdapter } from '../adapters/mcp.js';
import type { AuditTrailService } from '../service.js';
import type { AuditProducerEventCoreV1 } from '../types.js';

describe('MCP audit event adapter catalog', () => {
  it('maps consent, credential, key, ledger, and administration lifecycle signals', async () => {
    const events: Array<Partial<AuditProducerEventCoreV1>> = [];
    const adapter = new McpAuditEventAdapter({
      record: async (event) => {
        events.push(event);
        return { status: 'pending', event: event as AuditProducerEventCoreV1 };
      },
    });
    await adapter.consent('requested', { outcome: 'challenged', consentRef: 'consent-1' });
    await adapter.consent('credential_verified', { outcome: 'succeeded' });
    await adapter.key('rotated', { outcome: 'succeeded' });
    await adapter.ledger('checkpoint_created', {
      outcome: 'succeeded', checkpointDigest: `sha256:${'a'.repeat(64)}`,
    });
    await adapter.administration('exported', {
      outcome: 'succeeded', purpose: 'regulatory-review',
    });

    expect(events.map((event) => event.eventType)).toEqual([
      'consent.requested',
      'credential.verified',
      'key.rotated',
      'checkpoint.created',
      'audit.exported',
    ]);
  });

  it('preserves optional MCP lifecycle context without exposing tool names by default', async () => {
    const events: Array<Partial<AuditProducerEventCoreV1>> = [];
    const trail: Pick<AuditTrailService, 'record'> = {
      record: async (event) => {
        events.push(event);
        return { status: 'pending', event: event as AuditProducerEventCoreV1 };
      },
    };
    const adapter = new McpAuditEventAdapter(trail);
    const namedAdapter = new McpAuditEventAdapter(trail, { includeToolNames: true });
    const context = {
      actor: { kind: 'pairwise_did' as const, did: 'did:key:zActor' },
      responsibleParty: { kind: 'pairwise_did' as const, did: 'did:key:zOperator' },
      authorization: {
        source: 'policy' as const, decision: 'allowed' as const, policyId: 'policy-1',
      },
      correlationId: 'correlation-1',
      causationId: 'causation-1',
    };
    const digest = `sha256:${'a'.repeat(64)}` as const;

    await adapter.session('failed', { succeeded: false, reasonCode: 'HANDSHAKE_FAILED', context });
    await adapter.tool('failed', {
      toolName: 'orders.create', outcome: 'failed', reasonCode: 'TOOL_FAILED', context,
    });
    await namedAdapter.tool('completed', {
      toolName: 'orders.create', outcome: 'succeeded', attempt: '2',
    });
    await adapter.proof('verified', {
      outcome: 'failed', proofDigest: digest, verificationCode: 'INVALID_SIGNATURE', context,
    });
    await adapter.authorization('grant_used', {
      outcome: 'succeeded', policyDigest: digest, grantRef: 'grant-1', context,
    });
    await adapter.delegation('verified', {
      delegationRef: 'delegation-1', parentRef: 'delegation-0', outcome: 'denied',
      reasonCode: 'SCOPE_DENIED', context,
    });
    await adapter.delegation('issued', {
      delegationRef: 'delegation-2', outcome: 'succeeded',
    });
    await adapter.consent('denied', {
      outcome: 'denied', reasonCode: 'CONSENT_DENIED',
    });
    await adapter.key('configuration_changed', {
      outcome: 'succeeded', previousSigner: { did: 'did:key:zOld', kid: 'did:key:zOld#key', alg: 'EdDSA' },
      nextSigner: { did: 'did:key:zNew', kid: 'did:key:zNew#key', alg: 'EdDSA' },
      configurationDigest: digest, reasonCode: 'ROTATION', context,
    });
    await adapter.ledger('epoch_transitioned', {
      outcome: 'succeeded', checkpointDigest: digest, previousEpochId: 'epoch-0',
      previousTerminalCheckpointDigest: digest, successorEpochIds: ['epoch-2'], context,
    });
    await adapter.ledger('checkpoint_anchor_failed', {
      outcome: 'failed', reasonCode: 'ANCHOR_OFFLINE',
    });
    await adapter.administration('source_high_water', {
      outcome: 'succeeded', purpose: 'reconciliation', sourceSequence: '42',
      selectionDigest: digest, context,
    });
    await adapter.administration('accessed', {
      outcome: 'denied', reasonCode: 'ACCESS_DENIED',
    });

    expect(events[0]).toMatchObject({
      eventType: 'session.failed', outcome: 'failed', reason: { code: 'HANDSHAKE_FAILED' },
      actor: context.actor, responsibleParty: context.responsibleParty,
      authorization: context.authorization, correlationId: 'correlation-1', causationId: 'causation-1',
    });
    expect(events[1]?.action).toEqual({ category: 'tool.call' });
    expect(events[2]?.action).toEqual({ category: 'tool.call', name: 'orders.create' });
    expect(events.map((event) => event.eventType)).toEqual([
      'session.failed', 'tool.call.failed', 'tool.call.completed', 'proof.verified',
      'grant.used', 'delegation.verified', 'delegation.issued', 'consent.denied',
      'configuration.changed', 'ledger.epoch.transitioned', 'checkpoint.anchor_failed',
      'audit.source_high_water', 'audit.accessed',
    ]);
  });
});
