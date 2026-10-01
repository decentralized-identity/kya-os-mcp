import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { McpAuditEventAdapter } from '../adapters/mcp.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { LocalAuditRecorderClient } from '../providers/recorder-client.js';
import { MemoryAuditSourceState } from '../providers/source-state.js';
import { AuditRecorderService } from '../recorder-service.js';
import { createAuditTrail, type AuditTrailService } from '../service.js';
import type { AuditProducerEventCoreV1, PartyRef } from '../types.js';

const tenantRef: PartyRef = {
  kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-1',
};
const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };

function recordedTrail() {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const journal = new MemoryAuditJournal();
  const recorder = new AuditRecorderService({
    ...ledger, tenantRef, binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1', journal, hasher, clock: { now: () => 1_750_000_000_000 },
    signer: {
      ref: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#zRecorder', alg: 'EdDSA' },
      sign: async (payload) => `test.${Buffer.from(payload).toString('base64url')}.signature`,
    },
  });
  const trail = createAuditTrail({
    recorder: new LocalAuditRecorderClient(recorder, () => ({
      producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef,
    })),
    delivery: 'best-effort', hasher, ledgerId: ledger.ledgerId, tenantRef,
    producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
    sourceId: 'mcp-server-1', binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
    clock: { now: () => 1_750_000_000_000 }, sourceState: new MemoryAuditSourceState(),
  });
  return { journal, hasher, adapter: new McpAuditEventAdapter(trail) };
}

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

  it('records a rejected delegation whatever identifier the caller presented', async () => {
    const { journal, hasher, adapter } = recordedTrail();
    const presented = [
      // A pair that a code-unit truncation at 256 would split.
      `urn:uuid:${'a'.repeat(246)}\u{1F600}`,
      // A lone surrogate is legal JSON but cannot be canonicalized.
      JSON.parse('"urn:uuid:\\ud800"') as string,
      '',
    ];
    for (const delegationRef of presented) {
      await expect(adapter.delegation('rejected', {
        delegationRef, outcome: 'failed', reasonCode: 'DELEGATION_VERIFICATION_FAILED',
      })).resolves.toBeUndefined();
    }

    const refs = (await journal.snapshot(ledger))
      .filter((entry) => entry.core.event.eventType === 'delegation.rejected')
      .map((entry) => entry.core.event.details.family === 'delegation'
        ? entry.core.event.details.delegationRef
        : undefined);
    expect(refs).toEqual([
      await hasher.sha256(new TextEncoder().encode(presented[0])),
      await hasher.sha256(new TextEncoder().encode('urn:uuid:�')),
      await hasher.sha256(new Uint8Array()),
    ]);
  });

  it('bounds caller-supplied context references so best-effort audit never throws', async () => {
    const { journal, adapter } = recordedTrail();
    const longId = `urn:example:delegation:${'d'.repeat(300)}`;
    await expect(adapter.delegation('verified', {
      delegationRef: longId,
      outcome: 'succeeded',
      context: {
        authorization: {
          source: 'delegation', decision: 'allowed', delegationRef: longId,
          scopeId: 'orders:write', verificationCode: 'V'.repeat(200),
        },
        correlationId: longId,
        causationId: 'causation-1',
      },
    })).resolves.toBeUndefined();

    const event = (await journal.snapshot(ledger)).at(-1)!.core.event;
    expect(event.eventType).toBe('delegation.verified');
    expect(event.authorization).toMatchObject({
      delegationRef: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      scopeId: 'orders:write',
      verificationCode: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
    });
    expect(event.correlationId).toBe(event.authorization?.delegationRef);
    expect(event.causationId).toBe('causation-1');
  });
});
