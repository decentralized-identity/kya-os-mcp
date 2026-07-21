import { describe, expect, it } from 'vitest';
import { McpAuditEventAdapter } from '../adapters/mcp.js';
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
});
