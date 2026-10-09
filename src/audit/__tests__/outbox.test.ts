import { describe, expect, it } from 'vitest';
import { typeErrors as typeErrorsAt } from '../../__tests__/utils/type-errors.js';
import {
  MemoryAuditOutbox,
  auditOutboxItemKey,
  type AuditOutboxItem,
} from '../providers/outbox.js';
import type { AuditProducerEventCoreV1, PartyRef } from '../types.js';

const tenantRef: PartyRef = {
  kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-1',
};

function item(sourceId: string, eventId: string): AuditOutboxItem {
  const producerEvent: AuditProducerEventCoreV1 = {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
    eventId,
    eventType: 'tool.call.completed',
    eventVersion: '1.0.0',
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    occurredAt: 1_750_000_000_000,
    tenantRef,
    source: {
      producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
      sourceId,
      sourceSequence: '1',
    },
    action: { category: 'tool.call' },
    outcome: 'succeeded',
    evidence: [],
    details: { family: 'tool', phase: 'completed', attempt: '1' },
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
  };
  return {
    eventId,
    submission: { ledgerId: 'kya:tenant:prod:primary', producerEvent, encryptedEvidence: [] },
    enqueuedAt: 1,
    attempts: 0,
  };
}

async function pending(outbox: MemoryAuditOutbox): Promise<Array<[string, number]>> {
  const values: Array<[string, number]> = [];
  for await (const value of outbox.pending()) {
    values.push([value.submission.producerEvent.source.sourceId, value.attempts]);
  }
  return values;
}

/** Type-checks `source` as an in-memory module beside `providers/outbox.ts`. */
function typeErrors(source: string): string {
  return typeErrorsAt(source, new URL('../providers/outbox-compatibility.ts', import.meta.url));
}

// An adapter written against `markDelivered(eventId: string)`, before item keys.
const eventIdAdapter = `
import type { AuditOutboxItem, AuditOutboxItemKey, AuditOutboxProvider } from './outbox.js';

export class EventIdOutbox {
  readonly capabilities = { durability: 'durable' as const, fifoPerSource: true as const };
  async enqueue(_item: AuditOutboxItem): Promise<void> {}
  async *pending(): AsyncIterable<AuditOutboxItem> {}
  async markDelivered(_eventId: string): Promise<void> {}
  async markFailed(_eventId: string, _error: unknown): Promise<void> {}
}
`;

describe('audit outbox items', () => {
  it('acknowledges by item key, or by a bare event ID only while it is unambiguous', async () => {
    const outbox = new MemoryAuditOutbox();
    // Event IDs are unique only within a source, so both items are kept.
    await outbox.enqueue(item('source-a', 'evt_shared'));
    await outbox.enqueue(item('source-b', 'evt_shared'));
    await outbox.enqueue(item('source-a', 'evt_own'));
    await outbox.enqueue(item('source-b', 'evt_shared'));
    expect(await pending(outbox)).toEqual([['source-a', 0], ['source-b', 0], ['source-a', 0]]);
    await expect(outbox.enqueue({
      ...item('source-b', 'evt_shared'), enqueuedAt: 2,
      submission: { ...item('source-b', 'evt_shared').submission, ledgerId: 'other' },
    })).rejects.toThrow(/identity collision/);

    // With two sources pending, a bare ID cannot say whose item it means.
    await expect(outbox.markDelivered('evt_shared')).rejects.toThrow(/AuditOutboxItemKey/);
    await expect(outbox.markFailed('evt_shared', new Error('offline')))
      .rejects.toThrow(/AuditOutboxItemKey/);
    expect(await pending(outbox)).toHaveLength(3);

    await outbox.markFailed({ sourceId: 'source-b', eventId: 'evt_shared' }, new Error('offline'));
    await outbox.markDelivered(auditOutboxItemKey(item('source-a', 'evt_shared')));
    // A key for no pending item changes nothing.
    await outbox.markFailed({ sourceId: 'source-c', eventId: 'evt_shared' }, new Error('offline'));
    expect(await pending(outbox)).toEqual([['source-b', 1], ['source-a', 0]]);

    // Once only one source has it pending, the bare ID is unambiguous again.
    await outbox.markFailed('evt_shared', new Error('offline'));
    await outbox.markDelivered('evt_own');
    await outbox.markDelivered('evt_unknown');
    expect(await pending(outbox)).toEqual([['source-b', 2]]);
    await outbox.markDelivered('evt_shared');
    expect(await pending(outbox)).toEqual([]);
  });

  it('keeps an adapter that acknowledges by bare event ID a valid provider', () => {
    // Method syntax keeps the parameters bivariant, so the narrower legacy
    // signature still implements the interface that also accepts a key.
    expect(typeErrors(`${eventIdAdapter}
      import { MemoryAuditOutbox } from './outbox.js';
      export class Implementing extends EventIdOutbox implements AuditOutboxProvider {}
      // A subclass that restates the earlier capabilities shape.
      export class RestatedMemoryOutbox extends MemoryAuditOutbox {
        override readonly capabilities = {
          durability: 'ephemeral' as const, fifoPerSource: true as const,
        };
        override async markDelivered(eventId: string): Promise<void> {
          await super.markDelivered(eventId);
        }
      }
      const provider: AuditOutboxProvider = new EventIdOutbox();
      const key: AuditOutboxItemKey = { sourceId: 'source-1', eventId: 'evt_1' };
      export const calls = [
        provider.markDelivered('evt_1'),
        provider.markDelivered(key),
        provider.markFailed(key, new Error('offline')),
      ];
    `)).toBe('');

    // Controls: the check is strict enough to reject a property-syntax
    // interface (strictFunctionTypes) and an incompatible parameter type.
    expect(typeErrors(`${eventIdAdapter}
      interface PropertySyntax {
        markDelivered: (key: AuditOutboxItemKey | string) => Promise<void>;
      }
      export const viaProperty: PropertySyntax = new EventIdOutbox();
    `)).toContain("Type 'EventIdOutbox' is not assignable to type 'PropertySyntax'");
    expect(typeErrors(`${eventIdAdapter}
      export class NumericOutbox extends EventIdOutbox {
        override async markDelivered(_eventId: number): Promise<void> {}
      }
      export const provider: AuditOutboxProvider = new NumericOutbox();
    `)).toContain("Type 'NumericOutbox' is not assignable to type 'AuditOutboxProvider'");
  }, 60_000);
});
