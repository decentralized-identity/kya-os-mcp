import { describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher, type AuditSigner } from '../crypto.js';
import { digestAuditEvent } from '../integrity.js';
import { createAuditTrail, type AuditTrailEventInput } from '../service.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { MemoryAuditEvidenceProvider } from '../evidence.js';
import type { AuditEvidenceProvider } from '../providers/evidence.js';
import { LocalAuditRecorderClient } from '../providers/recorder-client.js';
import type {
  AuditOutboxItem,
  AuditOutboxItemKey,
  AuditOutboxProvider,
} from '../providers/outbox.js';
import { MemoryAuditOutbox } from '../providers/outbox.js';
import { MemoryAuditSourceState } from '../providers/source-state.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditRecorderSubmission } from '../providers/recorder-client.js';
import type { PartyRef, SignedAuditEntryV1 } from '../types.js';

class Signer implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder', kid: 'did:key:zRecorder#zRecorder', alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

const tenantRef: PartyRef = {
  kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-1',
};
const producer: PartyRef = { kind: 'pairwise_did', did: 'did:key:zProducer' };
const baseEvent: AuditTrailEventInput = {
  eventType: 'tool.call.completed',
  action: { category: 'tool.call' },
  outcome: 'succeeded',
  evidence: [],
  details: { family: 'tool', phase: 'completed', attempt: '1' },
};

function local(
  mode: 'required' | 'best-effort' = 'required',
  evidence?: AuditEvidenceProvider,
) {
  const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
  const journal = new MemoryAuditJournal();
  const recorder = new AuditRecorderService({
    ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
    journal, signer: new Signer(), hasher, clock: { now: () => 1_750_000_000_000 },
    ...(evidence === undefined ? {} : { evidence }),
  });
  const client = new LocalAuditRecorderClient(recorder, () => ({
    producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef,
  }));
  const trail = createAuditTrail({
    recorder: client, delivery: mode, hasher,
    ledgerId: 'kya:tenant:prod:primary', expectedLedgerEpochId: 'epoch_1',
    tenantRef, producer, sourceId: 'mcp-server-1',
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
    clock: { now: () => 1_750_000_000_000 },
    sourceState: new MemoryAuditSourceState(),
  });
  return { trail, journal, hasher };
}

class DurableTestOutbox implements AuditOutboxProvider {
  readonly capabilities = { durability: 'durable' as const, fifoPerSource: true as const };
  readonly items: AuditOutboxItem[] = [];
  async enqueue(item: AuditOutboxItem): Promise<void> { this.items.push(item); }
  async *pending(): AsyncIterable<AuditOutboxItem> { yield* [...this.items]; }
  async markDelivered(eventId: string): Promise<void> {
    const index = this.items.findIndex((item) => item.eventId === eventId);
    if (index >= 0) this.items.splice(index, 1);
  }
  async markFailed(): Promise<void> {}
}

/** A durable outbox that declares source-scoped keys and records each acknowledgement. */
class KeyedTestOutbox implements AuditOutboxProvider {
  readonly capabilities = {
    durability: 'durable' as const, fifoPerSource: true as const, keyedBySource: true as const,
  };
  readonly items: AuditOutboxItem[] = [];
  readonly acknowledged: Array<AuditOutboxItemKey | string> = [];
  async enqueue(item: AuditOutboxItem): Promise<void> { this.items.push(item); }
  async *pending(): AsyncIterable<AuditOutboxItem> { yield* [...this.items]; }
  async markDelivered(key: AuditOutboxItemKey | string): Promise<void> {
    this.acknowledged.push(key);
    if (typeof key === 'string') throw new Error('expected an item key');
    const index = this.items.findIndex((item) => item.eventId === key.eventId &&
      item.submission.producerEvent.source.sourceId === key.sourceId);
    if (index >= 0) this.items.splice(index, 1);
  }
  async markFailed(): Promise<void> {}
}

describe('AuditTrailService delivery modes', () => {
  it('records every call, with monotonic producer source sequence and receipts', async () => {
    const { trail, journal, hasher } = local();
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, index) => trail.record({
        ...baseEvent,
        eventId: `evt_${index}`,
      })),
    );
    expect(results.every((result) => result.status === 'recorded')).toBe(true);
    const entries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    });
    const sourceSequences = entries.slice(1)
      .map((entry) => Number(entry.core.event.source.sourceSequence))
      .sort((left, right) => left - right);
    expect(sourceSequences).toEqual(Array.from({ length: 20 }, (_, index) => index + 1));
    const bySourceSequence = [...entries.slice(1)].sort((left, right) =>
      Number(left.core.event.source.sourceSequence) - Number(right.core.event.source.sourceSequence));
    for (let index = 1; index < bySourceSequence.length; index += 1) {
      expect(bySourceSequence[index]!.core.event.source.previousSourceEventDigest).toBe(
        await digestAuditEvent(hasher, bySourceSequence[index - 1]!.core.event),
      );
    }
  });

  it('emits an explicit source high-water heartbeat through the same recorder path', async () => {
    const { trail, journal } = local();
    await trail.record({ ...baseEvent, eventId: 'evt_before_heartbeat' });
    await trail.recordSourceHighWater({ eventId: 'heartbeat_1' });
    const entries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    });
    expect(entries.at(-1)?.core.event).toMatchObject({
      eventId: 'heartbeat_1',
      eventType: 'audit.source_high_water',
      details: { family: 'administration', phase: 'source_high_water', sourceSequence: '1' },
    });
  });

  it('propagates required delivery failure but reports best-effort failure without throwing', async () => {
    const recorder = { submit: vi.fn(async (_submission: AuditRecorderSubmission) => {
      throw new Error('offline');
    }) };
    const failure = vi.fn();
    const common = {
      recorder,
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      ledgerId: 'ledger', tenantRef, producer, sourceId: 'source',
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25' as const,
      privacy: { classification: 'internal' as const, retentionClass: 'audit-365d' },
      clock: { now: () => 1_750_000_000_000 }, onDeliveryFailure: failure,
      sourceState: new MemoryAuditSourceState(),
    };
    await expect(createAuditTrail({ ...common, delivery: 'required' }).record(baseEvent))
      .rejects.toThrow('offline');
    await expect(createAuditTrail({ ...common, delivery: 'best-effort' }).record(baseEvent))
      .resolves.toMatchObject({ status: 'failed' });
    expect(failure).toHaveBeenCalledTimes(2);
  });

  it('durably enqueues buffered events before returning and reconciles them to receipts', async () => {
    const { trail: required } = local();
    const outbox = new DurableTestOutbox();
    const buffered = createAuditTrail({
      ...required.configuration,
      recorder: required.configuration.recorder,
      delivery: 'buffered',
      outbox,
    });
    await expect(buffered.record({ ...baseEvent, eventId: 'evt_buffered' }))
      .resolves.toMatchObject({ status: 'pending' });
    expect(outbox.items).toHaveLength(1);
    await buffered.flush();
    expect(outbox.items).toHaveLength(0);
  });

  it('does not flush later events from a source past a failed predecessor', async () => {
    const { trail } = local();
    const outbox = new DurableTestOutbox();
    const submit = vi.fn(async () => { throw new Error('recorder offline'); });
    const buffered = createAuditTrail({
      ...trail.configuration,
      recorder: { submit },
      delivery: 'buffered',
      outbox,
      sourceState: new MemoryAuditSourceState(),
    });
    await buffered.record({ ...baseEvent, eventId: 'evt_flush_first' });
    await buffered.record({ ...baseEvent, eventId: 'evt_flush_second' });

    await expect(buffered.flush()).resolves.toEqual({ delivered: 0, failed: 1 });
    expect(submit).toHaveBeenCalledOnce();
    expect(outbox.items.map((item) => item.eventId)).toEqual([
      'evt_flush_first', 'evt_flush_second',
    ]);
  });

  it('delivers pending items and redelivered retries across an epoch rollover', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const journal = new MemoryAuditJournal();
    const clock = { now: () => 1_750_000_000_000 };
    const recorderConfig = {
      ledgerId: 'kya:tenant:prod:primary', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25' as const, sourceId: 'recorder-1',
      journal, signer: new Signer(), hasher, clock,
    };
    const context = () => ({
      producerAuthority: 'did:key:zProducer', tenantAuthority: 'tenant-1', tenantRef,
    });
    const outbox = new DurableTestOutbox();
    const sourceState = new MemoryAuditSourceState();
    const trailConfig = {
      delivery: 'buffered' as const, hasher,
      ledgerId: 'kya:tenant:prod:primary', tenantRef, producer, sourceId: 'mcp-server-1',
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25' as const,
      privacy: { classification: 'internal' as const, retentionClass: 'audit-365d' },
      clock, outbox, sourceState,
    };
    const epochOne = createAuditTrail({
      ...trailConfig,
      recorder: new LocalAuditRecorderClient(
        new AuditRecorderService({ ...recorderConfig, ledgerEpochId: 'epoch_1' }),
        context,
      ),
      expectedLedgerEpochId: 'epoch_1',
    });

    await epochOne.record({ ...baseEvent, eventId: 'evt_rollover_recorded' });
    expect(outbox.items[0]?.submission.expectedLedgerEpochId).toBeUndefined();
    const redelivery = outbox.items[0]!;
    await expect(epochOne.flush()).resolves.toEqual({ delivered: 1, failed: 0 });
    await epochOne.record({ ...baseEvent, eventId: 'evt_rollover_pending' });

    const epochTwo = createAuditTrail({
      ...trailConfig,
      recorder: new LocalAuditRecorderClient(new AuditRecorderService({
        ...recorderConfig,
        ledgerEpochId: 'epoch_2',
        previousEpochId: 'epoch_1',
        previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
        epochTransitionGuard: { verifyAndSeal: async () => true },
      }), context),
      expectedLedgerEpochId: 'epoch_2',
    });
    outbox.items.push(redelivery);

    await expect(epochTwo.flush()).resolves.toEqual({ delivered: 2, failed: 0 });
    const epochTwoEntries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2',
    });
    expect(epochTwoEntries.map((entry) => entry.core.event.eventId)).toEqual([
      'genesis:kya:tenant:prod:primary:epoch_2', 'evt_rollover_pending',
    ]);
    const epochOneEntries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    });
    expect(epochOneEntries.filter(
      (entry) => entry.core.event.eventId === 'evt_rollover_recorded',
    )).toHaveLength(1);
  });

  it('receipts each flushed outbox item against its own producer source', async () => {
    const { trail } = local();
    const outbox = new DurableTestOutbox();
    const sourceState = new MemoryAuditSourceState();
    const receipts = vi.spyOn(sourceState, 'markReceipted');
    const shared = { ...trail.configuration, delivery: 'buffered' as const, outbox, sourceState };
    const trailA = createAuditTrail({ ...shared, sourceId: 'source-a' });
    const trailB = createAuditTrail({ ...shared, sourceId: 'source-b' });
    await trailA.record({ ...baseEvent, eventId: 'evt_source_a' });
    await trailB.record({ ...baseEvent, eventId: 'evt_source_b' });

    await expect(trailA.flush()).resolves.toEqual({ delivered: 2, failed: 0 });
    expect(receipts.mock.calls.map(([receiptSourceId, sequence]) => [receiptSourceId, sequence]))
      .toEqual([['source-a', '1'], ['source-b', '1']]);
  });

  it('commits buffered outbox items in claimed source-sequence order under concurrency', async () => {
    const { trail } = local();
    const outbox = new DurableTestOutbox();
    const originalEnqueue = outbox.enqueue.bind(outbox);
    let delayed = false;
    outbox.enqueue = async (item) => {
      if (!delayed) {
        delayed = true;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      await originalEnqueue(item);
    };
    const buffered = createAuditTrail({
      ...trail.configuration,
      delivery: 'buffered',
      outbox,
      sourceState: new MemoryAuditSourceState(),
    });
    await Promise.all([
      buffered.record({ ...baseEvent, eventId: 'evt_concurrent_first' }),
      buffered.record({ ...baseEvent, eventId: 'evt_concurrent_second' }),
    ]);
    expect(outbox.items.map((item) => item.submission.producerEvent.source.sourceSequence))
      .toEqual(['1', '2']);
  });

  it('makes direct-mode retries idempotent when eventId and occurredAt are pinned together', async () => {
    const { trail, journal } = local();
    const first = await trail.record({
      ...baseEvent, eventId: 'evt_pinned_retry', occurredAt: 1_750_000_000_123,
    });
    const restarted = createAuditTrail({
      ...trail.configuration, sourceState: new MemoryAuditSourceState(),
    });
    const retry = await restarted.record({
      ...baseEvent, eventId: 'evt_pinned_retry', occurredAt: 1_750_000_000_123,
    });
    expect(retry.status).toBe('recorded');
    expect(retry).toEqual(first);
    await expect(journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    })).resolves.toHaveLength(2);
  });

  it('rejects an unpinned same-eventId retry whose rebuilt content drifted', async () => {
    const { trail } = local();
    let tick = 0;
    const drifting = createAuditTrail({
      ...trail.configuration, clock: { now: () => 1_750_000_000_000 + (tick += 1) },
    });
    await drifting.record({ ...baseEvent, eventId: 'evt_drifting_retry' });
    const restarted = createAuditTrail({
      ...trail.configuration,
      clock: { now: () => 1_750_000_000_000 + (tick += 1) },
      sourceState: new MemoryAuditSourceState(),
    });
    await expect(restarted.record({ ...baseEvent, eventId: 'evt_drifting_retry' }))
      .rejects.toMatchObject({ code: 'AUDIT_EVENT_ID_CONFLICT' });
  });

  it('rejects buffered mode backed only by an ephemeral outbox', () => {
    expect(() => createAuditTrail({
      ...local().trail.configuration,
      delivery: 'buffered',
      outbox: {
        capabilities: { durability: 'ephemeral', fifoPerSource: true },
        enqueue: async () => undefined,
        pending: async function* () {},
        markDelivered: async () => undefined,
        markFailed: async () => undefined,
      },
    })).toThrow(/durable outbox/i);
  });

  it('makes outbox redelivery idempotent by canonical frozen content, not object identity', async () => {
    const { trail } = local();
    const result = await trail.record({ ...baseEvent, eventId: 'evt_outbox_contract' });
    const submission: AuditRecorderSubmission = {
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: result.event,
      encryptedEvidence: [],
    };
    const item: AuditOutboxItem = {
      eventId: result.event.eventId, submission, enqueuedAt: 1, attempts: 0,
    };
    const outbox = new MemoryAuditOutbox();
    await outbox.enqueue(item);
    await expect(outbox.enqueue(structuredClone(item))).resolves.toBeUndefined();
    const changed = structuredClone(item);
    changed.submission.producerEvent.action.category = 'changed';
    await expect(outbox.enqueue(changed)).rejects.toThrow(/identity collision/i);
  });

  it('compares redelivered outbox evidence byte-for-byte before accepting it as idempotent', async () => {
    const { trail } = local();
    const result = await trail.record({ ...baseEvent, eventId: 'evt_outbox_evidence' });
    const ref = {
      objectId: 'evi_outbox',
      ciphertextDigest: `sha256:${'a'.repeat(64)}` as const,
      mediaType: 'application/octet-stream',
      size: '3',
      encryption: {
        suite: 'A256GCM' as const,
        keyId: 'tenant-key-v1',
        nonce: 'AAAAAAAAAAAAAAAA',
        aadDigest: `sha256:${'b'.repeat(64)}` as const,
      },
    };
    const item = (ciphertext: Uint8Array, objectId = ref.objectId): AuditOutboxItem => ({
      eventId: result.event.eventId,
      submission: {
        ledgerId: 'kya:tenant:prod:primary',
        producerEvent: result.event,
        encryptedEvidence: [{ ref: { ...ref, objectId }, ciphertext }],
      },
      enqueuedAt: 1,
      attempts: 0,
    });
    const outbox = new MemoryAuditOutbox();
    await outbox.enqueue(item(Uint8Array.of(1, 2, 3)));

    // Byte-identical evidence is idempotent; any divergence is an identity collision.
    await expect(outbox.enqueue(item(Uint8Array.of(1, 2, 3)))).resolves.toBeUndefined();
    await expect(outbox.enqueue(item(Uint8Array.of(1, 2, 4))))
      .rejects.toThrow(/identity collision/i);
    await expect(outbox.enqueue(item(Uint8Array.of(1, 2))))
      .rejects.toThrow(/identity collision/i);
    await expect(outbox.enqueue(item(Uint8Array.of(1, 2, 3), 'evi_other')))
      .rejects.toThrow(/identity collision/i);
    const remaining: AuditOutboxItem[] = [];
    for await (const pending of outbox.pending()) remaining.push(pending);
    expect(remaining).toHaveLength(1);
  });

  it('tracks outbox delivery attempts and removes only acknowledged events', async () => {
    const { trail } = local();
    const firstEvent = await trail.record({ ...baseEvent, eventId: 'evt_outbox_first' });
    const secondEvent = await trail.record({ ...baseEvent, eventId: 'evt_outbox_second' });
    const item = (event: typeof firstEvent.event): AuditOutboxItem => ({
      eventId: event.eventId,
      submission: {
        ledgerId: 'kya:tenant:prod:primary', producerEvent: event, encryptedEvidence: [],
      },
      enqueuedAt: 1,
      attempts: 0,
    });
    const outbox = new MemoryAuditOutbox();
    await outbox.enqueue(item(firstEvent.event));
    await outbox.enqueue(item(secondEvent.event));

    const collect = async () => {
      const values: AuditOutboxItem[] = [];
      for await (const pending of outbox.pending()) values.push(pending);
      return values;
    };
    const limited: AuditOutboxItem[] = [];
    for await (const pending of outbox.pending(1)) limited.push(pending);
    expect(limited).toHaveLength(1);
    await outbox.markFailed(firstEvent.event.eventId, new Error('recorder offline'));
    expect((await collect())[0]?.attempts).toBe(1);
    await outbox.markFailed('unknown-event', new Error('already reconciled'));
    await outbox.markDelivered(firstEvent.event.eventId);
    expect((await collect()).map((pending) => pending.eventId))
      .toEqual([secondEvent.event.eventId]);
  });

  it('persists encrypted evidence before appending an event that commits its reference', async () => {
    const evidenceHasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const evidence = new MemoryAuditEvidenceProvider(evidenceHasher);
    const { trail } = local('required', evidence);
    const ciphertext = Uint8Array.of(1, 2, 3);
    const ref = {
      objectId: 'evi_trail_test',
      ciphertextDigest: await evidenceHasher.sha256(ciphertext),
      mediaType: 'application/octet-stream',
      size: '3',
      encryption: {
        suite: 'A256GCM' as const,
        keyId: 'tenant-key-v1',
        nonce: 'AAAAAAAAAAAAAAAA',
        aadDigest: await evidenceHasher.sha256(new Uint8Array()),
      },
    };
    await trail.record(
      { ...baseEvent, eventId: 'evt_with_evidence', evidence: [ref] },
      { encryptedEvidence: [{ ref, ciphertext }] },
    );
    await expect(evidence.has(ref)).resolves.toBe(true);
  });

  it('reports a committed event as recorded when only source watermark persistence fails', async () => {
    const { trail, journal } = local();
    const onSourceStateFailure = vi.fn();
    const failingSourceState = new MemoryAuditSourceState();
    vi.spyOn(failingSourceState, 'markReceipted').mockRejectedValue(
      new Error('source state unavailable'),
    );
    const configured = createAuditTrail({
      ...trail.configuration,
      sourceState: failingSourceState,
      onSourceStateFailure,
    });

    await expect(configured.record({ ...baseEvent, eventId: 'evt_committed_state_failure' }))
      .resolves.toMatchObject({ status: 'recorded' });
    expect(onSourceStateFailure).toHaveBeenCalledOnce();
    await expect(journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    })).resolves.toHaveLength(2);
  });

  it('reports emitted/receipted source high-water marks and explicit gaps', async () => {
    const { trail } = local();
    await trail.record({ ...baseEvent, eventId: 'evt_a' });
    await trail.record({ ...baseEvent, eventId: 'evt_b' });
    await expect(trail.getSourceState()).resolves.toEqual({
      sourceId: 'mcp-server-1',
      highestEmitted: '2',
      highestReceipted: '2',
      pendingSequences: [],
    });

    const failing = createAuditTrail({
      ...trail.configuration,
      recorder: { submit: async () => { throw new Error('offline'); } },
      delivery: 'best-effort',
      sourceState: new MemoryAuditSourceState(),
    });
    await failing.record({ ...baseEvent, eventId: 'evt_gap' });
    await expect(failing.getSourceState()).resolves.toMatchObject({
      highestEmitted: '1', highestReceipted: '0', pendingSequences: ['1'],
    });
  });

  it('exposes only truthful assurance capabilities and rejects inconsistent startup claims', () => {
    const { trail } = local();
    expect(trail.auditProfile).toBe('AAP-0');
    expect(trail.capabilities).toBeUndefined();
    const capabilities = {
      profile: 'AAP-2' as const,
      recorderTopology: 'self-hosted' as const,
      delivery: 'required' as const,
      journalDurability: 'durable' as const,
      atomicAppend: true,
      sourceHighWater: false,
      merkleCheckpoints: false,
      independentObservation: false,
      supportingAnchors: [],
      evidenceRetention: 'separate' as const,
    };
    const declared = createAuditTrail({ ...trail.configuration, capabilities });
    expect(declared.auditProfile).toBe('AAP-2');
    expect(declared.capabilities).toEqual(capabilities);

    expect(() => createAuditTrail({
      ...trail.configuration,
      capabilities: { ...capabilities, delivery: 'buffered' },
    })).toThrow(/does not match/);
    expect(() => createAuditTrail({
      ...trail.configuration,
      capabilities: {
        ...capabilities, profile: 'AAP-3', sourceHighWater: true, merkleCheckpoints: true,
      },
    })).toThrow(/durable source state/);
  });

  it('rejects recorder receipts that do not bind every submitted event boundary', async () => {
    const { trail } = local();
    const mutations: Array<(entry: SignedAuditEntryV1) => void> = [
      (entry) => {
        entry.core.ledgerId = 'wrong-ledger';
      },
      (entry) => { entry.eventDigest = `sha256:${'d'.repeat(64)}`; },
      (entry) => { entry.core.eventDigest = `sha256:${'e'.repeat(64)}`; },
      (entry) => { entry.core.event.action.category = 'tampered'; },
    ];

    for (const [index, mutate] of mutations.entries()) {
      const recorder = {
        submit: async (submission: AuditRecorderSubmission) => {
          const eventDigest = await digestAuditEvent(trail.configuration.hasher, submission.producerEvent);
          const entry: SignedAuditEntryV1 = {
            core: {
              schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0' as const,
              ledgerId: submission.ledgerId,
              ledgerEpochId: submission.expectedLedgerEpochId ?? 'epoch_1',
              sequence: '1' as const,
              previousEntryDigest: null,
              recordedAt: 1_750_000_000_000,
              recorder: new Signer().ref,
              eventDigest,
              event: structuredClone(submission.producerEvent),
              evidenceManifestDigest: `sha256:${'b'.repeat(64)}` as const,
              integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026' as const,
            },
            eventDigest,
            entryDigest: `sha256:${'c'.repeat(64)}` as const,
            recorderReceipt: {
              core: {
                schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0' as const,
                ledgerId: submission.ledgerId,
                ledgerEpochId: submission.expectedLedgerEpochId ?? 'epoch_1',
                sequence: '1' as const,
                eventId: submission.producerEvent.eventId,
                entryDigest: `sha256:${'c'.repeat(64)}` as const,
                previousEntryDigest: null,
                recordedAt: 1_750_000_000_000,
                recorder: new Signer().ref,
                integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026' as const,
              },
              jws: 'signature',
            },
          };
          mutate(entry);
          return entry;
        },
      };
      const validating = createAuditTrail({ ...trail.configuration, recorder });
      await expect(validating.record({
        ...baseEvent, eventId: `evt_tampered_receipt_${index}`,
      })).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });
    }
  });

  it('accepts a content-bound duplicate entry from an earlier retained epoch', async () => {
    const { trail } = local();
    const recorder = {
      submit: async (submission: AuditRecorderSubmission): Promise<SignedAuditEntryV1> => {
        const eventDigest = await digestAuditEvent(
          trail.configuration.hasher,
          submission.producerEvent,
        );
        return {
          core: {
            schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0' as const,
            ledgerId: submission.ledgerId,
            ledgerEpochId: 'epoch_0',
            sequence: '7' as const,
            previousEntryDigest: `sha256:${'a'.repeat(64)}` as const,
            recordedAt: 1_749_000_000_000,
            recorder: new Signer().ref,
            eventDigest,
            event: structuredClone(submission.producerEvent),
            evidenceManifestDigest: `sha256:${'b'.repeat(64)}` as const,
            integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026' as const,
          },
          eventDigest,
          entryDigest: `sha256:${'c'.repeat(64)}` as const,
          recorderReceipt: {
            core: {
              schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0' as const,
              ledgerId: submission.ledgerId,
              ledgerEpochId: 'epoch_0',
              sequence: '7' as const,
              eventId: submission.producerEvent.eventId,
              entryDigest: `sha256:${'c'.repeat(64)}` as const,
              previousEntryDigest: `sha256:${'a'.repeat(64)}` as const,
              recordedAt: 1_749_000_000_000,
              recorder: new Signer().ref,
              integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026' as const,
            },
            jws: 'signature',
          },
        };
      },
    };
    const crossEpoch = createAuditTrail({ ...trail.configuration, recorder });
    await expect(crossEpoch.record({ ...baseEvent, eventId: 'evt_cross_epoch_duplicate' }))
      .resolves.toMatchObject({
        status: 'recorded',
        entry: { core: { ledgerEpochId: 'epoch_0' } },
      });
  });

  it('mints default event IDs that two trails sharing one outbox cannot collide on', async () => {
    const { trail } = local();
    const outbox = new MemoryAuditOutbox();
    const durable: AuditOutboxProvider = Object.assign(
      Object.create(outbox) as AuditOutboxProvider,
      { capabilities: { durability: 'durable' as const, fifoPerSource: true as const } },
    );
    const shared = { ...trail.configuration, delivery: 'buffered' as const, outbox: durable };
    // Same clock reading and a fresh trail each: a time/counter ID would repeat.
    const trailA = createAuditTrail({
      ...shared, sourceId: 'source-a', sourceState: new MemoryAuditSourceState(),
    });
    const trailB = createAuditTrail({
      ...shared, sourceId: 'source-b', sourceState: new MemoryAuditSourceState(),
    });
    const first = await trailA.record(baseEvent);
    const second = await trailB.record(baseEvent);
    expect(first.event.eventId).not.toBe(second.event.eventId);
    expect(first.event.eventId).toMatch(/^audit_[0-9a-f-]{36}$/);
  });

  it('acknowledges by item key an outbox that declares it, and by bare event ID otherwise', async () => {
    const { trail, journal } = local();
    const outbox = new KeyedTestOutbox();
    const recorder = {
      submit: async (submission: AuditRecorderSubmission) => {
        if (submission.producerEvent.source.sourceId === 'source-a') {
          throw new Error('source-a recorder route offline');
        }
        return trail.configuration.recorder.submit(submission);
      },
    };
    const shared = {
      ...trail.configuration, recorder, delivery: 'buffered' as const, outbox,
    };
    const trailA = createAuditTrail({
      ...shared, sourceId: 'source-a', sourceState: new MemoryAuditSourceState(),
    });
    const trailB = createAuditTrail({
      ...shared, sourceId: 'source-b', sourceState: new MemoryAuditSourceState(),
    });
    // A caller-chosen event ID is unique only within its own source.
    await trailA.record({ ...baseEvent, eventId: 'evt_shared_name' });
    await trailB.record({ ...baseEvent, eventId: 'evt_shared_name' });

    await expect(trailA.flush()).resolves.toEqual({ delivered: 1, failed: 1 });
    expect(outbox.acknowledged).toEqual([{ sourceId: 'source-b', eventId: 'evt_shared_name' }]);
    expect(outbox.items.map((item) => item.submission.producerEvent.source.sourceId))
      .toEqual(['source-a']);
    await expect(journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    })).resolves.toHaveLength(2);

    // An adapter written against `markDelivered(eventId: string)` still gets one.
    const legacy = new DurableTestOutbox();
    const delivered = vi.spyOn(legacy, 'markDelivered');
    const legacyTrail = createAuditTrail({
      ...trail.configuration, delivery: 'buffered', outbox: legacy,
    });
    await legacyTrail.record({ ...baseEvent, eventId: 'evt_legacy_outbox' });
    await expect(legacyTrail.flush()).resolves.toEqual({ delivered: 1, failed: 0 });
    expect(delivered).toHaveBeenCalledWith('evt_legacy_outbox');
    expect(legacy.items).toHaveLength(0);
  });

  it('hands a MemoryAuditOutbox subclass that overrides acknowledgement the bare event ID', async () => {
    const { trail } = local();
    // Written against 1.16: acknowledges by `eventId: string`.
    class EventIdMemoryOutbox extends MemoryAuditOutbox {
      readonly acknowledged: unknown[] = [];
      override async markDelivered(eventId: string): Promise<void> {
        this.acknowledged.push(eventId);
        await super.markDelivered(eventId);
      }
    }
    class FailureCountingOutbox extends MemoryAuditOutbox {
      override async markFailed(eventId: string): Promise<void> {
        await super.markFailed(eventId);
      }
    }
    class KeyAwareOutbox extends MemoryAuditOutbox {
      override readonly capabilities = {
        durability: 'ephemeral' as const, fifoPerSource: true as const, keyedBySource: true as const,
      };
      override async markDelivered(key: AuditOutboxItemKey | string): Promise<void> {
        await super.markDelivered(key);
      }
    }
    expect(new MemoryAuditOutbox().capabilities.keyedBySource).toBe(true);
    expect(new (class extends MemoryAuditOutbox {})().capabilities.keyedBySource).toBe(true);
    expect(new EventIdMemoryOutbox().capabilities.keyedBySource).toBeUndefined();
    expect(new FailureCountingOutbox().capabilities.keyedBySource).toBeUndefined();
    expect(new KeyAwareOutbox().capabilities.keyedBySource).toBe(true);

    const outbox = new EventIdMemoryOutbox();
    // Buffered delivery needs a durable outbox; the memory outbox stands in.
    Object.assign(outbox, { capabilities: { ...outbox.capabilities, durability: 'durable' } });
    const buffered = createAuditTrail({ ...trail.configuration, delivery: 'buffered', outbox });
    await buffered.record({ ...baseEvent, eventId: 'evt_subclassed_outbox' });
    await expect(buffered.flush()).resolves.toEqual({ delivered: 1, failed: 0 });
    expect(outbox.acknowledged).toEqual(['evt_subclassed_outbox']);
    const remaining: AuditOutboxItem[] = [];
    for await (const item of outbox.pending()) remaining.push(item);
    expect(remaining).toEqual([]);
  });

  it('resolves a stable event ID redelivered after later events to its original receipt', async () => {
    const { trail, journal } = local();
    const first = await trail.record({
      ...baseEvent, eventId: 'order-42-completed', occurredAt: 1,
    });
    await trail.record({ ...baseEvent, eventId: 'order-43-completed', occurredAt: 2 });
    // At-least-once upstream delivery repeats order 42 with identical input.
    const retry = await trail.record({
      ...baseEvent, eventId: 'order-42-completed', occurredAt: 1,
    });

    expect(retry).toEqual(first);
    await expect(journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    })).resolves.toHaveLength(3);
    await expect(trail.getSourceState()).resolves.toMatchObject({
      highestEmitted: '2', highestReceipted: '2', pendingSequences: [],
    });
  });

  it('reports a redelivered event ID with different content as an event-ID conflict', async () => {
    const { trail } = local();
    await trail.record({ ...baseEvent, eventId: 'order-42-completed', occurredAt: 1 });
    await trail.record({ ...baseEvent, eventId: 'order-43-completed', occurredAt: 2 });
    // Drifted content under a retained claim, for an older and the latest event.
    for (const eventId of ['order-42-completed', 'order-43-completed']) {
      await expect(trail.record({ ...baseEvent, eventId, occurredAt: 99 })).rejects.toMatchObject({
        code: 'AUDIT_EVENT_ID_CONFLICT',
        message: `Source event identity collision: ${eventId}`,
      });
    }
    await expect(trail.getSourceState()).resolves.toMatchObject({
      highestEmitted: '2', pendingSequences: [],
    });
  });

  it('rejects invalid input before claiming a source sequence, keeping linkage intact', async () => {
    const { trail, hasher } = local();
    const first = await trail.record({ ...baseEvent, eventId: 'evt_valid_before' });
    await expect(trail.record({
      ...baseEvent, eventId: 'evt_schema_invalid', reason: { code: 'X'.repeat(200) },
    })).rejects.toThrow();
    await expect(trail.record({
      ...baseEvent, eventId: 'evt_lone_surrogate', correlationId: JSON.parse('"\\ud800"'),
    })).rejects.toThrow();
    await expect(trail.record({ ...baseEvent, eventId: 'evt_unreferenced_evidence' }, {
      encryptedEvidence: [{
        ref: {
          objectId: 'evi_unreferenced',
          ciphertextDigest: `sha256:${'a'.repeat(64)}`,
          mediaType: 'application/octet-stream',
          size: '1',
          encryption: {
            suite: 'A256GCM', keyId: 'k1', nonce: 'AAAAAAAAAAAAAAAA',
            aadDigest: `sha256:${'b'.repeat(64)}`,
          },
        },
        ciphertext: Uint8Array.of(1),
      }],
    })).rejects.toMatchObject({ code: 'AUDIT_EVIDENCE_FAILURE' });
    const next = await trail.record({ ...baseEvent, eventId: 'evt_valid_after' });

    expect(next.event.source.sourceSequence).toBe('2');
    expect(next.event.source.previousSourceEventDigest)
      .toBe(await digestAuditEvent(hasher, first.event));
    await expect(trail.getSourceState()).resolves.toMatchObject({ pendingSequences: [] });
  });

  it('releases a claim whose event could not be emitted', async () => {
    const { trail, hasher } = local();
    const sourceState = new MemoryAuditSourceState();
    const configured = createAuditTrail({ ...trail.configuration, sourceState });
    const first = await configured.record({ ...baseEvent, eventId: 'evt_emitted' });
    vi.spyOn(sourceState, 'markEmitted').mockRejectedValueOnce(new Error('state store offline'));
    await expect(configured.record({ ...baseEvent, eventId: 'evt_not_emitted' }))
      .rejects.toThrow('state store offline');
    const next = await configured.record({ ...baseEvent, eventId: 'evt_after_release' });

    expect(next.event.source.sourceSequence).toBe('2');
    expect(next.event.source.previousSourceEventDigest)
      .toBe(await digestAuditEvent(hasher, first.event));
  });

  it('surfaces the emission failure, not a failed release, and keeps the gap visible', async () => {
    const { trail } = local();
    const sourceState = new MemoryAuditSourceState();
    const configured = createAuditTrail({ ...trail.configuration, sourceState });
    await configured.record({ ...baseEvent, eventId: 'evt_emitted' });
    vi.spyOn(sourceState, 'markEmitted').mockRejectedValueOnce(new Error('state store offline'));
    vi.spyOn(sourceState, 'abandonClaim').mockRejectedValueOnce(new Error('release failed'));
    await expect(configured.record({ ...baseEvent, eventId: 'evt_not_emitted' }))
      .rejects.toThrow('state store offline');
    await expect(configured.getSourceState()).resolves.toMatchObject({
      highestEmitted: '2', pendingSequences: ['2'],
    });
  });

  it('bounds source-state memory by pending events and the redelivery window', async () => {
    const { trail } = local();
    let calls = 0;
    const flaky = {
      submit: async (submission: AuditRecorderSubmission) => {
        calls += 1;
        if (calls === 1) throw new Error('recorder briefly unavailable');
        return trail.configuration.recorder.submit(submission);
      },
    };
    const sourceState = new MemoryAuditSourceState({ redeliveryWindow: 4 });
    const bestEffort = createAuditTrail({
      ...trail.configuration, recorder: flaky, delivery: 'best-effort', sourceState,
    });
    await expect(bestEffort.record(baseEvent)).resolves.toMatchObject({ status: 'failed' });
    for (let index = 0; index < 200; index += 1) {
      await expect(bestEffort.record(baseEvent)).resolves.toMatchObject({ status: 'recorded' });
    }

    // One sequence stays an open gap, which must not stop pruning everything after it.
    await expect(bestEffort.getSourceState()).resolves.toEqual({
      sourceId: 'mcp-server-1',
      highestEmitted: '201',
      highestReceipted: '0',
      pendingSequences: ['1'],
    });
    const internal = (sourceState as unknown as {
      states: Map<string, { claims: Map<string, unknown>; pending: Map<bigint, string> }>;
    }).states.get('mcp-server-1')!;
    expect(internal.pending.size).toBe(1);
    expect(internal.claims.size).toBe(1 + 4);
    expect(() => new MemoryAuditSourceState({ redeliveryWindow: -1 })).toThrow(RangeError);
  });

  it('counts a committed outbox item as delivered when only its acknowledgement fails', async () => {
    const { trail, journal } = local();
    const outbox = new DurableTestOutbox();
    const markFailed = vi.spyOn(outbox, 'markFailed');
    const acknowledge = outbox.markDelivered.bind(outbox);
    let acknowledgementFailures = 1;
    outbox.markDelivered = async (eventId) => {
      if (acknowledgementFailures-- > 0) throw new Error('outbox ack timeout');
      await acknowledge(eventId);
    };
    const onDeliveryFailure = vi.fn();
    const onAcknowledgementFailure = vi.fn();
    const buffered = createAuditTrail({
      ...trail.configuration,
      delivery: 'buffered',
      outbox,
      onDeliveryFailure,
      onAcknowledgementFailure,
    });
    await buffered.record({ ...baseEvent, eventId: 'evt_unacknowledged' });

    await expect(buffered.flush()).resolves.toEqual({ delivered: 1, failed: 0 });
    expect(markFailed).not.toHaveBeenCalled();
    expect(onDeliveryFailure).not.toHaveBeenCalled();
    expect(onAcknowledgementFailure).toHaveBeenCalledOnce();
    // The item stays pending; redelivery resolves to the same receipt.
    await expect(buffered.flush()).resolves.toEqual({ delivered: 1, failed: 0 });
    expect(outbox.items).toHaveLength(0);
    await expect(journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    })).resolves.toHaveLength(2);
  });
});
