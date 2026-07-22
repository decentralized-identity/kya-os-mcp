import { describe, expect, it, vi } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher, type AuditSigner } from '../crypto.js';
import { digestAuditEvent } from '../integrity.js';
import { createAuditTrail, type AuditTrailEventInput } from '../service.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { MemoryAuditEvidenceProvider } from '../evidence.js';
import type { AuditEvidenceProvider } from '../providers/evidence.js';
import { LocalAuditRecorderClient } from '../providers/recorder-client.js';
import type { AuditOutboxItem, AuditOutboxProvider } from '../providers/outbox.js';
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
      (entry) => { entry.core.ledgerEpochId = 'wrong-epoch'; },
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
});
