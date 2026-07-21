import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import {
  AUDIT_EVENT_SCHEMA_ID,
  type AuditProducerEventCoreV1,
  type AuditSigner,
  type PartyRef,
} from '../index.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AuditProtocolError } from '../errors.js';
import { LocalAuditRecorderClient } from '../providers/recorder-client.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { AuditRecorderService } from '../recorder-service.js';
import type { AuditEvidenceProvider } from '../providers/evidence.js';

const tenantRef: PartyRef = {
  kind: 'keyed_commitment',
  value: `sha256:${'a'.repeat(64)}`,
  keyId: 'tenant-key-1',
};

class MutableClock {
  constructor(public value = 1_750_000_000_000) {}
  now(): number { return this.value; }
}

class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder',
    kid: 'did:key:zRecorder#zRecorder',
    alg: 'EdDSA' as const,
  };

  async sign(payload: Uint8Array): Promise<string> {
    return `test.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

function event(id: string, sequence: number, outcome: 'succeeded' | 'failed' = 'succeeded'): AuditProducerEventCoreV1 {
  return {
    schema: AUDIT_EVENT_SCHEMA_ID,
    eventId: id,
    eventType: outcome === 'succeeded' ? 'tool.call.completed' : 'tool.call.failed',
    eventVersion: '1.0.0',
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    occurredAt: 1_750_000_000_000 + sequence,
    tenantRef,
    source: {
      producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
      sourceId: 'mcp-server-1',
      sourceSequence: String(sequence),
    },
    action: { category: 'tool.call', name: 'orders.create' },
    outcome,
    evidence: [],
    details: {
      family: 'tool',
      phase: outcome === 'succeeded' ? 'completed' : 'failed',
      attempt: '1',
    },
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
  };
}

function service(input: {
  journal?: MemoryAuditJournal;
  clock?: MutableClock;
  epoch?: string;
  previousEpochId?: string;
  previousTerminalCheckpointDigest?: `sha256:${string}`;
  evidence?: AuditEvidenceProvider;
} = {}) {
  const crypto = new NodeCryptoProvider();
  const journal = input.journal ?? new MemoryAuditJournal();
  const clock = input.clock ?? new MutableClock();
  const recorder = new AuditRecorderService({
    ledgerId: 'kya:tenant:prod:primary',
    ledgerEpochId: input.epoch ?? 'epoch_1',
    tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1',
    journal,
    signer: new TestSigner(),
    hasher: new CryptoProviderAuditHasher(crypto),
    clock,
    ...(input.evidence === undefined ? {} : { evidence: input.evidence }),
    ...(input.previousEpochId ? { previousEpochId: input.previousEpochId } : {}),
    ...(input.previousTerminalCheckpointDigest
      ? { previousTerminalCheckpointDigest: input.previousTerminalCheckpointDigest }
      : {}),
  });
  return { recorder, journal, clock };
}

const context = {
  producerAuthority: 'did:key:zAuthenticatedProducer',
  tenantAuthority: 'tenant-1',
};

describe('AuditRecorderService', () => {
  it('creates an epoch genesis and appends a signed, chained first producer event', async () => {
    const { recorder, journal } = service();
    const appended = await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      expectedLedgerEpochId: 'epoch_1',
      producerEvent: event('evt_1', 1),
      encryptedEvidence: [],
    }, context);

    expect(appended.core.sequence).toBe('1');
    expect(appended.core.ledgerEpochId).toBe('epoch_1');
    expect(appended.core.previousEntryDigest).toMatch(/^sha256:/);
    expect(appended.recorderReceipt.core.entryDigest).toBe(appended.entryDigest);
    expect(appended.recorderReceipt.jws).toMatch(/^test\./);

    const entries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary',
      ledgerEpochId: 'epoch_1',
    });
    expect(entries.map((entry) => entry.core.sequence)).toEqual(['0', '1']);
    expect(entries[0]?.core.event.eventType).toBe('ledger.epoch.started');
  });

  it('returns the exact original receipt for an identical retry', async () => {
    const clock = new MutableClock();
    const { recorder } = service({ clock });
    const producerEvent = event('evt_retry', 1);
    const input = {
      ledgerId: 'kya:tenant:prod:primary',
      expectedLedgerEpochId: 'epoch_1',
      producerEvent,
      encryptedEvidence: [],
    } as const;

    const first = await recorder.submitAuthenticated(input, context);
    clock.value += 60_000;
    const retry = await recorder.submitAuthenticated(input, context);

    expect(retry).toEqual(first);
    expect(retry.core.recordedAt).toBe(first.core.recordedAt);
    expect(retry.recorderReceipt.jws).toBe(first.recorderReceipt.jws);
  });

  it('rejects reuse of the authenticated producer event identity with different bytes', async () => {
    const { recorder } = service();
    await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_conflict', 1),
      encryptedEvidence: [],
    }, context);

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_conflict', 1, 'failed'),
      encryptedEvidence: [],
    }, context)).rejects.toMatchObject<Partial<AuditProtocolError>>({
      code: 'AUDIT_EVENT_ID_CONFLICT',
    });
  });

  it('serializes concurrent writers without gaps or forks', async () => {
    const { recorder, journal } = service();
    const results = await Promise.all(
      Array.from({ length: 100 }, (_, index) => recorder.submitAuthenticated({
        ledgerId: 'kya:tenant:prod:primary',
        producerEvent: event(`evt_concurrent_${index + 1}`, index + 1),
        encryptedEvidence: [],
      }, context)),
    );

    const sequences = results.map((entry) => Number(entry.core.sequence)).sort((a, b) => a - b);
    expect(sequences).toEqual(Array.from({ length: 100 }, (_, index) => index + 1));

    const entries = await journal.snapshot({
      ledgerId: 'kya:tenant:prod:primary',
      ledgerEpochId: 'epoch_1',
    });
    for (let index = 1; index < entries.length; index += 1) {
      expect(entries[index]?.core.previousEntryDigest).toBe(entries[index - 1]?.entryDigest);
    }
  });

  it('preserves logical-ledger idempotency across epoch transitions', async () => {
    const journal = new MemoryAuditJournal();
    const firstService = service({ journal, epoch: 'epoch_1' }).recorder;
    const original = await firstService.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_transition_retry', 1),
      encryptedEvidence: [],
    }, context);

    const secondService = service({
      journal,
      epoch: 'epoch_2',
      previousEpochId: 'epoch_1',
      previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
    }).recorder;
    const retry = await secondService.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_transition_retry', 1),
      encryptedEvidence: [],
    }, context);

    expect(retry).toEqual(original);
    expect(retry.core.ledgerEpochId).toBe('epoch_1');
  });

  it('exposes a producer client that cannot supply sequence, time, signer, or idempotency key', async () => {
    const { recorder } = service();
    const client = new LocalAuditRecorderClient(recorder, () => context);
    const appended = await client.submit({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_client', 1),
      encryptedEvidence: [],
    });

    expect(appended.core.sequence).toBe('1');
    expect(appended.core.recorder.did).toBe('did:key:zRecorder');
  });

  it('rejects unreferenced encrypted evidence at the authenticated recorder boundary', async () => {
    let writes = 0;
    const evidenceProvider: AuditEvidenceProvider = {
      putIfAbsent: async (input) => { writes += 1; return input.ref; },
      has: async () => false,
      get: async () => null,
      applyRetention: async (command) => ({ ref: command.ref, state: 'missing' }),
    };
    const { recorder } = service({ evidence: evidenceProvider });
    const ref = {
      objectId: 'unreferenced', ciphertextDigest: `sha256:${'a'.repeat(64)}` as const,
      mediaType: 'application/octet-stream', size: '1',
      encryption: {
        suite: 'A256GCM' as const, keyId: 'key', nonce: 'nonce',
        aadDigest: `sha256:${'b'.repeat(64)}` as const,
      },
    };
    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent: event('evt_evidence', 1),
      encryptedEvidence: [{ ref, ciphertext: Uint8Array.of(1) }],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_EVIDENCE_FAILURE' });
    expect(writes).toBe(0);
  });
});
