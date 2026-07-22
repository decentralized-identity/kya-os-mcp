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
import type { AuditJournalProvider } from '../providers/journal.js';

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

class OtherSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zOtherRecorder',
    kid: 'did:key:zOtherRecorder#zOtherRecorder',
    alg: 'EdDSA' as const,
  };
  async sign(): Promise<string> { return 'other.signature'; }
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
  epochTransitionGuard?: { verifyAndSeal(): Promise<boolean> };
  evidence?: AuditEvidenceProvider;
  authorizer?: { authorize(): Promise<boolean> | boolean };
  maxAppendConflicts?: number;
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
    ...(input.authorizer === undefined ? {} : { authorizer: input.authorizer }),
    ...(input.maxAppendConflicts === undefined
      ? {}
      : { maxAppendConflicts: input.maxAppendConflicts }),
    ...(input.previousEpochId ? { previousEpochId: input.previousEpochId } : {}),
    ...(input.previousTerminalCheckpointDigest
      ? { previousTerminalCheckpointDigest: input.previousTerminalCheckpointDigest }
      : {}),
    ...(input.epochTransitionGuard === undefined
      ? {}
      : { epochTransitionGuard: input.epochTransitionGuard }),
  });
  return { recorder, journal, clock };
}

function serviceWithJournal(
  journal: AuditJournalProvider,
  input: { maxAppendConflicts?: number } = {},
): AuditRecorderService {
  return new AuditRecorderService({
    ledgerId: 'kya:tenant:prod:primary',
    ledgerEpochId: 'epoch_1',
    tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'recorder-1',
    journal,
    signer: new TestSigner(),
    hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
    clock: new MutableClock(),
    ...(input.maxAppendConflicts === undefined
      ? {}
      : { maxAppendConflicts: input.maxAppendConflicts }),
  });
}

const context = {
  producerAuthority: 'did:key:zProducer',
  tenantAuthority: 'tenant-1',
  tenantRef,
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

  it('binds producer and tenant claims to authenticated context before any write', async () => {
    let evidenceWrites = 0;
    const evidenceProvider: AuditEvidenceProvider = {
      putIfAbsent: async (input) => { evidenceWrites += 1; return input.ref; },
      has: async () => false,
      get: async () => null,
      applyRetention: async (command) => ({ ref: command.ref, state: 'missing' }),
    };
    const { recorder, journal } = service({ evidence: evidenceProvider });
    const ref = {
      objectId: 'auth-bound-evidence', ciphertextDigest: `sha256:${'a'.repeat(64)}` as const,
      mediaType: 'application/octet-stream', size: '1',
      encryption: {
        suite: 'A256GCM' as const, keyId: 'key', nonce: 'nonce',
        aadDigest: `sha256:${'b'.repeat(64)}` as const,
      },
    };
    const producerEvent = { ...event('evt_auth_binding', 1), evidence: [ref] };

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent,
      encryptedEvidence: [{ ref, ciphertext: Uint8Array.of(1) }],
    }, { ...context, producerAuthority: 'did:key:zImpostor' }))
      .rejects.toMatchObject({ code: 'AUDIT_UNAUTHORIZED_SUBMISSION' });

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent,
      encryptedEvidence: [{ ref, ciphertext: Uint8Array.of(1) }],
    }, { ...context, tenantRef: { ...tenantRef, keyId: 'other-tenant' } }))
      .rejects.toMatchObject({ code: 'AUDIT_UNAUTHORIZED_SUBMISSION' });

    expect(evidenceWrites).toBe(0);
    await expect(journal.getHead({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
    })).resolves.toBeNull();
  });

  it('requires an exact authenticated PartyRef for opaque producer identities', async () => {
    const opaqueProducer: PartyRef = {
      kind: 'keyed_commitment',
      value: `sha256:${'b'.repeat(64)}`,
      keyId: 'producer-key-1',
    };
    const producerEvent = {
      ...event('evt_opaque_producer', 1),
      source: { producer: opaqueProducer, sourceId: 'mcp-server-1', sourceSequence: '1' },
    };
    const { recorder } = service();

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent, encryptedEvidence: [],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_UNAUTHORIZED_SUBMISSION' });

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent, encryptedEvidence: [],
    }, { ...context, producerAuthority: 'opaque:producer-key-1', producerRef: opaqueProducer }))
      .resolves.toMatchObject({ core: { sequence: '1' } });
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
      epochTransitionGuard: { verifyAndSeal: async () => true },
    }).recorder;
    const retry = await secondService.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_transition_retry', 1),
      encryptedEvidence: [],
    }, context);

    expect(retry).toEqual(original);
    expect(retry.core.ledgerEpochId).toBe('epoch_1');
  });

  it('resolves pinned-previous-epoch redelivery as a duplicate and fences pinned new appends', async () => {
    const journal = new MemoryAuditJournal();
    const firstService = service({ journal, epoch: 'epoch_1' }).recorder;
    const original = await firstService.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      expectedLedgerEpochId: 'epoch_1',
      producerEvent: event('evt_pinned_redelivery', 1),
      encryptedEvidence: [],
    }, context);

    const secondService = service({
      journal,
      epoch: 'epoch_2',
      previousEpochId: 'epoch_1',
      previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
      epochTransitionGuard: { verifyAndSeal: async () => true },
    }).recorder;

    // A redelivered submission still frozen with the retained-epoch pin must
    // resolve to its original entry instead of wedging on EPOCH_MISMATCH.
    const redelivered = await secondService.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      expectedLedgerEpochId: 'epoch_1',
      producerEvent: event('evt_pinned_redelivery', 1),
      encryptedEvidence: [],
    }, context);
    expect(redelivered).toEqual(original);

    // A new (non-duplicate) append pinned to a stale epoch is still fenced.
    await expect(secondService.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      expectedLedgerEpochId: 'epoch_1',
      producerEvent: event('evt_pinned_new_append', 2),
      encryptedEvidence: [],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_EPOCH_MISMATCH' });
  });

  it('requires an authorized, atomic predecessor seal before starting a linked epoch', async () => {
    const calls: unknown[] = [];
    let evidenceWrites = 0;
    const evidenceProvider: AuditEvidenceProvider = {
      putIfAbsent: async (input) => { evidenceWrites += 1; return input.ref; },
      has: async () => false,
      get: async () => null,
      applyRetention: async (command) => ({ ref: command.ref, state: 'missing' }),
    };
    const ref = {
      objectId: 'transition-evidence', ciphertextDigest: `sha256:${'a'.repeat(64)}` as const,
      mediaType: 'application/octet-stream', size: '1',
      encryption: {
        suite: 'A256GCM' as const, keyId: 'key', nonce: 'nonce',
        aadDigest: `sha256:${'b'.repeat(64)}` as const,
      },
    };
    const { recorder, journal } = service({
      epoch: 'epoch_2',
      previousEpochId: 'epoch_1',
      previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
      evidence: evidenceProvider,
      epochTransitionGuard: {
        verifyAndSeal: async (input?: unknown) => { calls.push(input); return false; },
      },
    });

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: { ...event('evt_rejected_transition', 1), evidence: [ref] },
      encryptedEvidence: [{ ref, ciphertext: Uint8Array.of(1) }],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_INVALID_CONFIGURATION' });

    expect(calls).toEqual([{
      ledgerId: 'kya:tenant:prod:primary',
      previousEpochId: 'epoch_1',
      nextEpochId: 'epoch_2',
      previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
    }]);
    await expect(journal.getHead({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_2',
    })).resolves.toBeNull();
    expect(evidenceWrites).toBe(0);
  });

  it('rejects a second recorder identity against an initialized epoch', async () => {
    const { recorder, journal } = service();
    await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_authoritative_recorder', 1),
      encryptedEvidence: [],
    }, context);
    const competing = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal, signer: new OtherSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: new MutableClock(),
    });

    await expect(competing.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_competing_recorder', 2),
      encryptedEvidence: [],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });
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

  it('rejects incomplete epoch linkage, unauthenticated callers, wrong ledgers, and denied producers', async () => {
    expect(() => service({ previousEpochId: 'epoch_0' })).toThrowError(
      expect.objectContaining({ code: 'AUDIT_INVALID_CONFIGURATION' }),
    );
    expect(() => service({
      previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
    })).toThrowError(expect.objectContaining({ code: 'AUDIT_INVALID_CONFIGURATION' }));
    expect(() => service({
      previousEpochId: 'epoch_0',
      previousTerminalCheckpointDigest: `sha256:${'f'.repeat(64)}`,
    })).toThrowError(expect.objectContaining({ code: 'AUDIT_INVALID_CONFIGURATION' }));

    const submission = {
      ledgerId: 'kya:tenant:prod:primary',
      expectedLedgerEpochId: 'epoch_1',
      producerEvent: event('evt_boundary', 1),
      encryptedEvidence: [],
    } as const;
    await expect(service().recorder.submitAuthenticated(submission, {
      producerAuthority: '', tenantAuthority: 'tenant-1', tenantRef,
    })).rejects.toMatchObject({ code: 'AUDIT_UNAUTHORIZED_SUBMISSION' });
    await expect(service().recorder.submitAuthenticated({
      ...submission, ledgerId: 'wrong-ledger',
    }, context)).rejects.toMatchObject({ code: 'AUDIT_LEDGER_MISMATCH' });
    await expect(service().recorder.submitAuthenticated({
      ...submission, expectedLedgerEpochId: 'wrong-epoch',
    }, context)).rejects.toMatchObject({ code: 'AUDIT_EPOCH_MISMATCH' });
    await expect(service({ authorizer: { authorize: () => false } }).recorder
      .submitAuthenticated(submission, context))
      .rejects.toMatchObject({ code: 'AUDIT_UNAUTHORIZED_SUBMISSION' });
  });

  it('requires an evidence provider and preserves provider failures as their causal error', async () => {
    const ref = {
      objectId: 'evidence-1', ciphertextDigest: `sha256:${'a'.repeat(64)}` as const,
      mediaType: 'application/octet-stream', size: '1',
      encryption: {
        suite: 'A256GCM' as const, keyId: 'key', nonce: 'nonce',
        aadDigest: `sha256:${'b'.repeat(64)}` as const,
      },
    };
    const producerEvent = { ...event('evt_evidence_provider', 1), evidence: [ref] };
    const submission = {
      ledgerId: 'kya:tenant:prod:primary', producerEvent,
      encryptedEvidence: [{ ref, ciphertext: Uint8Array.of(1) }],
    } as const;

    await expect(service().recorder.submitAuthenticated(submission, context))
      .rejects.toMatchObject({ code: 'AUDIT_EVIDENCE_FAILURE' });

    const storageFailure = new Error('evidence store unavailable');
    const evidenceProvider: AuditEvidenceProvider = {
      putIfAbsent: async () => { throw storageFailure; },
      has: async () => false,
      get: async () => null,
      applyRetention: async (command) => ({ ref: command.ref, state: 'missing' }),
    };
    try {
      await service({ evidence: evidenceProvider }).recorder
        .submitAuthenticated(submission, context);
      expect.fail('submission should fail');
    } catch (error) {
      expect(error).toMatchObject({ code: 'AUDIT_EVIDENCE_FAILURE', cause: storageFailure });
    }
  });

  it('does not rewrite evidence for an idempotent producer retry', async () => {
    let evidenceWrites = 0;
    const evidenceProvider: AuditEvidenceProvider = {
      putIfAbsent: async (input) => { evidenceWrites += 1; return input.ref; },
      has: async () => true,
      get: async () => null,
      applyRetention: async (command) => ({ ref: command.ref, state: 'retained' }),
    };
    const ref = {
      objectId: 'retry-evidence', ciphertextDigest: `sha256:${'a'.repeat(64)}` as const,
      mediaType: 'application/octet-stream', size: '1',
      encryption: {
        suite: 'A256GCM' as const, keyId: 'key', nonce: 'nonce',
        aadDigest: `sha256:${'b'.repeat(64)}` as const,
      },
    };
    const producerEvent = { ...event('evt_evidence_retry', 1), evidence: [ref] };
    const { recorder } = service({ evidence: evidenceProvider });
    const submission = {
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent,
      encryptedEvidence: [{ ref, ciphertext: Uint8Array.of(1) }],
    } as const;

    const first = await recorder.submitAuthenticated(submission, context);
    const retry = await recorder.submitAuthenticated(submission, context);

    expect(retry).toEqual(first);
    expect(evidenceWrites).toBe(1);
  });

  it('fails closed when a journal reports a head without a readable genesis', async () => {
    const empty = new MemoryAuditJournal();
    const journal: AuditJournalProvider = {
      ...empty,
      capabilities: empty.capabilities,
      getHead: async () => ({
        ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
        sequence: '0', entryDigest: `sha256:${'a'.repeat(64)}`,
      }),
      getByIdempotencyKey: empty.getByIdempotencyKey.bind(empty),
      compareAndAppend: empty.compareAndAppend.bind(empty),
      readRange: empty.readRange.bind(empty),
    };

    await expect(serviceWithJournal(journal).submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent: event('evt_orphan_head', 1),
      encryptedEvidence: [],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });
  });

  it('wraps journal exceptions and enforces the optimistic-concurrency retry budget', async () => {
    const base = new MemoryAuditJournal();
    const throwing: AuditJournalProvider = {
      capabilities: base.capabilities,
      getHead: base.getHead.bind(base),
      getByIdempotencyKey: base.getByIdempotencyKey.bind(base),
      readRange: base.readRange.bind(base),
      compareAndAppend: async () => { throw new Error('database unavailable'); },
    };
    await expect(serviceWithJournal(throwing).submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent: event('evt_journal_throw', 1),
      encryptedEvidence: [],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });

    const stagnantConflict: AuditJournalProvider = {
      ...throwing,
      compareAndAppend: async () => ({ kind: 'head_conflict', actualHead: null }),
    };
    await expect(serviceWithJournal(stagnantConflict, { maxAppendConflicts: 1 })
      .submitAuthenticated({
        ledgerId: 'kya:tenant:prod:primary', producerEvent: event('evt_stagnant_conflict', 1),
        encryptedEvidence: [],
      }, context)).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });

    const advancingConflict: AuditJournalProvider = {
      ...throwing,
      compareAndAppend: async () => ({
        kind: 'head_conflict',
        actualHead: {
          ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1',
          sequence: '0', entryDigest: `sha256:${'a'.repeat(64)}`,
        },
      }),
    };
    await expect(serviceWithJournal(advancingConflict, { maxAppendConflicts: 0 })
      .submitAuthenticated({
        ledgerId: 'kya:tenant:prod:primary', producerEvent: event('evt_conflict_budget', 1),
        encryptedEvidence: [],
      }, context)).rejects.toMatchObject({ code: 'AUDIT_APPEND_CONFLICT_EXHAUSTED' });
  });
});
