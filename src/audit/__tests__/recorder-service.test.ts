import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { MemoryAuditEvidenceProvider } from '../evidence.js';
import {
  AUDIT_EVENT_SCHEMA_ID,
  type AuditProducerEventCoreV1,
  type AuditSigner,
  type PartyRef,
} from '../index.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import { AuditProtocolError } from '../errors.js';
import {
  LocalAuditRecorderClient,
  createLocalAuditRecorder,
} from '../providers/recorder-client.js';
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

  it('composes an in-process authoritative recorder through the one-call helper', async () => {
    const client = createLocalAuditRecorder({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal: new MemoryAuditJournal(), signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: new MutableClock(),
    }, () => context);
    const entry = await client.submit({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_helper_composed', 1),
      encryptedEvidence: [],
    });
    expect(entry.core.sequence).toBe('1');
    expect(entry.core.event.eventId).toBe('evt_helper_composed');
  });

  it('treats a raced replica genesis as configuration-validated, not identity reuse', async () => {
    const journal = new MemoryAuditJournal();
    const primary = service({ journal }).recorder;
    await primary.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_primary_before_race', 1),
      encryptedEvidence: [],
    }, context);

    // The replica observes an empty ledger once, then races the committed
    // genesis whose recorder-authored occurredAt differs from its own.
    let hidHead = false;
    const racingJournal: AuditJournalProvider = {
      capabilities: journal.capabilities,
      getHead: async (ledger) => {
        if (!hidHead) {
          hidHead = true;
          return null;
        }
        return journal.getHead(ledger);
      },
      readRange: (input) => journal.readRange(input),
      compareAndAppend: (input) => journal.compareAndAppend(input),
      getByIdempotencyKey: (ledgerId, key) => journal.getByIdempotencyKey(ledgerId, key),
    };
    const replica = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal: racingJournal, signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: new MutableClock(1_750_999_999_999),
    });

    const appended = await replica.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_replica_after_race', 2),
      encryptedEvidence: [],
    }, context);
    expect(appended.core.sequence).toBe('2');
  });

  it('disposes write-ahead evidence when the append permanently fails uncommitted', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const evidence = new MemoryAuditEvidenceProvider(hasher);
    const journal = new MemoryAuditJournal();
    let appends = 0;
    const failingJournal: AuditJournalProvider = {
      capabilities: journal.capabilities,
      getHead: (ledger) => journal.getHead(ledger),
      readRange: (input) => journal.readRange(input),
      getByIdempotencyKey: (ledgerId, key) => journal.getByIdempotencyKey(ledgerId, key),
      compareAndAppend: async (input) => {
        appends += 1;
        if (appends > 1) throw new Error('journal offline');
        return journal.compareAndAppend(input);
      },
    };
    const recorder = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal: failingJournal, signer: new TestSigner(), hasher,
      clock: new MutableClock(), evidence,
    });
    const ciphertext = Uint8Array.of(1, 2, 3);
    const ref = {
      objectId: 'evi_orphan_test',
      ciphertextDigest: await hasher.sha256(ciphertext),
      mediaType: 'application/octet-stream',
      size: '3',
      encryption: {
        suite: 'A256GCM' as const,
        keyId: 'tenant-key-v1',
        nonce: 'AAAAAAAAAAAAAAAA',
        aadDigest: await hasher.sha256(new Uint8Array()),
      },
    };

    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: { ...event('evt_orphaned_evidence', 1), evidence: [ref] },
      encryptedEvidence: [{ ref, ciphertext }],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });
    await expect(evidence.has(ref)).resolves.toBe(false);
  });

  it('keeps write-ahead evidence that a committed entry references when a later append fails', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const evidence = new MemoryAuditEvidenceProvider(hasher);
    const journal = new MemoryAuditJournal();
    let appends = 0;
    const flakyJournal: AuditJournalProvider = {
      capabilities: journal.capabilities,
      getHead: (ledger) => journal.getHead(ledger),
      readRange: (input) => journal.readRange(input),
      getByIdempotencyKey: (ledgerId, key) => journal.getByIdempotencyKey(ledgerId, key),
      compareAndAppend: async (input) => {
        appends += 1;
        // Genesis and the first event commit; the second event hits an outage.
        if (appends === 3) throw new Error('transient journal outage');
        return journal.compareAndAppend(input);
      },
    };
    const recorder = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal: flakyJournal, signer: new TestSigner(), hasher,
      clock: new MutableClock(), evidence,
    });
    const ciphertext = Uint8Array.of(9, 8, 7, 6);
    const ref = {
      objectId: 'evi_shared_session_identity',
      ciphertextDigest: await hasher.sha256(ciphertext),
      mediaType: 'application/octet-stream',
      size: '4',
      encryption: {
        suite: 'A256GCM' as const,
        keyId: 'tenant-key-v1',
        nonce: 'AAAAAAAAAAAAAAAA',
        aadDigest: await hasher.sha256(Uint8Array.of(1)),
      },
    };
    // One encrypted actor object is attached to every event of a session.
    const actor: PartyRef = { kind: 'evidence_ref', ref };

    await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: { ...event('evt_shared_first', 1), actor },
      encryptedEvidence: [{ ref, ciphertext }],
    }, context);
    await expect(recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: { ...event('evt_shared_second', 2), actor },
      encryptedEvidence: [{ ref, ciphertext }],
    }, context)).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });

    await expect(evidence.has(ref)).resolves.toBe(true);
  });

  it('keeps an evidence object a concurrent submission committed while this one failed', async () => {
    const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
    const inner = new MemoryAuditEvidenceProvider(hasher);
    // Barrier: neither submission stores the object until both have checked it,
    // so each sees it as new.
    let checks = 0;
    let bothChecked!: () => void;
    const checked = new Promise<void>((resolve) => { bothChecked = resolve; });
    const evidence: AuditEvidenceProvider = {
      putIfAbsent: (input) => inner.putIfAbsent(input),
      get: (ref, access) => inner.get(ref, access),
      applyRetention: (command) => inner.applyRetention(command),
      has: async (ref) => {
        const present = await inner.has(ref);
        if ((checks += 1) === 2) bothChecked();
        await checked;
        return present;
      },
    };
    // The loser's append fails only after the winner committed and returned.
    let winnerReturned!: () => void;
    const returned = new Promise<void>((resolve) => { winnerReturned = resolve; });
    const journal = new MemoryAuditJournal();
    const racing: AuditJournalProvider = {
      capabilities: journal.capabilities,
      getHead: (ledger) => journal.getHead(ledger),
      readRange: (input) => journal.readRange(input),
      getByIdempotencyKey: (ledgerId, key) => journal.getByIdempotencyKey(ledgerId, key),
      compareAndAppend: async (input) => {
        if (input.entry.core.event.eventId !== 'evt_race_loser') {
          return journal.compareAndAppend(input);
        }
        await returned;
        throw new Error('transient journal outage');
      },
    };
    const recorder = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal: racing, signer: new TestSigner(), hasher, clock: new MutableClock(), evidence,
    });
    await recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary', producerEvent: event('evt_race_warmup', 1),
      encryptedEvidence: [],
    }, context);
    const ciphertext = Uint8Array.of(5, 4, 3, 2);
    const ref = {
      objectId: 'evi_concurrent_session_identity',
      ciphertextDigest: await hasher.sha256(ciphertext),
      mediaType: 'application/octet-stream',
      size: '4',
      encryption: {
        suite: 'A256GCM' as const, keyId: 'tenant-key-v1', nonce: 'AAAAAAAAAAAAAAAA',
        aadDigest: await hasher.sha256(Uint8Array.of(1)),
      },
    };
    const actor: PartyRef = { kind: 'evidence_ref', ref };
    const submit = (eventId: string, sequence: number) => recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: { ...event(eventId, sequence), actor },
      encryptedEvidence: [{ ref, ciphertext }],
    }, context);

    const winner = submit('evt_race_winner', 2).finally(winnerReturned);
    const loser = submit('evt_race_loser', 3);
    await expect(winner).resolves.toMatchObject({ core: { sequence: '2' } });
    await expect(loser).rejects.toMatchObject({ code: 'AUDIT_JOURNAL_FAILURE' });
    await expect(inner.has(ref)).resolves.toBe(true);
  });

  it('fails closed instead of re-signing a receipted sequence when the journal head regresses', async () => {
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    let backing = new MemoryAuditJournal();
    // A failover to a lagging replica, or a restore, without an epoch change.
    const restoredTo = async (source: MemoryAuditJournal, size: number) => {
      const copy = new MemoryAuditJournal();
      for (const entry of (await source.snapshot(ledger)).slice(0, size)) {
        await copy.compareAndAppend({
          ledger, expectedHead: await copy.getHead(ledger), entry,
          idempotencyKey: `sha256:${entry.entryDigest.slice('sha256:'.length)}`,
        });
      }
      return copy;
    };
    const journal: AuditJournalProvider = {
      capabilities: { durability: 'durable', atomicAppend: true, orderedRead: true },
      getHead: (input) => backing.getHead(input),
      getByIdempotencyKey: (ledgerId, key) => backing.getByIdempotencyKey(ledgerId, key),
      readRange: (query) => backing.readRange(query),
      compareAndAppend: (input) => backing.compareAndAppend(input),
    };
    const recorder = serviceWithJournal(journal);
    const submit = (id: string, sequence: number) => recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event(id, sequence),
      encryptedEvidence: [],
    }, context);
    await submit('evt_before_restore_1', 1);
    expect((await submit('evt_before_restore_2', 2)).core.sequence).toBe('2');

    // The restored journal reads one append behind this recorder's commits.
    // The append targets the committed head, so the journal's own conflict
    // answer proves the regression and nothing is signed at sequence 2 again.
    backing = await restoredTo(backing, 2);
    await expect(submit('evt_after_restore', 3)).rejects.toMatchObject({
      code: 'AUDIT_JOURNAL_FAILURE',
    });
    expect(await backing.snapshot(ledger)).toHaveLength(2);

    // A different digest at a sequence the journal already reported is a fork.
    const fresh = new MemoryAuditJournal();
    let forkAnswer = false;
    const forking: AuditJournalProvider = {
      capabilities: fresh.capabilities,
      getHead: (input) => fresh.getHead(input),
      getByIdempotencyKey: (ledgerId, key) => fresh.getByIdempotencyKey(ledgerId, key),
      readRange: (query) => fresh.readRange(query),
      compareAndAppend: async (input) => {
        const head = await fresh.getHead(input.ledger);
        return forkAnswer && head !== null
          ? { kind: 'head_conflict', actualHead: { ...head, entryDigest: `sha256:${'f'.repeat(64)}` } }
          : fresh.compareAndAppend(input);
      },
    };
    const forkObserver = serviceWithJournal(forking);
    const submitForked = (id: string, sequence: number) => forkObserver.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event(id, sequence),
      encryptedEvidence: [],
    }, context);
    await submitForked('evt_before_fork', 1);
    forkAnswer = true;
    await expect(submitForked('evt_after_fork', 2)).rejects.toMatchObject({
      code: 'AUDIT_JOURNAL_FAILURE',
    });
  });

  it('retries past a stale head read instead of failing, as compare-and-append intends', async () => {
    const ledger = { ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1' };
    const backing = new MemoryAuditJournal();
    // A read replica one append behind, and one that misreports the head digest.
    let misreport = false;
    const lagging: AuditJournalProvider = {
      capabilities: backing.capabilities,
      getHead: async () => {
        const entries = await backing.snapshot(ledger);
        const behind = entries.at(-2);
        if (misreport && entries.length > 0) {
          return { ...ledger, sequence: entries.at(-1)!.core.sequence, entryDigest: `sha256:${'e'.repeat(64)}` };
        }
        return behind === undefined
          ? null
          : { ...ledger, sequence: behind.core.sequence, entryDigest: behind.entryDigest };
      },
      getByIdempotencyKey: (ledgerId, key) => backing.getByIdempotencyKey(ledgerId, key),
      readRange: (query) => backing.readRange(query),
      compareAndAppend: (input) => backing.compareAndAppend(input),
    };
    const recorder = serviceWithJournal(lagging);
    const submit = (id: string, sequence: number) => recorder.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event(id, sequence),
      encryptedEvidence: [],
    }, context);

    for (let sequence = 1; sequence <= 3; sequence += 1) {
      expect((await submit(`evt_lagging_${sequence}`, sequence)).core.sequence)
        .toBe(String(sequence));
    }
    misreport = true;
    expect((await submit('evt_misreported', 4)).core.sequence).toBe('4');
    const entries = await backing.snapshot(ledger);
    for (let index = 1; index < entries.length; index += 1) {
      expect(entries[index]!.core.previousEntryDigest).toBe(entries[index - 1]!.entryDigest);
    }
  });

  it('accepts a lost cold-start genesis race even when every replica read was stale', async () => {
    const journal = new MemoryAuditJournal();
    const primary = service({ journal }).recorder;
    await primary.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_primary_cold_start', 1),
      encryptedEvidence: [],
    }, context);

    // The replica finished all reads before the primary genesis was visible to
    // it, so the race surfaces only as an idempotency conflict at append time.
    let staleReads = true;
    const replicaJournal: AuditJournalProvider = {
      capabilities: journal.capabilities,
      getHead: async (ledger) => (staleReads ? null : journal.getHead(ledger)),
      getByIdempotencyKey: async (ledgerId, key) =>
        (staleReads ? null : journal.getByIdempotencyKey(ledgerId, key)),
      readRange: (input) => journal.readRange(input),
      compareAndAppend: async (input) => {
        staleReads = false;
        return journal.compareAndAppend(input);
      },
    };
    const replica = new AuditRecorderService({
      ledgerId: 'kya:tenant:prod:primary', ledgerEpochId: 'epoch_1', tenantRef,
      binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'recorder-1',
      journal: replicaJournal, signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: new MutableClock(1_750_000_000_123),
    });

    const appended = await replica.submitAuthenticated({
      ledgerId: 'kya:tenant:prod:primary',
      producerEvent: event('evt_replica_cold_start', 2),
      encryptedEvidence: [],
    }, context);
    expect(appended.core.sequence).toBe('2');
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
