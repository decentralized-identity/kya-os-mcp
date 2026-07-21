import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher, type AuditSigner } from '../crypto.js';
import {
  AuditCheckpointBuilder,
  MemoryAuditCheckpointStore,
} from '../checkpoint.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import type {
  AuditLedgerRef,
  Digest,
  SignedAuditEntryV1,
} from '../types.js';

const hash = (character: string) => `sha256:${character.repeat(64)}` as Digest;
const ledger: AuditLedgerRef = {
  ledgerId: 'kya:tenant:prod:primary',
  ledgerEpochId: 'epoch_1',
};

class TestSigner implements AuditSigner {
  readonly ref = {
    did: 'did:key:zRecorder',
    kid: 'did:key:zRecorder#zRecorder',
    alg: 'EdDSA' as const,
  };
  async sign(payload: Uint8Array): Promise<string> {
    return `checkpoint.${Buffer.from(payload).toString('base64url')}.signature`;
  }
}

function entry(sequence: number): SignedAuditEntryV1 {
  const entryDigest = hash(String((sequence % 9) + 1));
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
      ...ledger,
      sequence: String(sequence),
      previousEntryDigest: sequence === 0 ? null : hash(String((sequence % 9) || 9)),
      recordedAt: 1_750_000_000_000 + sequence,
      recorder: new TestSigner().ref,
      eventDigest: hash('a'),
      event: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
        eventId: `evt_${sequence}`,
        eventType: sequence === 0 ? 'ledger.epoch.started' : 'tool.call.completed',
        eventVersion: '1.0.0',
        binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
        occurredAt: 1_750_000_000_000 + sequence,
        tenantRef: { kind: 'pairwise_did', did: 'did:key:zTenant' },
        source: {
          producer: { kind: 'pairwise_did', did: 'did:key:zProducer' },
          sourceId: 'source-1',
          sourceSequence: String(sequence),
        },
        action: { category: sequence === 0 ? 'ledger.epoch' : 'tool.call' },
        outcome: 'succeeded',
        evidence: [],
        details: sequence === 0
          ? { family: 'ledger', phase: 'epoch_started' }
          : { family: 'tool', phase: 'completed', attempt: '1' },
        privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
      },
      evidenceManifestDigest: hash('b'),
      integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
    },
    eventDigest: hash('a'),
    entryDigest,
    recorderReceipt: {
      core: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0',
        ...ledger,
        sequence: String(sequence),
        eventId: `evt_${sequence}`,
        entryDigest,
        previousEntryDigest: sequence === 0 ? null : hash(String((sequence % 9) || 9)),
        recordedAt: 1_750_000_000_000 + sequence,
        recorder: new TestSigner().ref,
        integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
      },
      jws: 'entry.signature',
    },
  };
}

async function append(journal: MemoryAuditJournal, value: SignedAuditEntryV1) {
  const expectedHead = await journal.getHead(ledger);
  await journal.compareAndAppend({
    ledger,
    expectedHead,
    entry: value,
    idempotencyKey: hash(String((Number(value.core.sequence) % 9) + 1)),
  });
}

describe('AuditCheckpointBuilder', () => {
  it('signs growing checkpoints and links them without mutating older checkpoints', async () => {
    const journal = new MemoryAuditJournal();
    await append(journal, entry(0));
    await append(journal, entry(1));
    const store = new MemoryAuditCheckpointStore();
    let now = 1_750_000_001_000;
    const builder = new AuditCheckpointBuilder({
      journal,
      store,
      signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => now++ },
    });

    const first = await builder.createCheckpoint(ledger);
    await append(journal, entry(2));
    const second = await builder.createCheckpoint(ledger);

    expect(first.core.treeSize).toBe('2');
    expect(first.core.previousCheckpointDigest).toBeNull();
    expect(second.core.treeSize).toBe('3');
    expect(second.core.previousCheckpointDigest).toBe(first.checkpointDigest);
    expect(first).toEqual(await store.getByTreeSize(ledger, '2'));
    expect(second.jws).toMatch(/^checkpoint\./);
  });

  it('returns inclusion and consistency proofs that verify against checkpoints', async () => {
    const journal = new MemoryAuditJournal();
    for (let sequence = 0; sequence < 6; sequence += 1) await append(journal, entry(sequence));
    const builder = new AuditCheckpointBuilder({
      journal,
      store: new MemoryAuditCheckpointStore(),
      signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_001_000 },
    });
    const checkpoint = await builder.createCheckpoint(ledger);
    const inclusion = await builder.inclusionProof(ledger, '3', checkpoint);
    const consistency = await builder.consistencyProof(ledger, '3', checkpoint);

    await expect(builder.verifyInclusion(entry(3).entryDigest, checkpoint, inclusion))
      .resolves.toBe(true);
    const oldRoot = await builder.rootForRange(ledger, '3');
    await expect(builder.verifyConsistency({
      oldTreeSize: '3',
      oldRoot,
      checkpoint,
      proof: consistency,
    })).resolves.toBe(true);
  });

  it('emits checkpoint lifecycle callbacks only after the described snapshot is signed', async () => {
    const journal = new MemoryAuditJournal();
    await append(journal, entry(0));
    let callbackTreeSize: string | undefined;
    const builder = new AuditCheckpointBuilder({
      journal,
      store: new MemoryAuditCheckpointStore(),
      signer: new TestSigner(),
      hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
      clock: { now: () => 1_750_000_001_000 },
      onCheckpointCreated: async (checkpoint) => {
        callbackTreeSize = checkpoint.core.treeSize;
        await append(journal, entry(1));
      },
    });

    const checkpoint = await builder.createCheckpoint(ledger);
    expect(checkpoint.core.treeSize).toBe('1');
    expect(callbackTreeSize).toBe('1');
    expect((await builder.createCheckpoint(ledger)).core.treeSize).toBe('2');
  });
});
