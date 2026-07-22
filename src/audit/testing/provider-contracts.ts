import type { AuditHasher } from '../crypto.js';
import type { AuditAnchorProvider } from '../providers/anchor.js';
import type {
  AuditEvidenceProvider,
  EncryptedEvidenceInput,
} from '../providers/evidence.js';
import type { AuditJournalProvider } from '../providers/journal.js';
import type { AuditCheckpointObserverProvider } from '../providers/observer.js';
import type { AuditOutboxItem, AuditOutboxProvider } from '../providers/outbox.js';
import type {
  AuditLedgerRef,
  Digest,
  EvidenceRef,
  SignedAuditCheckpointV1,
  SignedAuditEntryV1,
} from '../types.js';

export interface AuditProviderContractCheck {
  name: string;
  passed: boolean;
  error?: unknown;
}

export interface AuditProviderContractReport {
  providerKind: 'journal' | 'evidence' | 'observer' | 'anchor' | 'outbox';
  passed: boolean;
  checks: AuditProviderContractCheck[];
}

function digest(character: string): Digest {
  return `sha256:${character.repeat(64)}`;
}

function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function expectContract(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function check(
  checks: AuditProviderContractCheck[],
  name: string,
  execute: () => Promise<void>,
): Promise<void> {
  try {
    await execute();
    checks.push({ name, passed: true });
  } catch (error) {
    checks.push({ name, passed: false, error });
  }
}

function report(
  providerKind: AuditProviderContractReport['providerKind'],
  checks: AuditProviderContractCheck[],
): AuditProviderContractReport {
  return { providerKind, passed: checks.every((item) => item.passed), checks };
}

export function assertAuditProviderContract(value: AuditProviderContractReport): void {
  const failures = value.checks.filter((item) => !item.passed);
  if (failures.length > 0) {
    throw new AggregateError(
      failures.map((item) => item.error),
      `${value.providerKind} provider contract failed: ${failures.map((item) => item.name).join(', ')}`,
    );
  }
}

function contractEntry(
  ledger: AuditLedgerRef,
  sequence: number,
  eventDigest: Digest,
  previousEntryDigest: Digest | null,
): SignedAuditEntryV1 {
  const entryDigest = digest(((sequence + 3) % 10).toString());
  const eventId = `contract-event-${sequence}`;
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
      ...ledger,
      sequence: String(sequence),
      previousEntryDigest,
      recordedAt: 1_750_000_000_000 + sequence,
      recorder: {
        did: 'did:key:zContractRecorder',
        kid: 'did:key:zContractRecorder#key',
        alg: 'EdDSA',
      },
      eventDigest,
      event: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
        eventId,
        eventType: sequence === 0 ? 'ledger.epoch.started' : 'tool.call.completed',
        eventVersion: '1.0.0',
        binding: 'urn:kya-os:audit-binding:contract:1',
        occurredAt: 1_750_000_000_000 + sequence,
        tenantRef: { kind: 'pairwise_did', did: 'did:key:zContractTenant' },
        source: {
          producer: { kind: 'pairwise_did', did: 'did:key:zContractProducer' },
          sourceId: 'contract-source',
          sourceSequence: String(sequence),
        },
        action: { category: sequence === 0 ? 'ledger.epoch' : 'tool.call' },
        outcome: 'succeeded',
        evidence: [],
        details: sequence === 0
          ? { family: 'ledger', phase: 'epoch_started' }
          : { family: 'tool', phase: 'completed', attempt: '1' },
        privacy: { classification: 'internal', retentionClass: 'contract' },
      },
      evidenceManifestDigest: digest('a'),
      integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
    },
    eventDigest,
    entryDigest,
    recorderReceipt: {
      core: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0',
        ...ledger,
        sequence: String(sequence),
        eventId,
        entryDigest,
        previousEntryDigest,
        recordedAt: 1_750_000_000_000 + sequence,
        recorder: {
          did: 'did:key:zContractRecorder',
          kid: 'did:key:zContractRecorder#key',
          alg: 'EdDSA',
        },
        integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
      },
      jws: `contract-signature-${sequence}`,
    },
  };
}

/** Framework-neutral executable contract for authoritative journal adapters. */
export async function evaluateAuditJournalProviderContract(
  createProvider: () => AuditJournalProvider | Promise<AuditJournalProvider>,
): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  const ledger = { ledgerId: 'contract-ledger', ledgerEpochId: 'epoch-1' };
  const first = contractEntry(ledger, 0, digest('1'), null);
  const second = contractEntry(ledger, 1, digest('2'), first.entryDigest);
  const third = contractEntry(ledger, 2, digest('3'), second.entryDigest);
  const idOne = digest('b');
  const idTwo = digest('c');
  const idThree = digest('d');

  await check(checks, 'declares atomic ordered capabilities', async () => {
    const provider = await createProvider();
    expectContract(provider.capabilities.atomicAppend === true, 'atomicAppend must be true');
    expectContract(provider.capabilities.orderedRead === true, 'orderedRead must be true');
    expectContract(
      provider.capabilities.durability === 'ephemeral' ||
        provider.capabilities.durability === 'durable',
      'durability must be declared',
    );
  });

  await check(checks, 'atomically appends and rejects a stale head', async () => {
    const provider = await createProvider();
    const appended = await provider.compareAndAppend({
      ledger, expectedHead: null, entry: first, idempotencyKey: idOne,
    });
    expectContract(appended.kind === 'appended', 'genesis append was not committed');
    const stale = await provider.compareAndAppend({
      ledger, expectedHead: null, entry: second, idempotencyKey: idTwo,
    });
    expectContract(stale.kind === 'head_conflict', 'stale head did not conflict');
    const head = await provider.getHead(ledger);
    expectContract(head?.entryDigest === first.entryDigest, 'stale append changed the head');
  });

  await check(checks, 'returns exact duplicates and rejects idempotency conflicts', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const duplicate = await provider.compareAndAppend({
      ledger, expectedHead: null, entry: first, idempotencyKey: idOne,
    });
    expectContract(
      duplicate.kind === 'duplicate' && equalJson(duplicate.entry, first),
      'same key and producer digest must return the original entry',
    );
    const conflicting = { ...first, eventDigest: digest('f') };
    const conflict = await provider.compareAndAppend({
      ledger, expectedHead: null, entry: conflicting, idempotencyKey: idOne,
    });
    expectContract(conflict.kind === 'idempotency_conflict', 'changed content was not rejected');
  });

  await check(checks, 'keeps logical-ledger idempotency across epoch changes', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const nextEpoch = { ledgerId: ledger.ledgerId, ledgerEpochId: 'epoch-2' };
    const replay = contractEntry(nextEpoch, 0, first.eventDigest, null);
    const duplicate = await provider.compareAndAppend({
      ledger: nextEpoch, expectedHead: null, entry: replay, idempotencyKey: idOne,
    });
    expectContract(duplicate.kind === 'duplicate', 'epoch transition reopened idempotency scope');
  });

  await check(checks, 'provides ordered stable range cursors', async () => {
    const provider = await createProvider();
    const firstResult = await provider.compareAndAppend({
      ledger, expectedHead: null, entry: first, idempotencyKey: idOne,
    });
    expectContract(firstResult.kind === 'appended', 'first append failed');
    const head = await provider.getHead(ledger);
    const secondResult = await provider.compareAndAppend({
      ledger, expectedHead: head, entry: second, idempotencyKey: idTwo,
    });
    expectContract(secondResult.kind === 'appended', 'second append failed');
    const iterator = provider.readRange(ledger)[Symbol.asyncIterator]();
    const firstRead = await iterator.next();
    const nextHead = await provider.getHead(ledger);
    await provider.compareAndAppend({
      ledger, expectedHead: nextHead, entry: third, idempotencyKey: idThree,
    });
    const remaining: SignedAuditEntryV1[] = [];
    for (;;) {
      const item = await iterator.next();
      if (item.done) break;
      remaining.push(item.value);
    }
    expectContract(firstRead.value?.core.sequence === '0', 'range did not start at sequence zero');
    expectContract(
      remaining.length === 1 && remaining[0]?.core.sequence === '1',
      'range cursor was not ordered and snapshot-stable',
    );
  });

  return report('journal', checks);
}

function contractEvidenceRef(
  ciphertextDigest: Digest,
  size: number,
  objectId = 'evi_contract',
): EvidenceRef {
  return {
    objectId,
    ciphertextDigest,
    mediaType: 'application/octet-stream',
    size: String(size),
    encryption: {
      suite: 'A256GCM', keyId: 'contract-key-v1', nonce: 'AAAAAAAAAAAAAAAA',
      aadDigest: digest('e'),
    },
  };
}

/** Executable contract for encrypted evidence/retention adapters. */
export async function evaluateAuditEvidenceProviderContract(input: {
  createProvider(): AuditEvidenceProvider | Promise<AuditEvidenceProvider>;
  hasher: AuditHasher;
}): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  const ciphertext = Uint8Array.of(1, 2, 3, 4);
  const ciphertextDigest = await input.hasher.sha256(ciphertext);
  const evidence: EncryptedEvidenceInput = {
    ref: contractEvidenceRef(ciphertextDigest, ciphertext.byteLength),
    ciphertext,
  };

  await check(checks, 'stores exact ciphertext idempotently and returns defensive bytes', async () => {
    const provider = await input.createProvider();
    await provider.putIfAbsent(evidence);
    await provider.putIfAbsent(evidence);
    const first = await provider.get(evidence.ref, { actor: 'contract', purpose: 'verification' });
    expectContract(first !== null && first[0] === 1, 'stored ciphertext was unavailable');
    first[0] = 255;
    const second = await provider.get(evidence.ref, { actor: 'contract', purpose: 'verification' });
    expectContract(second?.[0] === 1, 'provider leaked mutable ciphertext storage');
  });

  await check(checks, 'rejects opaque object identifier collisions', async () => {
    const provider = await input.createProvider();
    await provider.putIfAbsent(evidence);
    const otherBytes = Uint8Array.of(5, 6, 7);
    const collision: EncryptedEvidenceInput = {
      ref: contractEvidenceRef(
        await input.hasher.sha256(otherBytes),
        otherBytes.byteLength,
        evidence.ref.objectId,
      ),
      ciphertext: otherBytes,
    };
    let rejected = false;
    try {
      await provider.putIfAbsent(collision);
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'object ID collision was accepted');
  });

  await check(checks, 'enforces legal hold before irreversible disposal', async () => {
    const provider = await input.createProvider();
    await provider.putIfAbsent(evidence);
    await provider.applyRetention({
      kind: 'legal_hold', ref: evidence.ref, holdId: 'hold-1', authorizedBy: 'contract',
    });
    let rejected = false;
    try {
      await provider.applyRetention({
        kind: 'dispose', ref: evidence.ref, authorizedBy: 'contract', reason: 'expired',
      });
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'held evidence was disposed');
    await provider.applyRetention({
      kind: 'release_hold', ref: evidence.ref, holdId: 'hold-1', authorizedBy: 'contract',
    });
    const disposed = await provider.applyRetention({
      kind: 'dispose', ref: evidence.ref, authorizedBy: 'contract', reason: 'expired',
    });
    expectContract(disposed.state === 'disposed', 'released evidence was not disposed');
    expectContract(!(await provider.has(evidence.ref)), 'disposed ciphertext remains available');
  });

  return report('evidence', checks);
}

export interface AuditCheckpointProviderContractFixtures {
  first: SignedAuditCheckpointV1;
  next: SignedAuditCheckpointV1;
  conflict: SignedAuditCheckpointV1;
  rollback: SignedAuditCheckpointV1;
}

/** Executable monotonicity/split-view contract for independent observers. */
export async function evaluateAuditObserverProviderContract(input: {
  createProvider(): AuditCheckpointObserverProvider | Promise<AuditCheckpointObserverProvider>;
  fixtures: AuditCheckpointProviderContractFixtures;
}): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  await check(checks, 'retains monotonic linked observations and exact duplicates', async () => {
    const provider = await input.createProvider();
    expectContract(provider.capability === 'independent-observer', 'observer capability is false');
    const first = await provider.publish(input.fixtures.first);
    const duplicate = await provider.publish(input.fixtures.first);
    expectContract(equalJson(first, duplicate), 'duplicate checkpoint changed observation receipt');
    const next = await provider.publish(input.fixtures.next);
    expectContract(
      next.core.previousObservationDigest === first.observationDigest,
      'observation receipt chain was not linked',
    );
    const latest = await provider.latest(input.fixtures.next.core);
    expectContract(
      latest?.checkpoint.checkpointDigest === input.fixtures.next.checkpointDigest,
      'latest observed checkpoint is incorrect',
    );
  });
  await check(checks, 'rejects rollback and same-size conflicting views', async () => {
    const provider = await input.createProvider();
    await provider.publish(input.fixtures.first);
    for (const candidate of [input.fixtures.conflict, input.fixtures.rollback]) {
      let rejected = false;
      try {
        await provider.publish(candidate);
      } catch {
        rejected = true;
      }
      expectContract(rejected, 'observer accepted rollback or split view');
    }
  });
  return report('observer', checks);
}

/** Executable role-separation and binding contract for supporting anchors. */
export async function evaluateAuditAnchorProviderContract(input: {
  createProvider(): AuditAnchorProvider | Promise<AuditAnchorProvider>;
  checkpoint: SignedAuditCheckpointV1;
  otherCheckpoint: SignedAuditCheckpointV1;
}): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  await check(checks, 'publishes and verifies only a checkpoint-bound supporting receipt', async () => {
    const provider = await input.createProvider();
    expectContract(provider.capability === 'supporting-anchor', 'anchor claimed observer capability');
    const receipt = await provider.publish(input.checkpoint);
    expectContract(receipt.kind === provider.kind, 'anchor kind mismatch');
    expectContract(receipt.checkpointDigest === input.checkpoint.checkpointDigest, 'receipt is unbound');
    expectContract(await provider.verify(input.checkpoint, receipt), 'valid receipt did not verify');
    expectContract(
      !(await provider.verify(input.otherCheckpoint, receipt)),
      'receipt verified for a different checkpoint',
    );
  });
  return report('anchor', checks);
}

/** Executable FIFO, retry-accounting, and acknowledgement contract for outboxes. */
export async function evaluateAuditOutboxProviderContract(
  createProvider: () => AuditOutboxProvider | Promise<AuditOutboxProvider>,
): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  const ledger = { ledgerId: 'contract-ledger', ledgerEpochId: 'epoch-1' };
  const firstEntry = contractEntry(ledger, 1, digest('1'), digest('0'));
  const secondEntry = contractEntry(ledger, 2, digest('2'), firstEntry.entryDigest);
  const item = (entry: SignedAuditEntryV1): AuditOutboxItem => ({
    eventId: entry.core.event.eventId,
    submission: {
      ledgerId: ledger.ledgerId,
      expectedLedgerEpochId: ledger.ledgerEpochId,
      producerEvent: entry.core.event,
      encryptedEvidence: [],
    },
    enqueuedAt: entry.core.recordedAt,
    attempts: 0,
  });
  const collect = async (provider: AuditOutboxProvider): Promise<AuditOutboxItem[]> => {
    const values: AuditOutboxItem[] = [];
    for await (const value of provider.pending()) values.push(value);
    return values;
  };

  await check(checks, 'declares and preserves FIFO order per source', async () => {
    const provider = await createProvider();
    expectContract(provider.capabilities.fifoPerSource === true, 'fifoPerSource must be true');
    await provider.enqueue(item(firstEntry));
    await provider.enqueue(item(secondEntry));
    expectContract(
      equalJson((await collect(provider)).map((value) => value.eventId), [
        firstEntry.core.event.eventId,
        secondEntry.core.event.eventId,
      ]),
      'pending items were not yielded in enqueue order',
    );
  });
  await check(checks, 'accounts for failures and removes only acknowledged items', async () => {
    const provider = await createProvider();
    await provider.enqueue(item(firstEntry));
    await provider.enqueue(item(secondEntry));
    await provider.markFailed(firstEntry.core.event.eventId, new Error('offline'));
    let pending = await collect(provider);
    expectContract(pending[0]?.attempts === 1, 'failed delivery attempt was not persisted');
    await provider.markDelivered(firstEntry.core.event.eventId);
    pending = await collect(provider);
    expectContract(
      pending.length === 1 && pending[0]?.eventId === secondEntry.core.event.eventId,
      'acknowledgement removed the wrong pending item',
    );
  });

  return report('outbox', checks);
}
