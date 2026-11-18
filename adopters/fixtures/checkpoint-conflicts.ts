/**
 * An adopter runs an on-demand checkpoint endpoint over its audit journal, with two signer
 * processes sharing one checkpoint store. Two events refuse a checkpoint with
 * `AUDIT_CHECKPOINT_CONFLICT`. A lost race, where the other signer stored a checkpoint over the
 * same tree first, is benign: the endpoint answers with the stored checkpoint. A fork, where two
 * signed views of the ledger disagree, is a security event: the endpoint answers with a failure
 * and records a critical finding. The endpoint tells them apart with `isLostCheckpointRace`, and
 * never by the message.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { NodeCryptoProvider } from '@kya-os/mcp';
import {
  AUDIT_CHECKPOINT_CONFLICT_REASONS,
  AUDIT_ERROR_CODES,
  AuditCheckpointBuilder,
  AuditProtocolError,
  AuditRecorderService,
  CompactJwsAuditSigner,
  CryptoProviderAuditHasher,
  MemoryAuditCheckpointStore,
  MemoryAuditJournal,
  isLostCheckpointRace,
  sampleAuditEvent,
  type AuditCheckpointStore,
  type PartyRef,
  type SignedAuditCheckpointV1,
} from '@kya-os/mcp/audit';
import { runCases } from './shared/cases.js';

const ledger = { ledgerId: 'kya:orders:prod:primary', ledgerEpochId: 'epoch_1' };
const tenantRef: PartyRef = { kind: 'pairwise_did', did: 'did:key:zOrdersTenant' };
const producer = 'did:key:zOrdersService';
const hasher = new CryptoProviderAuditHasher(new NodeCryptoProvider());
const pkcs8 = generateKeyPairSync('ed25519').privateKey.export({ format: 'der', type: 'pkcs8' });
const signer = new CompactJwsAuditSigner(
  { did: 'did:key:zOrdersRecorder', kid: 'did:key:zOrdersRecorder#0', alg: 'EdDSA' },
  await webcrypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']),
);

/** A journal the recorder has recorded `eventIds` into, after its genesis. */
async function recordedJournal(eventIds: readonly string[]): Promise<MemoryAuditJournal> {
  const journal = new MemoryAuditJournal();
  const recorder = new AuditRecorderService({
    ...ledger,
    tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25',
    sourceId: 'orders-recorder',
    journal,
    signer,
    hasher,
    clock: { now: () => 1_750_000_001_000 },
  });
  for (const [index, eventId] of eventIds.entries()) {
    const sequence = index + 1;
    await recorder.submitAuthenticated({
      ledgerId: ledger.ledgerId,
      producerEvent: sampleAuditEvent(sequence, {
        eventId,
        tenantRef,
        source: {
          producer: { kind: 'pairwise_did', did: producer },
          sourceId: 'orders-service',
          sourceSequence: String(sequence),
        },
      }),
      encryptedEvidence: [],
    }, { producerAuthority: producer, tenantAuthority: 'orders-tenant', tenantRef });
  }
  return journal;
}

/** One signer process: a checkpoint builder over its copy of the journal and the shared store. */
function signerProcess(journal: MemoryAuditJournal, store: AuditCheckpointStore, now: number): AuditCheckpointBuilder {
  return new AuditCheckpointBuilder({ journal, store, signer, hasher, clock: { now: () => now } });
}

/** The shared store as the two signer processes see it while they race: both read it before either writes. */
function racedStore(inner: AuditCheckpointStore): AuditCheckpointStore {
  let readers = 0;
  let bothRead!: () => void;
  const ready = new Promise<void>((resolve) => { bothRead = resolve; });
  return {
    getByTreeSize: (input, treeSize) => inner.getByTreeSize(input, treeSize),
    putIfAbsent: (checkpoint) => inner.putIfAbsent(checkpoint),
    async getLatest(input) {
      const latest = await inner.getLatest(input);
      readers += 1;
      if (readers === 2) bothRead();
      await ready;
      return latest;
    },
  };
}

type EndpointAnswer =
  | { ok: true; checkpoint: SignedAuditCheckpointV1 }
  | { ok: false; criticalFinding: unknown };

/** The adopter's endpoint: success for a checkpoint or a lost race, failure and a finding for anything else. */
async function checkpointNow(builder: AuditCheckpointBuilder): Promise<EndpointAnswer> {
  try {
    return { ok: true, checkpoint: await builder.createCheckpoint(ledger) };
  } catch (error) {
    // The other signer's checkpoint stands; asking again returns it.
    if (isLostCheckpointRace(error)) return { ok: true, checkpoint: await builder.createCheckpoint(ledger) };
    return { ok: false, criticalFinding: error };
  }
}

/** Assert that `answer` is a failure whose finding is a checkpoint conflict naming a fork. */
function assertFork(answer: EndpointAnswer): void {
  assert.equal(answer.ok, false, 'the endpoint answered success for a fork');
  if (answer.ok) return;
  const finding = answer.criticalFinding;
  assert.ok(finding instanceof AuditProtocolError, `the finding is not an AuditProtocolError: ${String(finding)}`);
  assert.equal(finding.code, AUDIT_ERROR_CODES.CHECKPOINT_CONFLICT);
  assert.equal(finding.details?.reason, AUDIT_CHECKPOINT_CONFLICT_REASONS.FORK);
}

await runCases('checkpoint-conflicts', 'an on-demand checkpoint endpoint answers success for a lost race between two signers and failure for a forked journal, told apart by isLostCheckpointRace', [
  {
    name: 'control: one signer checkpoints the journal',
    run: async () => {
      const answer = await checkpointNow(signerProcess(await recordedJournal(['evt_1', 'evt_2', 'evt_3']), new MemoryAuditCheckpointStore(), 1));
      assert.ok(answer.ok, 'the checkpoint was refused');
      assert.equal(answer.checkpoint.core.treeSize, '4');
    },
  },
  {
    name: 'two signers checkpoint the same journal at once, and both answer with the checkpoint one of them stored',
    run: async () => {
      const journal = await recordedJournal(['evt_1', 'evt_2', 'evt_3']);
      const inner = new MemoryAuditCheckpointStore();
      const store = racedStore(inner);
      const answers = await Promise.all([checkpointNow(signerProcess(journal, store, 1)), checkpointNow(signerProcess(journal, store, 2))]);
      const stored = await inner.getLatest(ledger);
      for (const answer of answers) {
        assert.ok(answer.ok, `a lost race was answered as a failure: ${answer.ok ? '' : String(answer.criticalFinding)}`);
        assert.equal(answer.checkpoint.checkpointDigest, stored?.checkpointDigest);
      }
    },
  },
  {
    name: 'a journal restored under a stored checkpoint, then written to, is answered as a fork',
    run: async () => {
      const store = new MemoryAuditCheckpointStore();
      const signed = await signerProcess(await recordedJournal(['evt_1', 'evt_2', 'evt_3']), store, 1).createCheckpoint(ledger);
      const restored = await recordedJournal(['evt_1', 'evt_2b', 'evt_3b', 'evt_4b']);
      assertFork(await checkpointNow(signerProcess(restored, store, 2)));
      assert.equal((await store.getLatest(ledger))?.checkpointDigest, signed.checkpointDigest);
    },
  },
  {
    name: 'two copies of the journal that diverged race at the same size, and the one that lost is answered as a fork',
    run: async () => {
      const store = racedStore(new MemoryAuditCheckpointStore());
      const answers = await Promise.all([
        checkpointNow(signerProcess(await recordedJournal(['evt_1', 'evt_2', 'evt_3']), store, 1)),
        checkpointNow(signerProcess(await recordedJournal(['evt_1', 'evt_2b', 'evt_3b']), store, 2)),
      ]);
      assert.equal(answers.filter((answer) => answer.ok).length, 1, 'expected exactly one signer to store its checkpoint');
      const lost = answers.find((answer) => !answer.ok);
      assert.ok(lost !== undefined, 'both diverged copies were answered as success');
      assertFork(lost);
    },
  },
]);
