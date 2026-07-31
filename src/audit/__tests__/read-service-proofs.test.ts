import { describe, expect, it } from 'vitest';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { createLocalAuditReadService } from '../read-service.js';
import {
  createInMemoryReferenceRecorder,
  sampleAuditEvent,
} from '../reference-recorder.js';

describe('LocalAuditReadService proofs', () => {
  it('rejects proof calls when the service has no checkpoint access', async () => {
    const bare = createLocalAuditReadService({ journal: new MemoryAuditJournal() });
    await expect(
      bare.getInclusionProof({
        ledgerId: 'kya:x',
        ledgerEpochId: 'epoch_1',
        sequence: '1',
      }),
    ).rejects.toThrow(/checkpoint access/i);
  });

  it('rejects an inclusion proof before any checkpoint has been sealed', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    await recorder.submit(sampleAuditEvent(1));
    await expect(
      recorder.read.getInclusionProof({ ...recorder.ledger, sequence: '1' }),
    ).rejects.toThrow(/checkpoint/i);
  });

  it('produces an inclusion proof bound to entry + checkpoint that closes against the signed root', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 4; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }
    const checkpoint = await recorder.checkpoint();

    const page = await recorder.read.listEntries(recorder.ledger);
    const target = page.entries.at(-1)!;
    const proof = await recorder.read.getInclusionProof({
      ...recorder.ledger,
      sequence: target.core.sequence,
    });

    expect(proof.entryDigest).toBe(target.entryDigest);
    expect(proof.checkpointDigest).toBe(checkpoint.checkpointDigest);
    expect(proof.proof.treeSize).toBe(checkpoint.core.treeSize);

    // What a dashboard client checks: the Merkle path closes to the checkpoint's signed root.
    const closes = await recorder.checkpoints.builder.verifyInclusion(
      target.entryDigest,
      checkpoint,
      proof.proof,
    );
    expect(closes).toBe(true);
  });

  it('rejects an inclusion proof for a sequence that does not exist', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    await recorder.submit(sampleAuditEvent(1));
    await recorder.checkpoint();
    await expect(
      recorder.read.getInclusionProof({ ...recorder.ledger, sequence: '999999' }),
    ).rejects.toThrow();
  });

  it('produces a consistency proof binding an earlier checkpoint to the latest', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 2; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }
    const older = await recorder.checkpoint();
    for (let index = 3; index <= 4; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }
    const newer = await recorder.checkpoint();

    const proof = await recorder.read.getConsistencyProof({
      ...recorder.ledger,
      oldTreeSize: older.core.treeSize,
    });

    // The read service's job is correct assembly: bind both checkpoints and
    // carry the raw Merkle proof. (Merkle consistency correctness itself is
    // covered by checkpoint.test.ts, so this does not re-test the builder.)
    expect(proof.oldCheckpointDigest).toBe(older.checkpointDigest);
    expect(proof.newCheckpointDigest).toBe(newer.checkpointDigest);
    expect(proof.proof.oldTreeSize).toBe(older.core.treeSize);
    expect(proof.proof.newTreeSize).toBe(newer.core.treeSize);
    expect(proof.ledgerId).toBe(recorder.ledger.ledgerId);
  });

  it('rejects a consistency proof when no checkpoint exists at the old tree size', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    await recorder.submit(sampleAuditEvent(1));
    await recorder.checkpoint();
    await expect(
      recorder.read.getConsistencyProof({ ...recorder.ledger, oldTreeSize: '999' }),
    ).rejects.toThrow(/old tree size/i);
  });
});
