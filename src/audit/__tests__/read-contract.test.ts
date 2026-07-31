import { describe, expect, it } from 'vitest';
import {
  AUDIT_LIST_ENTRIES_REQUEST_SCHEMA_ID,
  parseAuditConsistencyProofResponse,
  parseAuditHeadResponse,
  parseAuditInclusionProofResponse,
  parseAuditListEntriesRequest,
  parseAuditListEntriesResponse,
  toAuditConsistencyProofResponse,
  toAuditHeadResponse,
  toAuditInclusionProofResponse,
  toAuditListEntriesResponse,
} from '../read-contract.js';
import {
  createInMemoryReferenceRecorder,
  sampleAuditEvent,
} from '../reference-recorder.js';

/** Simulate the network: serialize to JSON and parse back, as a transport would. */
function overTheWire<T>(value: T): unknown {
  return JSON.parse(JSON.stringify(value));
}

describe('audit read wire contract', () => {
  it('parses a valid list-entries request and rejects malformed ones', () => {
    const valid = {
      schema: AUDIT_LIST_ENTRIES_REQUEST_SCHEMA_ID,
      ledger: { ledgerId: 'kya:x', ledgerEpochId: 'epoch_1' },
      limit: 50,
    };
    expect(parseAuditListEntriesRequest(valid).limit).toBe(50);

    expect(() => parseAuditListEntriesRequest({ ...valid, bogus: 1 })).toThrow();
    expect(() => parseAuditListEntriesRequest({ ...valid, limit: 999_999 })).toThrow();
    expect(() => parseAuditListEntriesRequest({ ...valid, afterSequence: 'not-decimal' })).toThrow();
    expect(() => parseAuditListEntriesRequest({ ...valid, limit: 0 })).toThrow();
  });

  it('round-trips a real listEntries result: entries still verify after the wire', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 3; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }

    const page = await recorder.read.listEntries(recorder.ledger);
    const parsed = parseAuditListEntriesResponse(overTheWire(toAuditListEntriesResponse(page)));

    expect(parsed.entries.map((entry) => entry.entryDigest)).toEqual(
      page.entries.map((entry) => entry.entryDigest),
    );
    expect(parsed.head).toEqual(page.head);
    expect(parsed.nextAfterSequence).toBe(page.nextAfterSequence);

    // The whole point of the "both" trust model: verification survives serialization.
    const report = await recorder.verifier.verifyEntries(
      parsed.entries,
      recorder.verificationPolicy,
    );
    expect(report.cryptographicIntegrity.verdict).toBe('valid');
    expect(report.chainIntegrity.verdict).toBe('valid');
  });

  it('round-trips a head response', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    await recorder.submit(sampleAuditEvent(1));
    const head = await recorder.read.getHead(recorder.ledger);
    const parsed = parseAuditHeadResponse(overTheWire(toAuditHeadResponse(head)));
    expect(parsed.head).toEqual(head);
  });

  it('round-trips a real inclusion proof: still closes against the signed root after the wire', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 3; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }
    const checkpoint = await recorder.checkpoint();
    const page = await recorder.read.listEntries(recorder.ledger);
    const target = page.entries.at(-1)!;

    const proof = await recorder.read.getInclusionProof({
      ...recorder.ledger,
      sequence: target.core.sequence,
    });
    const parsed = parseAuditInclusionProofResponse(overTheWire(toAuditInclusionProofResponse(proof)));

    const closes = await recorder.checkpoints.builder.verifyInclusion(
      target.entryDigest,
      checkpoint,
      parsed.proof.proof,
    );
    expect(closes).toBe(true);
  });

  it('round-trips a consistency proof response', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 2; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }
    const older = await recorder.checkpoint();
    await recorder.submit(sampleAuditEvent(3));
    await recorder.checkpoint();

    const proof = await recorder.read.getConsistencyProof({
      ...recorder.ledger,
      oldTreeSize: older.core.treeSize,
    });
    const parsed = parseAuditConsistencyProofResponse(
      overTheWire(toAuditConsistencyProofResponse(proof)),
    );
    expect(parsed.proof.oldCheckpointDigest).toBe(older.checkpointDigest);
  });
});
