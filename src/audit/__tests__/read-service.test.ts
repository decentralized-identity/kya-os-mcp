import { describe, expect, it } from 'vitest';
import {
  createInMemoryReferenceRecorder,
  sampleAuditEvent,
} from '../reference-recorder.js';

describe('LocalAuditReadService', () => {
  it('returns an empty page and null head before anything is recorded', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    const page = await recorder.read.listEntries(recorder.ledger);
    expect(page.entries).toEqual([]);
    expect(page.head).toBeNull();
    expect(page.nextAfterSequence).toBeNull();
  });

  it('lists produced entries in ascending sequence, echoing the head', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    const submitted = [];
    for (let index = 1; index <= 3; index += 1) {
      submitted.push(await recorder.submit(sampleAuditEvent(index)));
    }

    const page = await recorder.read.listEntries(recorder.ledger);

    // strictly ascending sequence
    const sequences = page.entries.map((entry) => BigInt(entry.core.sequence));
    for (let index = 1; index < sequences.length; index += 1) {
      expect(sequences[index]! > sequences[index - 1]!).toBe(true);
    }

    // every submitted entry is present
    const returned = new Set(page.entries.map((entry) => entry.entryDigest));
    for (const entry of submitted) {
      expect(returned.has(entry.entryDigest)).toBe(true);
    }

    // the page echoes the ledger head, and the head is the last entry
    const head = await recorder.read.getHead(recorder.ledger);
    expect(page.head).toEqual(head);
    expect(head?.entryDigest).toBe(page.entries.at(-1)!.entryDigest);
    expect(page.nextAfterSequence).toBeNull();
  });

  it('yields entries that pass independent cryptographic and chain verification', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 3; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }

    const page = await recorder.read.listEntries(recorder.ledger);
    const report = await recorder.verifier.verifyEntries(
      page.entries,
      recorder.verificationPolicy,
    );

    expect(report.cryptographicIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
    expect(report.chainIntegrity).toEqual({ verdict: 'valid', reasonCodes: [] });
  });

  it('paginates: stepping the cursor reconstructs the full ledger exactly', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    for (let index = 1; index <= 5; index += 1) {
      await recorder.submit(sampleAuditEvent(index));
    }

    const all = await recorder.read.listEntries(recorder.ledger);
    expect(all.entries.length).toBeGreaterThanOrEqual(5);

    const paged = [];
    let cursor: string | undefined;
    for (;;) {
      const nextPage = await recorder.read.listEntries({
        ...recorder.ledger,
        limit: 2,
        ...(cursor === undefined ? {} : { afterSequence: cursor }),
      });
      paged.push(...nextPage.entries);
      if (nextPage.nextAfterSequence === null) break;
      expect(nextPage.entries).toHaveLength(2);
      cursor = nextPage.nextAfterSequence;
    }

    expect(paged.map((entry) => entry.entryDigest)).toEqual(
      all.entries.map((entry) => entry.entryDigest),
    );
  });

  it('clamps an oversized limit instead of over-reading', async () => {
    const recorder = await createInMemoryReferenceRecorder();
    await recorder.submit(sampleAuditEvent(1));
    const page = await recorder.read.listEntries({
      ...recorder.ledger,
      limit: 10_000_000,
    });
    expect(page.nextAfterSequence).toBeNull();
    expect(page.entries.length).toBeGreaterThanOrEqual(1);
  });
});
