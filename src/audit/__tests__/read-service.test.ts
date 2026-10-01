import { describe, expect, it } from 'vitest';
import { NodeCryptoProvider } from '../../__tests__/utils/node-crypto-provider.js';
import { CryptoProviderAuditHasher } from '../crypto.js';
import type { AuditJournalProvider } from '../providers/journal.js';
import { MemoryAuditJournal } from '../providers/memory-journal.js';
import { LocalAuditReadService } from '../read-service.js';
import { AuditRecorderService } from '../recorder-service.js';
import {
  createInMemoryReferenceRecorder,
  sampleAuditEvent,
} from '../reference-recorder.js';

async function racingLedger() {
  const journal = new MemoryAuditJournal();
  const tenantRef = sampleAuditEvent(1).tenantRef;
  const recorder = new AuditRecorderService({
    ledgerId: 'kya:reference:audit:primary', ledgerEpochId: 'epoch_1', tenantRef,
    binding: 'urn:kya-os:audit-binding:mcp:2025-11-25', sourceId: 'reference-recorder',
    journal, hasher: new CryptoProviderAuditHasher(new NodeCryptoProvider()),
    clock: { now: () => 1_750_000_001_000 },
    signer: {
      ref: { did: 'did:key:zRecorder', kid: 'did:key:zRecorder#0', alg: 'EdDSA' },
      sign: async () => 'signature',
    },
  });
  let next = 1;
  const append = () => recorder.submitAuthenticated({
    ledgerId: 'kya:reference:audit:primary',
    producerEvent: sampleAuditEvent(next++),
    encryptedEvidence: [],
  }, { producerAuthority: 'did:key:zReferenceProducer', tenantAuthority: 'tenant', tenantRef });
  for (let index = 0; index < 3; index += 1) await append();
  return { journal, append, ledger: { ledgerId: 'kya:reference:audit:primary', ledgerEpochId: 'epoch_1' } };
}

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

  it('echoes the head that bounds the page while appends race the read', async () => {
    const { journal, append, ledger } = await racingLedger();
    const passthrough = {
      capabilities: journal.capabilities,
      getByIdempotencyKey: journal.getByIdempotencyKey.bind(journal),
      compareAndAppend: journal.compareAndAppend.bind(journal),
    };
    // An append lands while the head is being read...
    const appendDuringHead: AuditJournalProvider = {
      ...passthrough,
      getHead: async (input) => {
        await append();
        return journal.getHead(input);
      },
      readRange: (query) => journal.readRange(query),
    };
    // ...or after the head was read and before the range is.
    const appendDuringRange: AuditJournalProvider = {
      ...passthrough,
      getHead: (input) => journal.getHead(input),
      readRange: async function* (query) {
        await append();
        yield* journal.readRange(query);
      },
    };

    for (const racing of [appendDuringHead, appendDuringRange]) {
      const page = await new LocalAuditReadService({ journal: racing }).listEntries({
        ...ledger, limit: 50,
      });
      // SPEC-AUDIT-READ 2.2: null exactly when the page reached the echoed head.
      expect(page.nextAfterSequence).toBeNull();
      expect(page.entries.at(-1)?.core.sequence).toBe(page.head?.sequence);
    }

    const bounded = await new LocalAuditReadService({ journal: appendDuringRange }).listEntries({
      ...ledger, limit: 2,
    });
    expect(bounded.entries.map((entry) => entry.core.sequence)).toEqual(['0', '1']);
    expect(bounded.nextAfterSequence).toBe('1');
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
