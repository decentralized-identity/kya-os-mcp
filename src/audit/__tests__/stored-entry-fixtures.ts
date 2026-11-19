import { expect } from 'vitest';
import { canonicalizeJsonBytes } from '../../utils/canonical-json.js';
import type { AuditSigner } from '../crypto.js';
import {
  buildAuditRecorderReceiptCore,
  digestAuditEntry,
  digestAuditEvent,
  digestAuditEvidenceManifest,
} from '../integrity.js';
import type { MemoryAuditJournal } from '../providers/memory-journal.js';
import type {
  AuditEntryCoreV1,
  AuditHead,
  AuditLedgerRef,
  SignedAuditEntryV1,
  SignerRef,
} from '../types.js';
import { producerEvent, TestSigner } from './audit-fixtures.js';
import { hasher, ledger } from './observer-fixtures.js';

/** A well-formed entry with correct digests after `head`, as a writer of the journal store with no key could write. */
export async function unsignedEntryAfter(
  head: AuditHead,
  options: {
    jws?: string;
    recorder?: SignerRef;
    ledgerRef?: AuditLedgerRef;
    previousEntryDigest?: AuditHead['entryDigest'];
    /** Signs the receipt with this signer instead of writing `jws`. */
    signWith?: AuditSigner;
  } = {},
): Promise<SignedAuditEntryV1> {
  const event = producerEvent('evt_never_happened', 99);
  const eventDigest = await digestAuditEvent(hasher, event);
  const core: AuditEntryCoreV1 = {
    schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
    ...(options.ledgerRef ?? ledger),
    sequence: String(BigInt(head.sequence) + 1n),
    previousEntryDigest: options.previousEntryDigest ?? head.entryDigest,
    recordedAt: 1_750_000_001_000,
    recorder: options.recorder ?? new TestSigner().ref,
    eventDigest,
    event,
    evidenceManifestDigest: await digestAuditEvidenceManifest(hasher, event),
    integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
  };
  const entryDigest = await digestAuditEntry(hasher, core);
  const receiptCore = buildAuditRecorderReceiptCore(core, entryDigest);
  return {
    core, eventDigest, entryDigest,
    recorderReceipt: {
      core: receiptCore,
      jws: options.signWith === undefined
        ? options.jws ?? 'no.recorder.signature'
        : await options.signWith.sign(canonicalizeJsonBytes(receiptCore)),
    },
  };
}

export async function insert(journal: MemoryAuditJournal, entry: SignedAuditEntryV1, key: string): Promise<void> {
  const head = await journal.getHead(ledger);
  const result = await journal.compareAndAppend({
    ledger, expectedHead: head, entry, idempotencyKey: `sha256:${key.repeat(64)}`,
  });
  expect(result.kind).toBe('appended');
}
