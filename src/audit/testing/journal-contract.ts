import type { AuditJournalProvider } from '../providers/journal.js';
import type { SignedAuditEntryV1 } from '../types.js';
import {
  check,
  contractEntry,
  digest,
  equalJson,
  expectContract,
  numberedDigest,
  report,
  type AuditProviderContractCheck,
  type AuditProviderContractReport,
} from './contract-harness.js';

/**
 * How many appends on one expected head the contract issues at once. A journal
 * that compares the head and inserts in two steps, with any await between
 * them, commits more than one.
 */
const CONCURRENT_APPENDS = 8;

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

  await check(checks, 'rejects an expected head that is no longer the head', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const genesisHead = await provider.getHead(ledger);
    expectContract(genesisHead !== null, 'genesis append did not set the head');
    await provider.compareAndAppend({
      ledger, expectedHead: genesisHead, entry: second, idempotencyKey: idTwo,
    });
    const head = await provider.getHead(ledger);
    expectContract(head?.entryDigest === second.entryDigest, 'second append did not set the head');
    // The head's sequence with another entry's digest, and an earlier head.
    for (const stale of [{ ...head, entryDigest: digest('e') }, genesisHead]) {
      const result = await provider.compareAndAppend({
        ledger, expectedHead: stale, entry: third, idempotencyKey: idThree,
      });
      expectContract(
        result.kind === 'head_conflict' && result.actualHead?.entryDigest === second.entryDigest,
        'an expected head that is no longer the head did not conflict with the actual head',
      );
    }
    const after = await provider.getHead(ledger);
    expectContract(after?.entryDigest === second.entryDigest, 'a stale expected head changed the head');
  });

  await check(checks, 'commits exactly one of several concurrent appends on one expected head', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const head = await provider.getHead(ledger);
    // Each contender is a different entry at sequence 1, as recorder replicas racing would sign.
    const settled = await Promise.allSettled(
      Array.from({ length: CONCURRENT_APPENDS }, (_, index) => provider.compareAndAppend({
        ledger,
        expectedHead: head,
        entry: contractEntry(ledger, 1, numberedDigest(0x100 + index), first.entryDigest, index),
        idempotencyKey: numberedDigest(0x200 + index),
      })),
    );
    const results = settled.flatMap((item) => item.status === 'fulfilled' ? [item.value] : []);
    const appended = results.flatMap((result) => result.kind === 'appended' ? [result.entry] : []);
    expectContract(
      appended.length === 1,
      `${appended.length} concurrent appends on one expected head were committed`,
    );
    const winner = appended[0]!;
    // A contender that lost may answer with the head that won it, or fail without committing.
    expectContract(
      results.every((result) => result.kind === 'appended' ||
        (result.kind === 'head_conflict' &&
          result.actualHead?.sequence === winner.core.sequence &&
          result.actualHead.entryDigest === winner.entryDigest)),
      'a lost concurrent append did not answer with the head that won',
    );
    const range: SignedAuditEntryV1[] = [];
    for await (const entry of provider.readRange(ledger)) range.push(entry);
    expectContract(
      range.length === 2 && range[1]?.entryDigest === winner.entryDigest,
      'the journal holds more than one entry at one sequence, or not the one it committed',
    );
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

  await check(checks, 'scopes heads and ranges by epoch within a logical ledger', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const nextEpoch = { ledgerId: ledger.ledgerId, ledgerEpochId: 'epoch-2' };
    expectContract(
      (await provider.getHead(nextEpoch)) === null,
      'a fresh epoch inherited the previous epoch head',
    );
    const nextGenesis = contractEntry(nextEpoch, 0, digest('7'), null);
    const appended = await provider.compareAndAppend({
      ledger: nextEpoch, expectedHead: null, entry: nextGenesis, idempotencyKey: digest('8'),
    });
    expectContract(appended.kind === 'appended', 'fresh epoch genesis append failed');
    const previousHead = await provider.getHead(ledger);
    expectContract(
      previousHead?.entryDigest === first.entryDigest,
      'appending to a new epoch changed the previous epoch head',
    );
    const nextHead = await provider.getHead(nextEpoch);
    expectContract(
      nextHead?.entryDigest === nextGenesis.entryDigest,
      'the new epoch head is not scoped to its epoch',
    );
    const nextRange: SignedAuditEntryV1[] = [];
    for await (const entry of provider.readRange(nextEpoch)) nextRange.push(entry);
    expectContract(
      nextRange.length === 1 && nextRange[0]?.entryDigest === nextGenesis.entryDigest,
      'the new epoch range leaked entries from another epoch',
    );
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
