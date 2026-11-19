import type { AuditJournalProvider } from '../providers/journal.js';
import type { SignedAuditEntryV1 } from '../types.js';
import {
  check,
  contractEntry,
  digest,
  equalJson,
  expectContract,
  report,
  type AuditProviderContractCheck,
  type AuditProviderContractReport,
} from './contract-harness.js';

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
