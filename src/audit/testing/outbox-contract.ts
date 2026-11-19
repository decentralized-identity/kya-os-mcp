import {
  auditOutboxItemKey,
  type AuditOutboxItem,
  type AuditOutboxItemKey,
  type AuditOutboxProvider,
} from '../providers/outbox.js';
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
  // Acknowledge the way the trail does: by key when the adapter declares it.
  const keyOf = (
    provider: AuditOutboxProvider,
    value: AuditOutboxItem,
  ): AuditOutboxItemKey | string =>
    provider.capabilities.keyedBySource === true ? auditOutboxItemKey(value) : value.eventId;

  let keyedBySource = false;
  await check(checks, 'declares and preserves FIFO order per source', async () => {
    const provider = await createProvider();
    keyedBySource = provider.capabilities.keyedBySource === true;
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
  await check(checks, 'enqueues idempotently and rejects divergent content per event identity', async () => {
    const provider = await createProvider();
    await provider.enqueue(item(firstEntry));
    await provider.enqueue(structuredClone(item(firstEntry)));
    const pending = await collect(provider);
    expectContract(pending.length === 1, 'redelivered enqueue duplicated the pending item');
    const divergent = item(firstEntry);
    divergent.submission = {
      ...divergent.submission,
      producerEvent: {
        ...divergent.submission.producerEvent,
        action: { category: 'tampered' },
      },
    };
    let rejected = false;
    try {
      await provider.enqueue(divergent);
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'divergent content under one event identity was accepted');
  });

  await check(checks, 'accounts for failures and removes only acknowledged items', async () => {
    const provider = await createProvider();
    await provider.enqueue(item(firstEntry));
    await provider.enqueue(item(secondEntry));
    await provider.markFailed(keyOf(provider, item(firstEntry)), new Error('offline'));
    let pending = await collect(provider);
    expectContract(pending[0]?.attempts === 1, 'failed delivery attempt was not persisted');
    await provider.markDelivered(keyOf(provider, item(firstEntry)));
    pending = await collect(provider);
    expectContract(
      pending.length === 1 && pending[0]?.eventId === secondEntry.core.event.eventId,
      'acknowledgement removed the wrong pending item',
    );
  });

  // Only an adapter that declares source-scoped keys promises to keep two
  // sources' items with one event ID apart.
  if (keyedBySource) {
    await check(checks, 'keys items by producer source and event identity', async () => {
      const provider = await createProvider();
      const own = item(firstEntry);
      const otherSource: AuditOutboxItem = {
        ...own,
        submission: {
          ...own.submission,
          producerEvent: {
            ...own.submission.producerEvent,
            source: { ...own.submission.producerEvent.source, sourceId: 'contract-source-2' },
          },
        },
      };
      await provider.enqueue(own);
      await provider.enqueue(otherSource);
      expectContract(
        (await collect(provider)).length === 2,
        'an event ID from one source displaced another source\'s pending item',
      );
      await provider.markDelivered(auditOutboxItemKey(own));
      const pending = await collect(provider);
      expectContract(
        pending.length === 1 &&
          pending[0]?.submission.producerEvent.source.sourceId === 'contract-source-2',
        'acknowledging one source removed another source\'s pending item',
      );
    });
  }

  return report('outbox', checks);
}
