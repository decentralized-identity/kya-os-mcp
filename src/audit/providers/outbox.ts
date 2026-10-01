import type { AuditRecorderSubmission } from './recorder-client.js';
import { canonicalizeJson } from '../../utils/canonical-json.js';

export interface AuditOutboxItem {
  eventId: string;
  submission: AuditRecorderSubmission;
  enqueuedAt: number;
  /** Persisted delivery failures; durable adapters use this for retry and DLQ policy. */
  attempts: number;
}

/**
 * Event IDs are unique only within a producer source, so an outbox shared by
 * several sources identifies an item by both.
 */
export interface AuditOutboxItemKey {
  sourceId: string;
  eventId: string;
}

export function auditOutboxItemKey(item: AuditOutboxItem): AuditOutboxItemKey {
  return { sourceId: item.submission.producerEvent.source.sourceId, eventId: item.eventId };
}

export interface AuditOutboxProvider {
  readonly capabilities: {
    durability: 'ephemeral' | 'durable';
    /** `pending()` yields enqueue order within each producer source. */
    fifoPerSource: true;
    /**
     * Items are keyed by {@link AuditOutboxItemKey}: `enqueue` is idempotent per
     * key, and the trail acknowledges items with their key. Without it the
     * trail acknowledges by bare event ID, as adapters that predate the key
     * expect. Declare it only where `markDelivered` and `markFailed` handle a
     * key; `MemoryAuditOutbox` withholds it from a subclass that overrides them.
     */
    keyedBySource?: true;
  };
  enqueue(item: AuditOutboxItem): Promise<void>;
  /**
   * Eligible items MUST be yielded FIFO for each `producerEvent.source.sourceId`.
   * The provider owns retry scheduling/caps and excludes dead-lettered items.
   */
  pending(limit?: number): AsyncIterable<AuditOutboxItem>;
  /**
   * The trail passes the item's key when `capabilities.keyedBySource` is set,
   * and its bare event ID otherwise. Method syntax on purpose: parameters stay
   * bivariant, so an adapter that still declares `markDelivered(eventId: string)`
   * implements this interface.
   */
  markDelivered(key: AuditOutboxItemKey | string): Promise<void>;
  /** Persist the failure and apply the provider's configured retry/DLQ policy. */
  markFailed(key: AuditOutboxItemKey | string, error: unknown): Promise<void>;
}

function storageKey(key: AuditOutboxItemKey): string {
  return `${key.sourceId}\0${key.eventId}`;
}

/** Development-only outbox. Buffered assurance requires a durable adapter. */
export class MemoryAuditOutbox implements AuditOutboxProvider {
  // Typed so the new flag stays optional: a subclass that overrides
  // `capabilities` with the earlier shape still compiles. The flag is declared
  // only while acknowledgement runs this class's own key-aware methods; a
  // subclass that overrides them may expect the bare event ID it was written
  // for, so it receives one unless it declares the flag itself.
  readonly capabilities: { durability: 'ephemeral'; fifoPerSource: true; keyedBySource?: true } = {
    durability: 'ephemeral',
    fifoPerSource: true,
    ...(this.markDelivered === MemoryAuditOutbox.prototype.markDelivered &&
      this.markFailed === MemoryAuditOutbox.prototype.markFailed
      ? { keyedBySource: true as const }
      : {}),
  };
  private readonly items = new Map<string, AuditOutboxItem>();

  async enqueue(item: AuditOutboxItem): Promise<void> {
    const key = storageKey(auditOutboxItemKey(item));
    const existing = this.items.get(key);
    if (existing !== undefined) {
      if (!sameSubmission(existing.submission, item.submission)) {
        throw new Error(`Audit outbox event identity collision: ${item.eventId}`);
      }
      return;
    }
    this.items.set(key, item);
  }

  async *pending(limit = Number.MAX_SAFE_INTEGER): AsyncIterable<AuditOutboxItem> {
    let count = 0;
    for (const item of [...this.items.values()]) {
      if (count >= limit) return;
      count += 1;
      yield item;
    }
  }

  async markDelivered(key: AuditOutboxItemKey | string): Promise<void> {
    const stored = this.storedKey(key);
    if (stored !== undefined) this.items.delete(stored);
  }

  async markFailed(key: AuditOutboxItemKey | string): Promise<void> {
    const stored = this.storedKey(key);
    if (stored === undefined) return;
    const item = this.items.get(stored);
    if (item !== undefined) this.items.set(stored, { ...item, attempts: item.attempts + 1 });
  }

  /**
   * A bare event ID names an item only while exactly one source has it
   * pending. With several, acknowledging any one of them could drop another
   * source's event, so the caller must pass the item's key instead.
   */
  private storedKey(key: AuditOutboxItemKey | string): string | undefined {
    if (typeof key !== 'string') return storageKey(key);
    const matches = [...this.items].filter(([, item]) => item.eventId === key);
    if (matches.length > 1) {
      throw new Error(
        `Audit outbox event ID ${key} is pending for several sources; pass its AuditOutboxItemKey`,
      );
    }
    return matches[0]?.[0];
  }
}

function sameSubmission(left: AuditRecorderSubmission, right: AuditRecorderSubmission): boolean {
  if (left.ledgerId !== right.ledgerId ||
    left.expectedLedgerEpochId !== right.expectedLedgerEpochId ||
    canonicalizeJson(left.producerEvent) !== canonicalizeJson(right.producerEvent) ||
    left.encryptedEvidence.length !== right.encryptedEvidence.length) return false;
  return left.encryptedEvidence.every((item, index) => {
    const other = right.encryptedEvidence[index];
    if (other === undefined || canonicalizeJson(item.ref) !== canonicalizeJson(other.ref) ||
      item.ciphertext.byteLength !== other.ciphertext.byteLength) return false;
    let difference = 0;
    for (let offset = 0; offset < item.ciphertext.byteLength; offset += 1) {
      difference |= item.ciphertext[offset]! ^ other.ciphertext[offset]!;
    }
    return difference === 0;
  });
}
