import type { AuditRecorderSubmission } from './recorder-client.js';
import { canonicalizeJson } from '../../utils/canonical-json.js';

export interface AuditOutboxItem {
  eventId: string;
  submission: AuditRecorderSubmission;
  enqueuedAt: number;
  attempts: number;
}

export interface AuditOutboxProvider {
  readonly capabilities: { durability: 'ephemeral' | 'durable' };
  enqueue(item: AuditOutboxItem): Promise<void>;
  pending(limit?: number): AsyncIterable<AuditOutboxItem>;
  markDelivered(eventId: string): Promise<void>;
  markFailed(eventId: string, error: unknown): Promise<void>;
}

/** Development-only outbox. Buffered assurance requires a durable adapter. */
export class MemoryAuditOutbox implements AuditOutboxProvider {
  readonly capabilities = { durability: 'ephemeral' as const };
  private readonly items = new Map<string, AuditOutboxItem>();

  async enqueue(item: AuditOutboxItem): Promise<void> {
    const existing = this.items.get(item.eventId);
    if (existing !== undefined) {
      if (!sameSubmission(existing.submission, item.submission)) {
        throw new Error(`Audit outbox event identity collision: ${item.eventId}`);
      }
      return;
    }
    this.items.set(item.eventId, item);
  }

  async *pending(limit = Number.MAX_SAFE_INTEGER): AsyncIterable<AuditOutboxItem> {
    let count = 0;
    for (const item of [...this.items.values()]) {
      if (count >= limit) return;
      count += 1;
      yield item;
    }
  }

  async markDelivered(eventId: string): Promise<void> {
    this.items.delete(eventId);
  }

  async markFailed(eventId: string): Promise<void> {
    const item = this.items.get(eventId);
    if (item !== undefined) this.items.set(eventId, { ...item, attempts: item.attempts + 1 });
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
