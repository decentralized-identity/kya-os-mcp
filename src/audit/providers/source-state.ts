import type { Digest } from '../types.js';

export interface AuditSourceState {
  sourceId: string;
  highestEmitted: string;
  highestReceipted: string;
  pendingSequences: string[];
}

export interface AuditSourceStateProvider {
  readonly capabilities: { durability: 'ephemeral' | 'durable'; atomicClaim: true };
  claimEvent(sourceId: string, eventId: string): Promise<{
    sequence: string;
    previousSourceEventDigest?: Digest;
  }>;
  markEmitted(sourceId: string, eventId: string, sequence: string, eventDigest: Digest): Promise<void>;
  markReceipted(sourceId: string, sequence: string, entryDigest: Digest): Promise<void>;
  getState(sourceId: string): Promise<AuditSourceState>;
}

interface MutableSourceState {
  next: bigint;
  receiptedWatermark: bigint;
  receipted: Set<bigint>;
  claims: Map<string, { sequence: bigint; previousSourceEventDigest?: Digest }>;
  eventDigests: Map<bigint, Digest>;
}

/** In-process reference source-watermark state. Production AAP-3 needs durability. */
export class MemoryAuditSourceState implements AuditSourceStateProvider {
  readonly capabilities = { durability: 'ephemeral' as const, atomicClaim: true as const };
  private readonly states = new Map<string, MutableSourceState>();

  async claimEvent(sourceId: string, eventId: string): Promise<{
    sequence: string;
    previousSourceEventDigest?: Digest;
  }> {
    const state = this.state(sourceId);
    const existing = state.claims.get(eventId);
    if (existing !== undefined) {
      return {
        sequence: existing.sequence.toString(),
        ...(existing.previousSourceEventDigest === undefined
          ? {}
          : { previousSourceEventDigest: existing.previousSourceEventDigest }),
      };
    }
    state.next += 1n;
    const previousSourceEventDigest = state.eventDigests.get(state.next - 1n);
    const claim = {
      sequence: state.next,
      ...(previousSourceEventDigest === undefined ? {} : { previousSourceEventDigest }),
    };
    state.claims.set(eventId, claim);
    return {
      sequence: claim.sequence.toString(),
      ...(claim.previousSourceEventDigest === undefined
        ? {}
        : { previousSourceEventDigest: claim.previousSourceEventDigest }),
    };
  }

  async markEmitted(
    sourceId: string,
    eventId: string,
    sequence: string,
    eventDigest: Digest,
  ): Promise<void> {
    const state = this.state(sourceId);
    const parsed = BigInt(sequence);
    const claim = state.claims.get(eventId);
    if (claim?.sequence !== parsed) throw new RangeError('Unknown source event claim');
    const existing = state.eventDigests.get(parsed);
    if (existing !== undefined && existing !== eventDigest) {
      throw new Error(`Source event identity collision: ${eventId}`);
    }
    state.eventDigests.set(parsed, eventDigest);
  }

  async markReceipted(sourceId: string, sequence: string): Promise<void> {
    const parsed = BigInt(sequence);
    const state = this.state(sourceId);
    if (parsed < 1n || parsed > state.next) throw new RangeError('Unknown source sequence');
    if (parsed <= state.receiptedWatermark) return;
    state.receipted.add(parsed);
    while (state.receipted.delete(state.receiptedWatermark + 1n)) {
      state.receiptedWatermark += 1n;
    }

    // Keep only the current watermark's claim/digest plus unresolved entries.
    // This bounds the reference adapter by the outstanding delivery window,
    // while retaining the digest needed to link the next producer event.
    for (const [eventId, claim] of state.claims) {
      if (claim.sequence < state.receiptedWatermark) state.claims.delete(eventId);
    }
    for (const sequenceNumber of state.eventDigests.keys()) {
      if (sequenceNumber < state.receiptedWatermark) state.eventDigests.delete(sequenceNumber);
    }
  }

  async getState(sourceId: string): Promise<AuditSourceState> {
    const state = this.state(sourceId);
    const pendingSequences: string[] = [];
    for (let sequence = state.receiptedWatermark + 1n; sequence <= state.next; sequence += 1n) {
      if (!state.receipted.has(sequence)) pendingSequences.push(sequence.toString());
    }
    return {
      sourceId,
      highestEmitted: state.next.toString(),
      highestReceipted: state.receiptedWatermark.toString(),
      pendingSequences,
    };
  }

  private state(sourceId: string): MutableSourceState {
    const existing = this.states.get(sourceId);
    if (existing !== undefined) return existing;
    const created = {
      next: 0n,
      receiptedWatermark: 0n,
      receipted: new Set<bigint>(),
      claims: new Map<string, { sequence: bigint; previousSourceEventDigest?: Digest }>(),
      eventDigests: new Map<bigint, Digest>(),
    };
    this.states.set(sourceId, created);
    return created;
  }
}
