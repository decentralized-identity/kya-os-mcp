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
    state.receipted.add(parsed);
  }

  async getState(sourceId: string): Promise<AuditSourceState> {
    const state = this.state(sourceId);
    let highestContiguous = 0n;
    while (state.receipted.has(highestContiguous + 1n)) highestContiguous += 1n;
    const pendingSequences: string[] = [];
    for (let sequence = highestContiguous + 1n; sequence <= state.next; sequence += 1n) {
      if (!state.receipted.has(sequence)) pendingSequences.push(sequence.toString());
    }
    return {
      sourceId,
      highestEmitted: state.next.toString(),
      highestReceipted: highestContiguous.toString(),
      pendingSequences,
    };
  }

  private state(sourceId: string): MutableSourceState {
    const existing = this.states.get(sourceId);
    if (existing !== undefined) return existing;
    const created = {
      next: 0n,
      receipted: new Set<bigint>(),
      claims: new Map<string, { sequence: bigint; previousSourceEventDigest?: Digest }>(),
      eventDigests: new Map<bigint, Digest>(),
    };
    this.states.set(sourceId, created);
    return created;
  }
}
