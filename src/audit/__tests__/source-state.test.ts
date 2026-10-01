import { describe, expect, it } from 'vitest';
import { MemoryAuditSourceState } from '../providers/source-state.js';
import type { Digest } from '../types.js';

const digest = (character: string) => `sha256:${character.repeat(64)}` as Digest;

describe('MemoryAuditSourceState', () => {
  it('returns the original claim for an event ID while pending and after its receipt', async () => {
    const state = new MemoryAuditSourceState();
    const first = await state.claimEvent('source', 'evt_a');
    await state.markEmitted('source', 'evt_a', first.sequence, digest('a'));
    // A redelivery before the receipt reuses the pending claim.
    await expect(state.claimEvent('source', 'evt_a')).resolves.toEqual(first);

    const second = await state.claimEvent('source', 'evt_b');
    await state.markEmitted('source', 'evt_b', second.sequence, digest('b'));
    await state.markReceipted('source', first.sequence, digest('1'));
    await state.markReceipted('source', second.sequence, digest('2'));
    // ...and so does one after later events were receipted.
    await expect(state.claimEvent('source', 'evt_a')).resolves.toEqual(first);
    await expect(state.getState('source')).resolves.toEqual({
      sourceId: 'source', highestEmitted: '2', highestReceipted: '2', pendingSequences: [],
    });
  });

  it('releases only the latest claim that was never emitted', async () => {
    const state = new MemoryAuditSourceState();
    const emitted = await state.claimEvent('source', 'evt_emitted');
    await state.markEmitted('source', 'evt_emitted', emitted.sequence, digest('a'));
    // An emitted claim may be in flight, so it is never released.
    await state.abandonClaim('source', 'evt_emitted', emitted.sequence);
    // Unknown IDs and a sequence that is not the claim's are ignored.
    await state.abandonClaim('source', 'evt_unknown', '1');
    await state.abandonClaim('source', 'evt_emitted', '2');

    const released = await state.claimEvent('source', 'evt_released');
    expect(released).toEqual({ sequence: '2', previousSourceEventDigest: digest('a') });
    await state.abandonClaim('source', 'evt_released', released.sequence);
    const reused = await state.claimEvent('source', 'evt_reused');
    expect(reused).toEqual(released);

    // Once a later claim exists, an earlier unemitted one stays a visible gap.
    const later = await state.claimEvent('source', 'evt_later');
    await state.abandonClaim('source', 'evt_reused', reused.sequence);
    await state.markReceipted('source', later.sequence, digest('3'));
    await expect(state.getState('source')).resolves.toEqual({
      sourceId: 'source', highestEmitted: '3', highestReceipted: '0',
      pendingSequences: ['1', '2'],
    });
  });
});
