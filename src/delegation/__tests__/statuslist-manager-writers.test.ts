/**
 * Several `StatusList2021Manager`s over one status-list store, as the replicas of one issuing
 * service run them, or a process that builds a manager per request. Each manager serialises only
 * its own writes, so these tests interleave the writes of different managers and check that every
 * change a manager reported is on the list the store keeps, signed over what the list says.
 */

import { describe, expect, it } from 'vitest';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import type { VCSigningFunction } from '../vc-issuer.js';
import { allocated, proofOver, replica, signedOverItself } from './helpers/status-list-writers.js';

/**
 * A signer that holds every signature until `writers` are waiting, and none after that, so each of
 * `writers` managers has read the list before any of them writes it.
 */
function signerHeldFor(writers: number): VCSigningFunction {
  let waiting = 0;
  let release!: () => void;
  const everyoneRead = new Promise<void>((resolve) => {
    release = resolve;
  });
  return async (canonical) => {
    if (++waiting === writers) release();
    await everyoneRead;
    return proofOver(canonical);
  };
}

describe('StatusList2021Manager writers over one store', () => {
  it('keeps both revocations when two managers revoke on one list at once', async () => {
    const storage = new MemoryStatusListStorage();
    const [first, second] = await allocated(storage, 2);
    const sign = signerHeldFor(2);

    await Promise.all([
      replica(storage, { sign }).updateStatus(first!, true),
      replica(storage, { sign }).updateStatus(second!, true),
    ]);

    const verifier = replica(storage);
    expect({ first: await verifier.checkStatus(first!), second: await verifier.checkStatus(second!) })
      .toEqual({ first: true, second: true });
    expect(await signedOverItself(storage, first!.statusListCredential)).toBe(true);
  });

  it('keeps every change, revocations and a restoration, when five managers write one list at once', async () => {
    const storage = new MemoryStatusListStorage();
    const entries = await allocated(storage, 5);
    await replica(storage).updateStatus(entries[0]!, true);
    const sign = signerHeldFor(5);

    await Promise.all([
      replica(storage, { sign }).updateStatus(entries[0]!, false),
      ...entries.slice(1).map((entry) => replica(storage, { sign }).updateStatus(entry, true)),
    ]);

    expect(await replica(storage).getRevokedIndices(entries[0]!.statusListCredential)).toEqual([1, 2, 3, 4]);
    expect(await signedOverItself(storage, entries[0]!.statusListCredential)).toBe(true);
  });

  it('creates a list once when two managers create it at once', async () => {
    const storage = new MemoryStatusListStorage();
    const sign = signerHeldFor(2);

    const [first, second] = await Promise.all([
      replica(storage, { sign }).allocateStatusEntry('revocation'),
      replica(storage, { sign }).allocateStatusEntry('revocation'),
    ]);

    expect(first.statusListCredential).toBe(second.statusListCredential);
    expect(await storage.getStatusListVersionCount(first.statusListCredential)).toBe(1);
  });

  it('does not let a creation that lost the race replace a list that has since recorded a revocation', async () => {
    const storage = new MemoryStatusListStorage();
    let signing!: () => void;
    const lateCreatorSigns = new Promise<void>((resolve) => {
      signing = resolve;
    });
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const lateCreator = replica(storage, {
      sign: async (canonical) => {
        signing();
        await held;
        return proofOver(canonical);
      },
    });

    // The late creator has read no list and is signing a fresh, empty one.
    const lateEntry = lateCreator.allocateStatusEntry('revocation');
    await lateCreatorSigns;
    const other = replica(storage);
    const entry = await other.allocateStatusEntry('revocation');
    await other.updateStatus(entry, true);

    release();
    await lateEntry;
    expect(await other.checkStatus(entry)).toBe(true);
    expect(await storage.getStatusListVersionCount(entry.statusListCredential)).toBe(2);
  });
});
