/**
 * A delegation's status list entry is the one the operator allocated for it. The issuer of a
 * re-delegation writes the entry its credential carries, so it can name any entry. When the graph
 * reads the owners the status list manager records (`statusEntryOwners`), it registers a delegation
 * only with an entry allocated to that delegation's id, and cascading revocation sets or clears an
 * entry only for its owner, or for a subtree that holds its owner.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { DelegationGraphManager } from '../delegation-graph.js';
import { MemoryDelegationGraphStorage } from '../storage/memory-graph-storage.js';
import { ENTRY, REGISTRATION_REFUSED, forgetWarning, leftUnchanged, operator, refusal } from './helpers/status-entry-operator.js';

describe('a graph that reads the owners the status list manager records', () => {
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    forgetWarning();
    warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => {
    warn.mockRestore();
    forgetWarning();
  });

  it('registers, revokes and restores each delegation with the entry allocated to it, and warns of nothing', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    await op.issue('child', 'root');
    await op.issue('sibling', 'root');

    const events = await op.cascade.revokeDelegation('child');
    expect(events.map((event) => event.delegationId)).toEqual(['child']);
    expect(events[0]).not.toHaveProperty('statusEntrySharedWith');
    expect(await op.bits()).toEqual({ root: false, child: true, sibling: false });

    await op.cascade.revokeDelegation('root');
    expect(await op.bits()).toEqual({ root: true, child: true, sibling: true });

    await op.cascade.restoreDelegation('sibling');
    expect(await op.bits()).toEqual({ root: true, child: true, sibling: false });
    expect(warn).not.toHaveBeenCalled();
  });

  it("refuses a child that carries its parent's entry, or another's, in words that say neither whose nor whether it is in use", async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    await op.issue('other');

    for (const named of ['root', 'other']) {
      expect(await refusal(op.carrying('child', 'root', op.entry(named)))).toEqual({
        code: 'delegation_malformed',
        message: REGISTRATION_REFUSED('child'),
      });
    }
    expect(await op.graph.getNode('child')).toBeNull();
  });

  it('refuses an entry with no owner record: one allocated without a delegationId, or not allocated yet', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    const unowned = await op.manager.allocateStatusEntry('revocation');
    const notYet = { ...unowned, id: ENTRY(Number(unowned.statusListIndex) + 1), statusListIndex: String(Number(unowned.statusListIndex) + 1) };

    for (const entry of [unowned, notYet]) {
      expect((await refusal(op.carrying('child', 'root', entry))).message).toBe(REGISTRATION_REFUSED('child'));
    }
  });

  it('refuses a pre-claimed index, so the delegation it is later allocated to registers and revokes as its own', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    const next = Number(op.entry('root').statusListIndex) + 1;
    const preClaimed = { ...op.entry('root'), id: ENTRY(next), statusListIndex: String(next) };

    expect((await refusal(op.carrying('squatter', 'root', preClaimed))).message).toBe(REGISTRATION_REFUSED('squatter'));

    await op.issue('victim');
    expect(op.entry('victim').statusListIndex).toBe(String(next));
    await op.cascade.revokeDelegation('victim');
    expect(await op.bits()).toEqual({ root: false, victim: true });
  });

  it('defers to the allocation record over a node stored before entries were checked', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    const next = Number(op.entry('root').statusListIndex) + 1;
    await op.carryingBefore('squatter', 'root', { ...op.entry('root'), id: ENTRY(next), statusListIndex: String(next) });

    // The store holds a node with the index already; the record says whose it is.
    await op.issue('victim');

    const error = await leftUnchanged(op.cascade.revokeDelegation('squatter'));
    expect(error.unchanged).toEqual([
      { delegationId: 'squatter', credentialStatus: expect.objectContaining({ statusListIndex: String(next) }), reason: 'allocated-to-another' },
    ]);
    expect(error.events.map((event) => event.delegationId)).toEqual(['squatter']);
    expect((await op.graph.getNode('squatter'))?.revoked).toBe(true);
    expect(await op.bits()).toEqual({ root: false, victim: false });

    // Revoking the subtree that holds the owner sets it.
    await op.cascade.revokeDelegation('victim');
    expect(await op.bits()).toEqual({ root: false, victim: true });
    const restore = await leftUnchanged(op.cascade.restoreDelegation('squatter'));
    expect(restore.events).toEqual([]);
    expect(restore.unchanged.map((entry) => entry.reason)).toEqual(['allocated-to-another']);
    expect(await op.bits()).toEqual({ root: false, victim: true });
  });

  it("keeps a removed delegation's entry its own, so no other delegation can take it and restore it", async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    await op.issue('victim', 'root');
    await op.cascade.revokeDelegation('victim');
    await op.graph.removeDelegation('victim');

    expect((await refusal(op.carrying('squatter', 'root', op.entry('victim')))).message).toBe(REGISTRATION_REFUSED('squatter'));
    expect(await op.bits()).toEqual({ root: false, victim: true });

    // The delegation the entry was allocated to may be registered again with it.
    await op.carrying('victim', 'root', op.entry('victim'));
  });

  it('lets one of two concurrent registrations carrying one entry through: the one it was allocated to', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    const entry = await op.allocate('owner');

    const [squatter, owner] = await Promise.allSettled([
      op.carrying('squatter', 'root', entry),
      op.carrying('owner', 'root', entry),
    ]);
    expect(squatter.status).toBe('rejected');
    expect(owner.status).toBe('fulfilled');
  });

  it('allocates and registers many delegations concurrently through one manager, each with its own entry', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    const ids = Array.from({ length: 24 }, (_, index) => `d${index}`);

    await Promise.all(ids.map((id) => op.issue(id, 'root')));

    const indexes = new Set(ids.map((id) => op.entry(id).statusListIndex));
    expect(indexes.size).toBe(ids.length);
    await op.cascade.revokeDelegation('d7');
    const bits = await op.bits();
    expect(Object.keys(bits).filter((id) => bits[id])).toEqual(['d7']);
  });

  it("refuses an entry that names one of the manager's lists by another spelling, even over a store that normalises it", async () => {
    const op = operator({ owners: 'wired', normalising: true });
    await op.issue('root');
    await op.issue('victim', 'root');

    for (const list of ['https://STATUS.example:443/revocation/v1', 'https://status.example/revocation/./v1']) {
      const respelled = { ...op.entry('victim'), statusListCredential: list, id: `${list}#${op.entry('victim').statusListIndex}` };
      expect((await refusal(op.carrying('squatter', 'root', respelled))).message).toBe(REGISTRATION_REFUSED('squatter'));
    }
    await op.cascade.revokeDelegation('victim');
    await op.cascade.restoreDelegation('victim');
    expect(await op.bits()).toEqual({ root: false, victim: false });
  });

  it('throws a TypeError for statusEntryOwners without getStatusEntryOwner', () => {
    expect(
      () => new DelegationGraphManager(new MemoryDelegationGraphStorage(), { statusEntryOwners: {} as never }),
    ).toThrow(
      new TypeError(
        'DelegationGraphManager was given statusEntryOwners without a getStatusEntryOwner method: pass the ' +
          'StatusList2021Manager that allocates the entries',
      ),
    );
  });
});
