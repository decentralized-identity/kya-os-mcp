/**
 * A graph built without `statusEntryOwners` cannot tell which delegation an entry was allocated to.
 * It refuses an entry another registered delegation holds, when its storage provider can look one
 * up; a revocation always sets the entry, and reports the delegations outside the subtree that
 * hold it too; a restore never clears an entry another delegation holds. What it cannot refuse, a
 * pre-claimed index and a removed delegation's entry, is pinned here as documented, with the
 * warning that says so.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import {
  ENTRY,
  REGISTRATION_REFUSED,
  forgetWarning,
  leftUnchanged,
  operator,
  refusal,
} from './helpers/status-entry-operator.js';

const UNWIRED_WARNING =
  '[kya-os] A delegation was registered with a status list entry by a delegation graph built without ' +
  'statusEntryOwners, so the graph cannot tell which delegation an entry was allocated to. It refuses an entry ' +
  'another registered delegation holds, when its storage provider implements getNodeIdsByStatusEntry, but it ' +
  'cannot refuse an entry allocated and not yet registered, nor the entry of a delegation removed from the ' +
  'graph: a re-delegation that carries such an entry is registered, and revoking or restoring it changes that ' +
  'entry. Allocate each entry with allocateStatusEntry(purpose, { delegationId }) and pass that ' +
  'StatusList2021Manager to the graph as statusEntryOwners, which refuses both.';

describe('a graph built without statusEntryOwners', () => {
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    forgetWarning();
    warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => {
    warn.mockRestore();
    forgetWarning();
  });

  it('warns once, in fixed words, when it first registers a delegation with a status list entry', async () => {
    const op = operator();
    await op.graph.registerDelegation(op.params('plain', null));
    expect(warn).not.toHaveBeenCalled();

    await op.issue('root');
    await op.issue('child\n[kya-os] all clear', 'root');
    expect(warn.mock.calls).toEqual([[UNWIRED_WARNING]]);
  });

  it("refuses a child that carries its parent's entry, one bit for a subtree, in the words the wired graph uses", async () => {
    const op = operator();
    await op.issue('root');

    expect(await refusal(op.carrying('child', 'root', op.entry('root')))).toEqual({
      code: 'delegation_malformed',
      message: REGISTRATION_REFUSED('child'),
    });
    expect(await op.graph.getNode('child')).toBeNull();
  });

  for (const store of ['memory', 'lookup'] as const) {
    it(`lets one of two concurrent registrations carrying one entry through (${store} store)`, async () => {
      const op = operator({ store });
      await op.issue('root');
      const entry = await op.allocate('shared');

      const settled = await Promise.allSettled([
        op.carrying('a', 'root', entry),
        op.carrying('b', 'root', entry),
      ]);
      expect(settled.map((result) => result.status).sort()).toEqual(['fulfilled', 'rejected']);
    });
  }

  it("sets the victim's own entry when the victim is revoked, and reports the squatter that holds it too", async () => {
    const op = operator();
    await op.issue('root');
    await op.issue('victim', 'root');
    await op.carryingBefore('squatter', 'root', op.entry('victim'));

    const events = await op.cascade.revokeDelegation('victim');

    expect(events).toEqual([expect.objectContaining({ delegationId: 'victim', statusEntrySharedWith: ['squatter'] })]);
    expect(await op.bits()).toEqual({ root: false, victim: true });
  });

  it("sets the entry when a squatter is revoked, revoking the victim too, the safe way, and says so", async () => {
    const op = operator();
    await op.issue('root');
    await op.issue('victim', 'root');
    await op.carryingBefore('squatter', 'root', op.entry('victim'));

    const events = await op.cascade.revokeDelegation('squatter');

    expect(events).toEqual([expect.objectContaining({ delegationId: 'squatter', statusEntrySharedWith: ['victim'] })]);
    expect(await op.bits()).toEqual({ root: false, victim: true });

    // A subtree that holds both reports neither.
    const [rootEvent, ...below] = await op.cascade.revokeDelegation('root');
    expect([rootEvent, ...below].some((event) => 'statusEntrySharedWith' in event)).toBe(false);
  });

  it('never clears an entry another delegation holds: each restore of it is refused, and it stays set', async () => {
    const op = operator();
    await op.issue('root');
    await op.issue('victim', 'root');
    await op.cascade.revokeDelegation('victim');
    await op.carryingBefore('squatter', 'root', op.entry('victim'));

    for (const id of ['squatter', 'victim']) {
      const error = await leftUnchanged(op.cascade.restoreDelegation(id));
      expect(error.unchanged).toEqual([
        { delegationId: id, credentialStatus: op.entry('victim'), reason: 'registered-to-another' },
      ]);
    }
    expect(await op.bits()).toEqual({ root: false, victim: true });
    expect((await op.graph.getNode('victim'))?.revoked).toBe(true);

    // Once the squatter is removed, the victim's entry is its own again.
    await op.graph.removeDelegation('squatter');
    await op.cascade.restoreDelegation('victim');
    expect(await op.bits()).toEqual({ root: false, victim: false });
  });

  it('cannot refuse a pre-claimed index, as documented: the delegation it is allocated to is then refused', async () => {
    const op = operator();
    await op.issue('root');
    const next = Number(op.entry('root').statusListIndex) + 1;
    await op.carrying('squatter', 'root', { ...op.entry('root'), id: ENTRY(next), statusListIndex: String(next) });

    const victim = await op.allocate('victim');
    expect(victim.statusListIndex).toBe(String(next));
    expect((await refusal(op.graph.registerDelegation(op.params('victim', null, victim)))).message).toBe(
      REGISTRATION_REFUSED('victim'),
    );

    await op.cascade.revokeDelegation('squatter');
    expect(await op.bits()).toEqual({ root: false, victim: true });
  });

  it("cannot refuse a removed delegation's entry, as documented: restoring the new holder clears it", async () => {
    const op = operator();
    await op.issue('root');
    await op.issue('victim', 'root');
    await op.cascade.revokeDelegation('victim');
    await op.graph.removeDelegation('victim');

    await op.carrying('squatter', 'root', op.entry('victim'));
    await op.cascade.restoreDelegation('squatter');
    expect(await op.bits()).toEqual({ root: false, victim: false });
  });

  it('cannot refuse even a shared entry over a provider that cannot look entries up, as documented', async () => {
    const op = operator({ store: 'base' });
    await op.issue('root');
    await op.carrying('child', 'root', op.entry('root'));
    expect(warn.mock.calls).toEqual([[UNWIRED_WARNING]]);

    await op.cascade.revokeDelegation('child');
    expect(await op.bits()).toEqual({ root: true });
    await op.cascade.restoreDelegation('child');
    expect(await op.bits()).toEqual({ root: false });
  });

  it('applies one rule half wired, when entries record owners the graph does not read: it warns at registration', async () => {
    const op = operator({ owners: 'half-wired' });
    await op.issue('root');
    expect(warn.mock.calls).toEqual([[UNWIRED_WARNING]]);

    // The owners recorded are not read, by the graph or the cascade: both apply the rule above.
    expect((await refusal(op.carrying('child', 'root', op.entry('root')))).message).toBe(REGISTRATION_REFUSED('child'));
    const next = Number(op.entry('root').statusListIndex) + 1;
    await op.carrying('squatter', 'root', { ...op.entry('root'), id: ENTRY(next), statusListIndex: String(next) });
    await op.allocate('victim');

    await op.cascade.revokeDelegation('squatter');
    expect(await op.bits()).toEqual({ root: false, victim: true });
  });
});
