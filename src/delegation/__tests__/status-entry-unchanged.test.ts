/**
 * When cascading revocation leaves a status list entry unchanged, it says so to the operator: a
 * `StatusEntryUnchangedError`, never a `RefusalError` a host could pass to a presenter, carrying
 * what was done and each entry left unchanged, with every value a presenter could have written
 * quoted. A revocation finishes the subtree first, a dry run reaches the same answer without
 * changing anything, and an entry that names the manager's list by another spelling is left alone.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../../logging/index.js';
import { RefusalError } from '../../utils/refusal.js';
import type { RevocationEvent } from '../cascading-revocation.js';
import { forgetWarning, leftUnchanged, operator } from './helpers/status-entry-operator.js';

/** An event without its timestamp, which differs from run to run. */
const withoutTime = ({ delegationId, isRoot, parentId, reason }: RevocationEvent) => ({ delegationId, isRoot, parentId, reason });

const SPELLINGS = ['https://STATUS.example:443/revocation/v1', 'https://status.example/revocation/./v1'];

describe('an entry left unchanged', () => {
  beforeEach(() => {
    forgetWarning();
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    forgetWarning();
  });

  for (const list of SPELLINGS) {
    it(`is never set or cleared for an entry that spells the list as ${list}, over a store that normalises it`, async () => {
      const op = operator({ normalising: true });
      await op.issue('root');
      await op.issue('victim', 'root');
      const index = op.entry('victim').statusListIndex;
      await op.carrying('squatter', 'root', { ...op.entry('victim'), statusListCredential: list, id: `${list}#${index}` });

      const revoked = await leftUnchanged(op.cascade.revokeDelegation('squatter'));
      expect(revoked.unchanged).toEqual([
        {
          delegationId: 'squatter',
          credentialStatus: expect.objectContaining({ statusListCredential: list }),
          reason: 'refused-by-status-list',
          cause: expect.any(RefusalError),
        },
      ]);
      expect((revoked.unchanged[0]?.cause as RefusalError).code).toBe('delegation_malformed');
      expect((await op.graph.getNode('squatter'))?.revoked).toBe(true);
      expect(await op.bits()).toEqual({ root: false, victim: false });

      await op.cascade.revokeDelegation('victim');
      const restored = await leftUnchanged(op.cascade.restoreDelegation('squatter'));
      expect(restored.unchanged.map((entry) => entry.reason)).toEqual(['refused-by-status-list']);
      expect(await op.bits()).toEqual({ root: false, victim: true });
    });
  }

  it('is reported once the whole subtree is revoked, with the events of every delegation in it', async () => {
    const op = operator({ normalising: true });
    await op.issue('root');
    await op.issue('first', 'root');
    const index = op.entry('first').statusListIndex;
    await op.carrying('respelled', 'root', { ...op.entry('first'), statusListCredential: SPELLINGS[0]!, id: `${SPELLINGS[0]}#${index}` });
    await op.issue('last', 'root');
    const hook = vi.fn();

    const error = await leftUnchanged(op.cascade.revokeDelegation('root', { onRevoke: hook }));

    expect(error.events.map((event) => event.delegationId)).toEqual(['root', 'first', 'respelled', 'last']);
    expect(hook).toHaveBeenCalledTimes(4);
    expect(error.unchanged.map((entry) => entry.delegationId)).toEqual(['respelled']);
    expect(await op.bits()).toEqual({ root: true, first: true, last: true });
    expect((await op.graph.getNode('last'))?.revoked).toBe(true);
  });

  it('is reached by a dry run as by the real one, which changes nothing', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    await op.issue('victim');
    await op.carryingBefore('squatter', 'root', op.entry('victim'));

    const dry = await leftUnchanged(op.cascade.revokeDelegation('root', { dryRun: true }));
    expect((await op.graph.getNode('root'))?.revoked).toBeUndefined();
    expect((await op.graph.getNode('squatter'))?.revoked).toBeUndefined();
    expect(await op.bits()).toEqual({ root: false, victim: false });

    const real = await leftUnchanged(op.cascade.revokeDelegation('root'));
    expect(dry.message).toBe(real.message);
    expect(dry.unchanged).toEqual(real.unchanged);
    expect(dry.events.map(withoutTime)).toEqual(real.events.map(withoutTime));
    expect(await op.bits()).toEqual({ root: true, victim: false });
  });

  it('reports a shared entry in a dry run as the real run does', async () => {
    const op = operator();
    await op.issue('root');
    await op.issue('victim', 'root');
    await op.carryingBefore('squatter', 'root', op.entry('victim'));

    const dry = await op.cascade.revokeDelegation('victim', { dryRun: true });
    expect(dry).toEqual([expect.objectContaining({ delegationId: 'victim', statusEntrySharedWith: ['squatter'] })]);
    expect(await op.bits()).toEqual({ root: false, victim: false });
  });

  it('is named in words that quote each id and entry, so none can break the line or forge a log entry', async () => {
    const op = operator({ owners: 'wired' });
    const id = 'squatter\n[kya-os] all clear';
    await op.issue('root');
    await op.issue('victim');
    await op.carryingBefore(id, 'root', op.entry('victim'));
    const key = `${op.entry('victim').statusListCredential}#${op.entry('victim').statusListIndex}`;

    const revoked = await leftUnchanged(op.cascade.revokeDelegation(id));
    expect(revoked.name).toBe('StatusEntryUnchangedError');
    expect(revoked.message).toBe(
      'Revoking delegation "squatter\\n[kya-os] all clear" left one status list entry unchanged, so a verifier that ' +
        `reads only the status list does not see that revocation: entry "${key}" of delegation ` +
        '"squatter\\n[kya-os] all clear", since it was allocated to a delegation outside the subtree, and setting it ' +
        'would revoke that delegation too. Each such delegation is revoked in the delegation graph; issue it again ' +
        'with an entry allocated for it.',
    );

    const restored = await leftUnchanged(op.cascade.restoreDelegation(id));
    expect(restored.message).toBe(
      `Delegation "squatter\\n[kya-os] all clear" was not restored: its status list entry "${key}" was left ` +
        'unchanged, since it was allocated to another delegation, and clearing it would restore that delegation ' +
        'too. It stays revoked; issue the delegation again with an entry allocated for it.',
    );
    for (const message of [revoked.message, restored.message]) {
      expect(message).not.toContain('\n');
    }
  });

  it('lists at most five entries in its message, and every one in unchanged', async () => {
    const op = operator({ owners: 'wired' });
    await op.issue('root');
    await op.issue('victim');
    for (let n = 0; n < 7; n++) {
      await op.carryingBefore(`s${n}`, 'root', op.entry('victim'));
    }

    const error = await leftUnchanged(op.cascade.revokeDelegation('root'));

    expect(error.unchanged).toHaveLength(7);
    expect(error.message).toContain('left 7 status list entries unchanged');
    expect(error.message).toContain('does not see those revocations');
    expect(error.message).toContain('of delegation "s4", since');
    expect(error.message).not.toContain('"s5"');
    expect(error.message).toContain("; and 2 more, each in the error's unchanged entries.");
  });
});
