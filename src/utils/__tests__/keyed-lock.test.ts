/**
 * `KeyedLock` runs the tasks given one key one at a time, in the order they were given, while
 * tasks under other keys run alongside them, and a task that fails holds up none after it.
 */

import { describe, expect, it } from 'vitest';
import { KeyedLock } from '../keyed-lock.js';

/** A promise and the function that settles it. */
function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

describe('KeyedLock', () => {
  it('runs the tasks of one key one at a time, in the order they were given', async () => {
    const lock = new KeyedLock();
    const events: string[] = [];
    const firstMayEnd = deferred();

    const first = lock.run('list', async () => {
      events.push('first starts');
      await firstMayEnd.promise;
      events.push('first ends');
      return 1;
    });
    const second = lock.run('list', async () => {
      events.push('second starts');
      return 2;
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(events).toEqual(['first starts']);

    firstMayEnd.resolve();

    expect(await Promise.all([first, second])).toEqual([1, 2]);
    expect(events).toEqual(['first starts', 'first ends', 'second starts']);
  });

  it('runs tasks of other keys alongside', async () => {
    const lock = new KeyedLock();
    const held = deferred();
    const holding = lock.run('one', () => held.promise);

    expect(await lock.run('two', async () => 'ran')).toBe('ran');

    held.resolve();
    await holding;
  });

  it("gives a task's error to its caller, and runs the next task of the key", async () => {
    const lock = new KeyedLock();
    const failing = lock.run('list', async () => {
      throw new Error('store unreachable');
    });
    const thrownAtOnce = lock.run('list', () => {
      throw new Error('thrown before a promise');
    });
    const next = lock.run('list', async () => 'ran');

    await expect(failing).rejects.toThrow('store unreachable');
    await expect(thrownAtOnce).rejects.toThrow('thrown before a promise');
    expect(await next).toBe('ran');
  });
});
