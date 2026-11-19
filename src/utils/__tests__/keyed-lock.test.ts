/**
 * `KeyedLock` runs the tasks given one key one at a time, in the order they were given, while
 * tasks under other keys run alongside them, and a task that fails holds up none after it.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { KeyedLock, keyedLockOf } from '../keyed-lock.js';

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

describe('KeyedLock: a bounded wait for a turn', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('rejects with the error it names once the wait is over, never runs the task, and holds up none after it', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const lock = new KeyedLock();
    const holderMayEnd = deferred();
    const ran: string[] = [];
    const holder = lock.run('node', async () => {
      ran.push('holder');
      await holderMayEnd.promise;
    });
    const late = lock.run('node', async () => void ran.push('late'), { ms: 1_000, expired: () => new Error('no turn') });
    const after = lock.run('node', async () => void ran.push('after'));
    const lateSettled = late.then(() => 'ran', (error: Error) => error.message);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(await lateSettled).toBe('no turn');
    holderMayEnd.resolve();
    await holder;
    await after;
    expect(ran).toEqual(['holder', 'after']);
  });

  it('runs the task, and clears its timer, when the turn comes in time', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const lock = new KeyedLock();
    const answer = lock.run('node', async () => 'ran', { ms: 1_000, expired: () => new Error('no turn') });
    expect(await answer).toBe('ran');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('forgets a key once a task that gave up and every task before it have settled', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const lock = new KeyedLock();
    const holderMayEnd = deferred();
    const holder = lock.run('node', () => holderMayEnd.promise);
    const late = lock.run('node', async () => undefined, { ms: 10, expired: () => new Error('no turn') });
    late.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(10);
    holderMayEnd.resolve();
    await holder;
    await new Promise((resolve) => setImmediate(resolve));
    expect((lock as unknown as { tails: Map<string, unknown> }).tails.size).toBe(0);
  });
});

describe('keyedLockOf', () => {
  it('gives every caller over one object the same lock, and callers over another object their own', () => {
    const store = {};
    expect(keyedLockOf(store)).toBe(keyedLockOf(store));
    expect(keyedLockOf({})).not.toBe(keyedLockOf(store));
  });
});
