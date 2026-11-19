/**
 * Keyed Lock
 *
 * Runs tasks one at a time for each key, within one process.
 */

import { startDeadline } from './deadline.js';

/**
 * The longest one wait of a writer may be, in milliseconds: for its turn at a key, or between two
 * tries of a write a conditional store refused. A writer stuck behind a store that never answers
 * so gives up, and says so, rather than wait forever.
 */
export const LONGEST_WAIT_MS = 10_000;

/** How long a task waits for its turn, and what it rejects with when its turn has not come by then. */
export interface TurnWait {
  /** The longest the task waits for its turn, in milliseconds. */
  readonly ms: number;
  /** The error the task rejects with when its turn has not come in that time. */
  readonly expired: () => Error;
}

/**
 * Runs the tasks given one key one at a time, in the order they were given, while tasks under
 * other keys run alongside them. A task waits until every earlier task of its key has settled,
 * whether it resolved or threw, so one that fails holds up none after it, and its own result or
 * error reaches its caller. A task must not wait on a later task of its own key, which would
 * wait on it in turn, so neither would ever run to its end.
 */
export class KeyedLock {
  /** For each key with a task running or waiting, a promise that settles once the last of them has. */
  private readonly tails = new Map<string, Promise<void>>();

  /**
   * Run `task` once every task given `key` before it has settled, and settle as it does. With
   * `wait`, a task whose turn has not come within `wait.ms` never runs: this rejects with
   * `wait.expired()`, and the tasks given `key` after it wait only for those before it.
   */
  async run<T>(key: string, task: () => Promise<T>, wait?: TurnWait): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const done = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => done);
    this.tails.set(key, tail);
    const forget = (): void => {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    };
    try {
      await (wait === undefined ? previous : turnWithin(previous, wait));
    } catch (error) {
      release();
      void tail.then(forget);
      throw error;
    }
    try {
      return await task();
    } finally {
      release();
      forget();
    }
  }
}

/**
 * Wait for `turn`, which never rejects, for at most `wait.ms`. The deadline's own rejection is the
 * only one it can see, so it rejects with `wait.expired()` in its stead.
 */
async function turnWithin(turn: Promise<void>, wait: TurnWait): Promise<void> {
  const deadline = startDeadline('the turn did not come', wait.ms);
  try {
    await deadline.within(turn);
  } catch {
    throw wait.expired();
  } finally {
    deadline.clear();
  }
}

/** The lock of each object {@link keyedLockOf} was asked about. */
const LOCKS = new WeakMap<object, KeyedLock>();

/**
 * The one {@link KeyedLock} of `owner`, made the first time it is asked for, so every caller that
 * holds the same object, as every manager built over one store does, takes its turns in one lock.
 * Callers over two objects, two copies of this package among them, share nothing.
 */
export function keyedLockOf(owner: object): KeyedLock {
  let lock = LOCKS.get(owner);
  if (lock === undefined) {
    lock = new KeyedLock();
    LOCKS.set(owner, lock);
  }
  return lock;
}
