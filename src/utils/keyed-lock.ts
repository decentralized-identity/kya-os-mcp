/**
 * Keyed Lock
 *
 * Runs tasks one at a time for each key, within one process.
 */

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

  /** Run `task` once every task given `key` before it has settled, and settle as it does. */
  async run<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const done = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => done);
    this.tails.set(key, tail);
    await previous;
    try {
      return await task();
    } finally {
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
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
