/**
 * Test helpers for the deadline a verifier gives each dependency it waits on (`utils/deadline.ts`):
 * a dependency that never answers, the clock walked up to a deadline, and the values the
 * `dependencyTimeoutMs` option refuses.
 */
import { expect, vi } from 'vitest';

/** The runtime's `setImmediate`, kept from before any test fakes the timers. */
const realSetImmediate = setImmediate;

/**
 * Let work the fake clock does not drive finish: a signature check runs on the runtime's own
 * threads and completes over a few turns of the real event loop.
 */
async function realWorkDone(): Promise<void> {
  for (let turn = 0; turn < 20; turn += 1) await new Promise<void>((resolve) => realSetImmediate(resolve));
}

/** A dependency that never answers. */
export type Hang = <A>() => Promise<A>;

/**
 * What `work` settles to when the dependency it is handed, one that never answers, has been waited
 * on for `ms`: it must still be pending 1 ms before, settle at `ms`, and leave no timer behind. The
 * clock is faked, and moves only once the dependency has been asked, so any real work before it,
 * such as a signature check, has finished; real work after an early refusal is given time to
 * finish too, so a verifier that gave up before `ms` is seen to have settled. The caller restores
 * real timers.
 */
export async function settledAt<T>(ms: number, work: (hang: Hang) => Promise<T>): Promise<T> {
  vi.useFakeTimers();
  let asked!: () => void;
  const reached = new Promise<void>((resolve) => {
    asked = resolve;
  });
  let settled: { value: T } | undefined;
  const done = work(() => {
    asked();
    return new Promise<never>(() => undefined);
  }).then((value) => {
    settled = { value };
  });
  await reached;
  await vi.advanceTimersByTimeAsync(ms - 1);
  await realWorkDone();
  expect(settled).toBeUndefined();
  await vi.advanceTimersByTimeAsync(1);
  await done;
  expect(vi.getTimerCount()).toBe(0);
  return settled!.value;
}

/**
 * What `work` settles to and the milliseconds of the faked clock it took, for work that waits many
 * times: the clock is walked `stepMs` at a time whenever a timer is waiting, and real work that no
 * timer waits on, such as hashing, is given turns in between, during which the clock stands still.
 * Every dependency the work waits on under a deadline must answer by a faked timer, or at once: a
 * real signature check under one would have the clock walked while it ran. The caller restores real
 * timers.
 */
export async function settledAfter<T>(work: () => Promise<T>, stepMs = 1_000): Promise<{ value: T; ms: number }> {
  vi.useFakeTimers();
  let settled: { value: T } | undefined;
  const done = work().then((value) => {
    settled = { value };
  });
  let ms = 0;
  for (let turn = 0; settled === undefined; turn += 1) {
    if (turn > 10_000) throw new Error('settledAfter: the work never settled');
    await realWorkDone();
    if (settled !== undefined || vi.getTimerCount() === 0) continue;
    await vi.advanceTimersByTimeAsync(stepMs);
    ms += stepMs;
  }
  await done;
  return { value: settled.value, ms };
}

/**
 * The two deadlines every wait is tested under: the default, with the option left out, and one the
 * host raised. Each row is a label, the option to spread into the verifier's options, the
 * milliseconds waited, and how a reason states them.
 */
export const DEADLINES: [string, { dependencyTimeoutMs?: number }, number, string][] = [
  ['by default', {}, 5_000, '5 seconds'],
  ['with dependencyTimeoutMs raised to 7,500', { dependencyTimeoutMs: 7_500 }, 7_500, '7500 ms'],
];

/** Values `dependencyTimeoutMs` refuses, each with how the `TypeError` describes it. */
export const REFUSED_TIMEOUTS: [string, unknown, string][] = [
  ['0', 0, '0'],
  ['a negative number', -1, '-1'],
  ['NaN', Number.NaN, 'NaN'],
  ['Infinity', Number.POSITIVE_INFINITY, 'Infinity'],
  ['a number over the longest timer', 2_147_483_648, '2147483648'],
  ['a string', '5000', 'a value "5000"'],
  ['null', null, 'a value of type null'],
];

/** The `TypeError` `option` at `path` throws for a refused value described as `got`. */
export function timeoutTypeError(got: string, path = '', option = 'dependencyTimeoutMs'): TypeError {
  return new TypeError(
    `[kya-os] ${path}${option} must be a number of milliseconds greater than 0 and at most 2147483647 (got ${got})`,
  );
}
