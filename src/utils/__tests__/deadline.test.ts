/**
 * `answerWithinDeadline`, the one deadline every dependency a verifier waits on is called under: it
 * passes an answer or a failure through, rejects with a `DeadlineExceededError` that names who did
 * not answer and in what time once the deadline has passed, and leaves no timer behind either way.
 * `dependencyTimeout` reads the option a host sets that deadline with: 5 seconds when it is left
 * out, and a `TypeError` for anything but a number of milliseconds a timer can hold. A time budget
 * is the time a whole check has: each wait draws on it, so waits that each end in time cannot
 * together hold the check open, however many there are. `totalTimeout` reads its option, 30
 * seconds when left out.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { REFUSED_TIMEOUTS, timeoutTypeError } from '../../__tests__/utils/deadlines.js';
import {
  answerWithinDeadline, DeadlineExceededError, DEFAULT_TOTAL_TIMEOUT_MS, dependencyTimeout, dependencyTimeoutRefusal, describeTimeout,
  MAX_DEPENDENCY_TIMEOUT_MS, startDeadline, startTimeBudget, totalTimeout, totalTimeoutRefusal,
} from '../deadline.js';
import { OUTBOUND_READ_TIMEOUT_MS } from '../outbound-read-limits.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('answerWithinDeadline', () => {
  it('passes on what the dependency answers, at once or later, and what it throws', async () => {
    vi.useFakeTimers();
    expect(await answerWithinDeadline('the resolver', () => 7, 5_000)).toBe(7);
    expect(await answerWithinDeadline('the resolver', async () => 'late', 5_000)).toBe('late');
    await expect(answerWithinDeadline('the resolver', async () => { throw new TypeError('offline'); }, 5_000)).rejects.toThrow(TypeError);
    await expect(answerWithinDeadline('the resolver', () => { throw new RangeError('at once'); }, 5_000)).rejects.toThrow(RangeError);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    [5_000, 'the resolver did not answer within 5 seconds'],
    [7_500, 'the resolver did not answer within 7500 ms'],
    [1_000, 'the resolver did not answer within 1 second'],
    [1, 'the resolver did not answer within 1 ms'],
  ])('rejects at %d ms, and no sooner, naming who did not answer and in what time', async (timeoutMs, message) => {
    vi.useFakeTimers();
    let outcome: unknown;
    const settled = answerWithinDeadline('the resolver', () => new Promise<never>(() => undefined), timeoutMs).catch((error: unknown) => {
      outcome = error;
    });
    await vi.advanceTimersByTimeAsync(timeoutMs - 1);
    expect(outcome).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await settled;
    expect(outcome).toBeInstanceOf(DeadlineExceededError);
    expect((outcome as Error).message).toBe(message);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('drops an answer that comes after the deadline, and a failure that does, unhandled by no one', async () => {
    vi.useFakeTimers();
    const late = new Promise<string>((_, reject) => setTimeout(() => reject(new Error('too late')), 5_001));
    const settled = answerWithinDeadline('the resolver', () => late, 5_000).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await settled).toBeInstanceOf(DeadlineExceededError);
  });
});

describe('startDeadline', () => {
  it('rejects a step with its message once its own length has passed, and no sooner', async () => {
    vi.useFakeTimers();
    const deadline = startDeadline('too slow', 9_000);
    let outcome: unknown;
    void deadline.within(new Promise<never>(() => undefined)).catch((error: unknown) => {
      outcome = error;
    });
    await vi.advanceTimersByTimeAsync(8_999);
    expect(outcome).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    expect(outcome).toEqual(new DeadlineExceededError('too slow'));
  });
});

describe('dependencyTimeout', () => {
  it('is 5,000 ms when the option is left out', () => {
    expect(OUTBOUND_READ_TIMEOUT_MS).toBe(5_000);
    expect(dependencyTimeout(undefined)).toBe(5_000);
  });

  it('is the option, for a number of milliseconds greater than 0 and at most the longest timer', () => {
    expect(MAX_DEPENDENCY_TIMEOUT_MS).toBe(2 ** 31 - 1);
    for (const value of [1, 0.5, 5_000, 30_000, MAX_DEPENDENCY_TIMEOUT_MS]) {
      expect(dependencyTimeout(value)).toBe(value);
      expect(dependencyTimeoutRefusal(value)).toBeUndefined();
    }
  });

  it.each(REFUSED_TIMEOUTS)('throws a TypeError that names the option for %s', (_label, value, got) => {
    expect(() => dependencyTimeout(value)).toThrow(timeoutTypeError(got));
    expect(() => dependencyTimeout(value, 'delegation.')).toThrow(timeoutTypeError(got, 'delegation.'));
    expect(dependencyTimeoutRefusal(value)).toBe(timeoutTypeError(got).message.slice('[kya-os] '.length));
  });

  it('refuses a value that is not a number without converting it', () => {
    const boxed = { valueOf: () => 5_000, toString: () => { throw new Error('converted'); } };
    for (const [value, got] of [[boxed, 'a value of type object'], [true, 'a value of type boolean'], [[5_000], 'a value of type array']] as const) {
      expect(() => dependencyTimeout(value)).toThrow(timeoutTypeError(got));
    }
  });
});

describe('a time budget', () => {
  const hang = () => new Promise<never>(() => undefined);
  /** What a wait that never gets its answer rejects with, once `ms` have passed and no sooner. */
  const rejectedAt = async (ms: number, wait: Promise<unknown>): Promise<unknown> => {
    let outcome: unknown;
    const settled = wait.catch((error: unknown) => {
      outcome = error;
    });
    await vi.advanceTimersByTimeAsync(ms - 1);
    expect(outcome).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await settled;
    return outcome;
  };

  it('gives a wait its own deadline while the check has more time left than that', async () => {
    vi.useFakeTimers();
    const budget = startTimeBudget('the delegation check', 30_000);
    expect(await answerWithinDeadline('the resolver', async () => 'in time', 5_000, budget)).toBe('in time');
    expect(await rejectedAt(5_000, answerWithinDeadline('the resolver', hang, 5_000, budget))).toEqual(
      new DeadlineExceededError('the resolver did not answer within 5 seconds'),
    );
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ends a wait when the check runs out of time, and says the check did, not the dependency', async () => {
    vi.useFakeTimers();
    const budget = startTimeBudget('the delegation check', 12_000);
    await rejectedAt(5_000, answerWithinDeadline('the resolver', hang, 5_000, budget));
    await rejectedAt(5_000, answerWithinDeadline('the resolver', hang, 5_000, budget));
    expect(budget.left()).toBe(2_000);
    expect(await rejectedAt(2_000, answerWithinDeadline('the resolver', hang, 5_000, budget))).toEqual(
      new DeadlineExceededError('the delegation check did not finish within 12 seconds'),
    );
    expect(vi.getTimerCount()).toBe(0);
  });

  it('asks nothing once the time is spent, however short the wait would have been', async () => {
    vi.useFakeTimers();
    const budget = startTimeBudget('the delegation check', 1_000);
    await vi.advanceTimersByTimeAsync(1_000);
    const ask = vi.fn(async () => 'answered');
    await expect(answerWithinDeadline('the resolver', ask, 1, budget)).rejects.toEqual(
      new DeadlineExceededError('the delegation check did not finish within 1 second'),
    );
    expect(ask).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('counts the time of waits that were answered, so many quick answers still add up', async () => {
    vi.useFakeTimers();
    const budget = startTimeBudget('the delegation check', 1_000);
    const answerIn = (ms: number) => () => new Promise<string>((resolve) => setTimeout(() => resolve('answered'), ms));
    let answered = 0;
    const walk = (async () => {
      for (;;) {
        await answerWithinDeadline('the resolver', answerIn(300), 5_000, budget);
        answered += 1;
      }
    })().catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await walk).toEqual(new DeadlineExceededError('the delegation check did not finish within 1 second'));
    expect(answered).toBe(3);
  });
});

describe('totalTimeout', () => {
  it('is 30,000 ms when the option is left out', () => {
    expect(DEFAULT_TOTAL_TIMEOUT_MS).toBe(30_000);
    expect(totalTimeout(undefined)).toBe(30_000);
  });

  it('is the option, for a number of milliseconds greater than 0 and at most the longest timer', () => {
    for (const value of [1, 0.5, 5_000, 120_000, MAX_DEPENDENCY_TIMEOUT_MS]) {
      expect(totalTimeout(value)).toBe(value);
      expect(totalTimeoutRefusal(value)).toBeUndefined();
    }
  });

  it.each(REFUSED_TIMEOUTS)('throws a TypeError that names the option for %s', (_label, value, got) => {
    expect(() => totalTimeout(value)).toThrow(timeoutTypeError(got, '', 'totalTimeoutMs'));
    expect(() => totalTimeout(value, 'delegation.')).toThrow(timeoutTypeError(got, 'delegation.', 'totalTimeoutMs'));
    expect(totalTimeoutRefusal(value)).toBe(timeoutTypeError(got, '', 'totalTimeoutMs').message.slice('[kya-os] '.length));
  });
});

describe('describeTimeout', () => {
  it('states whole seconds as seconds and anything else in milliseconds', () => {
    expect([5_000, 1_000, 12_000, 7_500, 999, 1_001].map(describeTimeout)).toEqual([
      '5 seconds', '1 second', '12 seconds', '7500 ms', '999 ms', '1001 ms',
    ]);
  });
});
