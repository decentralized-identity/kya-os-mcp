/**
 * `answerWithinDeadline`, the one deadline every dependency a verifier waits on is called under: it
 * passes an answer or a failure through, rejects with a `DeadlineExceededError` that names who did
 * not answer once 5 seconds have passed, and leaves no timer behind either way.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { answerWithinDeadline, DeadlineExceededError } from '../deadline.js';
import { OUTBOUND_READ_TIMEOUT_MS } from '../outbound-read-limits.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('answerWithinDeadline', () => {
  it('passes on what the dependency answers, at once or later, and what it throws', async () => {
    vi.useFakeTimers();
    expect(await answerWithinDeadline('the resolver', () => 7)).toBe(7);
    expect(await answerWithinDeadline('the resolver', async () => 'late')).toBe('late');
    await expect(answerWithinDeadline('the resolver', async () => { throw new TypeError('offline'); })).rejects.toThrow(TypeError);
    await expect(answerWithinDeadline('the resolver', () => { throw new RangeError('at once'); })).rejects.toThrow(RangeError);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('rejects at 5,000 ms, and no sooner, naming who did not answer', async () => {
    expect(OUTBOUND_READ_TIMEOUT_MS).toBe(5_000);
    vi.useFakeTimers();
    let outcome: unknown;
    const settled = answerWithinDeadline('the resolver', () => new Promise<never>(() => undefined)).catch((error: unknown) => {
      outcome = error;
    });
    await vi.advanceTimersByTimeAsync(OUTBOUND_READ_TIMEOUT_MS - 1);
    expect(outcome).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await settled;
    expect(outcome).toBeInstanceOf(DeadlineExceededError);
    expect((outcome as Error).message).toBe('the resolver did not answer within 5 seconds');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('drops an answer that comes after the deadline, and a failure that does, unhandled by no one', async () => {
    vi.useFakeTimers();
    const late = new Promise<string>((_, reject) => setTimeout(() => reject(new Error('too late')), OUTBOUND_READ_TIMEOUT_MS + 1));
    const settled = answerWithinDeadline('the resolver', () => late).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(OUTBOUND_READ_TIMEOUT_MS + 1);
    expect(await settled).toBeInstanceOf(DeadlineExceededError);
  });
});
