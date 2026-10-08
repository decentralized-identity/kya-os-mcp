import { describe, expect, it } from 'vitest';
import { RunBoundary } from '../src/lib/run-boundary.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

describe('merchant run boundary', () => {
  it('allows independent operations to run concurrently', async () => {
    const boundary = new RunBoundary(), first = deferred(), second = deferred(), finish = deferred();
    const a = boundary.operation(async () => { first.resolve(); await finish.promise; return 'a'; });
    await first.promise;
    const b = boundary.operation(async () => { second.resolve(); await finish.promise; return 'b'; });
    await second.promise;
    finish.resolve();
    expect(await Promise.all([a, b])).toEqual(['a', 'b']);
  });

  it('drains existing operations and gives a queued reset priority over later operations', async () => {
    const boundary = new RunBoundary(), entered = deferred(), finish = deferred(), resetting = deferred(), releaseReset = deferred();
    const events: string[] = [];
    const before = boundary.operation(async () => { events.push('before'); entered.resolve(); await finish.promise; });
    await entered.promise;
    const reset = boundary.exclusive(async () => { events.push('reset'); resetting.resolve(); await releaseReset.promise; });
    const after = boundary.operation(() => { events.push('after'); });
    await Promise.resolve();
    expect(events).toEqual(['before']);
    finish.resolve(); await before; await resetting.promise;
    expect(events).toEqual(['before', 'reset']);
    releaseReset.resolve(); await Promise.all([reset, after]);
    expect(events).toEqual(['before', 'reset', 'after']);
  });

  it('lets an existing operation enter nested work after a reset has queued', async () => {
    const boundary = new RunBoundary(), entered = deferred(), continueOuter = deferred(), nested = deferred(), finish = deferred();
    const events: string[] = [];
    const operation = boundary.operation(async () => {
      entered.resolve(); await continueOuter.promise;
      await boundary.operation(() => { events.push('nested'); nested.resolve(); });
      await finish.promise;
    });
    await entered.promise;
    const reset = boundary.exclusive(() => { events.push('reset'); });
    continueOuter.resolve(); await nested.promise;
    expect(events).toEqual(['nested']);
    finish.resolve(); await Promise.all([operation, reset]);
    expect(events).toEqual(['nested', 'reset']);
  });

  it('rejects upgrading an operation to exclusive access instead of deadlocking', async () => {
    const boundary = new RunBoundary();
    await expect(boundary.operation(() => boundary.exclusive(() => 'unsafe')))
      .rejects.toThrow('RUN_BOUNDARY_UPGRADE_FORBIDDEN');
    expect(await boundary.exclusive(() => 'released')).toBe('released');
  });

  it('allows reset work to call nested operation and exclusive helpers', async () => {
    const boundary = new RunBoundary();
    expect(await boundary.exclusive(() => boundary.operation(() => boundary.exclusive(() => 'nested'))))
      .toBe('nested');
  });

  it.each(['operation', 'exclusive'] as const)('releases %s access after synchronous and asynchronous failures', async method => {
    const boundary = new RunBoundary();
    await expect(boundary[method](() => { throw new Error('sync'); })).rejects.toThrow('sync');
    await expect(boundary[method](async () => { await Promise.resolve(); throw new Error('async'); })).rejects.toThrow('async');
    expect(await boundary.exclusive(() => 'released')).toBe('released');
    expect(await boundary.operation(() => 'available')).toBe('available');
  });

  it('keeps nested asynchronous work inside the boundary even if its caller returns early', async () => {
    const boundary = new RunBoundary(), nested = deferred(), finish = deferred();
    let work!: Promise<void>, resetStarted = false;
    await boundary.operation(() => {
      work = boundary.operation(async () => { nested.resolve(); await finish.promise; });
    });
    await nested.promise;
    const reset = boundary.exclusive(() => { resetStarted = true; });
    await Promise.resolve(); expect(resetStarted).toBe(false);
    finish.resolve(); await work; await reset;
    expect(resetStarted).toBe(true);
  });

  it('does not let a stale async context bypass a later reset', async () => {
    const boundary = new RunBoundary(), resume = deferred(), resetting = deferred(), finishReset = deferred();
    const events: string[] = [];
    let deferredWork!: Promise<void>;
    await boundary.operation(() => {
      deferredWork = resume.promise.then(() => boundary.operation(() => { events.push('later'); }));
    });
    const reset = boundary.exclusive(async () => { events.push('reset'); resetting.resolve(); await finishReset.promise; });
    await resetting.promise; resume.resolve(); await Promise.resolve(); await Promise.resolve();
    expect(events).toEqual(['reset']);
    finishReset.resolve(); await Promise.all([reset, deferredWork]);
    expect(events).toEqual(['reset', 'later']);
  });
});
