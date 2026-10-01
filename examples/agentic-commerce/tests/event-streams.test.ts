import fs from 'node:fs';
import vm from 'node:vm';
import { afterEach, describe, expect, it, vi } from 'vitest';

function workerHarness() {
  const streams: { url: string; closed: boolean; readyState: number; onopen?: () => void; onerror?: () => void; onmessage?: (event: { data: string }) => void; close(): void }[] = [];
  const context = vm.createContext({
    setTimeout, clearTimeout,
    EventSource: class {
      static CONNECTING = 0; static OPEN = 1; static CLOSED = 2;
      closed = false;
      readyState = 0;
      constructor(public url: string) { streams.push(this); }
      close() { this.closed = true; this.readyState = 2; }
    },
  });
  context.self = context;
  vm.runInContext(fs.readFileSync('web/event-streams.js', 'utf8'), context);
  function client() {
    const messages: unknown[] = [];
    const port = { postMessage: (message: unknown) => messages.push(message), start() {}, onmessage: null as null | ((event: { data: unknown }) => void) };
    context.onconnect({ ports: [port] });
    return { messages, send: (data: unknown) => port.onmessage?.({ data }) };
  }
  return { streams, client };
}

describe('shared monitor event connections', () => {
  it('shares one stream across tabs and fans events out without opening extra sockets', () => {
    const w = workerHarness();
    const tabs = Array.from({ length: 8 }, () => w.client());
    for (const tab of tabs) tab.send({ type: 'subscribe', url: 'http://localhost:4949/api/events' });
    expect(w.streams).toHaveLength(1);
    w.streams[0]!.onmessage!({ data: '{"type":"request"}' });
    for (const tab of tabs) expect(tab.messages).toContainEqual({ url: 'http://localhost:4949/api/events', type: 'message', data: '{"type":"request"}' });
    tabs[0]!.send({ type: 'unsubscribe', url: 'http://localhost:4949/api/events' });
    expect(w.streams[0]!.closed).toBe(false);
    for (const tab of tabs.slice(1)) tab.send({ type: 'unsubscribe', url: 'http://localhost:4949/api/events' });
    expect(w.streams[0]!.closed).toBe(true);
  });

  it('keeps merchant and RP feeds independent and ignores duplicate subscriptions', () => {
    const w = workerHarness(), tab = w.client();
    for (const url of ['http://localhost:4949/api/events', 'http://localhost:4950/api/rp/events', 'http://localhost:4949/api/events']) tab.send({ type: 'subscribe', url });
    expect(w.streams).toHaveLength(2);
    tab.send({ type: 'disconnect' });
    expect(w.streams.every(stream => stream.closed)).toBe(true);
  });
});

afterEach(() => vi.useRealTimers());
describe('fatal shared feed recovery', () => {
  const url = 'http://localhost:4949/api/events';
  function fixture() {
    vi.useFakeTimers();
    const w = workerHarness(), a = w.client(), b = w.client();
    for (const tab of [a, b]) tab.send({ type: 'subscribe', url });
    const source = w.streams[0]!;
    source.readyState = 1; source.onopen!();
    return { ...w, a, b, source };
  }
  function fatal(source: ReturnType<typeof workerHarness>['streams'][number]) {
    source.readyState = 2; source.onerror!();
  }

  it('reconnects a CLOSED feed mid-session without a new tab and keeps all subscribers', () => {
    const w = fixture();
    fatal(w.source);
    expect(w.a.messages.at(-1)).toMatchObject({ type: 'error' });
    expect(w.streams).toHaveLength(1);
    vi.advanceTimersToNextTimer();
    expect(w.streams).toHaveLength(2);
    const replacement = w.streams[1]!;
    replacement.readyState = 1; replacement.onopen!();
    replacement.onmessage!({ data: 'recovered verdict' });
    for (const tab of [w.a, w.b]) expect(tab.messages.slice(-2)).toEqual([
      { url, type: 'open', data: undefined }, { url, type: 'message', data: 'recovered verdict' },
    ]);
  });

  it('uses one pending retry when new or duplicate subscribers encounter a dead stream', () => {
    const w = fixture();
    fatal(w.source);
    for (let i = 0; i < 8; i++) w.client().send({ type: 'subscribe', url });
    w.a.send({ type: 'subscribe', url });
    w.source.onerror!();
    expect(vi.getTimerCount()).toBe(1);
    expect(w.streams).toHaveLength(1);
    vi.advanceTimersToNextTimer();
    expect(w.streams).toHaveLength(2);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('repairs a closed source discovered by subscription even if its error callback was missed', () => {
    const w = fixture();
    w.source.readyState = 2;
    w.a.send({ type: 'subscribe', url });
    vi.advanceTimersToNextTimer();
    expect(w.streams).toHaveLength(2);
    const later = w.client(); later.send({ type: 'subscribe', url });
    w.streams[1]!.readyState = 1; w.streams[1]!.onopen!();
    expect(later.messages.at(-1)).toMatchObject({ type: 'open' });
    expect(w.a.messages.at(-1)).toMatchObject({ type: 'open' });
  });

  it('leaves transient CONNECTING errors to EventSource native reconnection', () => {
    const w = fixture();
    w.source.readyState = 0; w.source.onerror!();
    w.client().send({ type: 'subscribe', url });
    vi.advanceTimersByTime(60_000);
    expect(w.streams).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
    w.source.readyState = 1; w.source.onopen!();
    expect(w.a.messages.at(-1)).toMatchObject({ type: 'open' });
  });

  it('backs off repeated fatal failures, caps retries and restores the initial delay after opening', () => {
    const w = fixture();
    const delays: number[] = [];
    for (let i = 0; i < 9; i++) {
      fatal(w.streams.at(-1)!);
      const started = Date.now();
      vi.advanceTimersToNextTimer();
      delays.push(Date.now() - started);
    }
    expect(delays[0]).toBeGreaterThan(0);
    expect(delays[1]).toBeGreaterThan(delays[0]!);
    expect(delays.at(-1)).toBe(delays.at(-2));
    expect(delays.at(-1)).toBeLessThanOrEqual(15_000);
    w.streams.at(-1)!.readyState = 1; w.streams.at(-1)!.onopen!();
    fatal(w.streams.at(-1)!);
    const started = Date.now(); vi.advanceTimersToNextTimer();
    expect(Date.now() - started).toBe(delays[0]);
  });

  it('cancels recovery after the last subscriber leaves, while another feed keeps working', () => {
    const w = fixture();
    const rpUrl = 'http://localhost:4950/api/rp/events';
    w.a.send({ type: 'subscribe', url: rpUrl });
    fatal(w.source);
    w.a.send({ type: 'unsubscribe', url });
    expect(vi.getTimerCount()).toBe(1);
    w.b.send({ type: 'disconnect' });
    expect(vi.getTimerCount()).toBe(0);
    vi.advanceTimersByTime(60_000);
    expect(w.streams).toHaveLength(2);
    w.streams[1]!.onmessage!({ data: 'RP update' });
    expect(w.a.messages.at(-1)).toMatchObject({ url: rpUrl, type: 'message' });
    w.b.send({ type: 'subscribe', url });
    expect(w.streams).toHaveLength(2);
  });

  it('ignores callbacks queued by a retired source and keeps the replacement alive', () => {
    const w = fixture();
    const stale = { open: w.source.onopen!, error: w.source.onerror!, message: w.source.onmessage! };
    fatal(w.source); vi.advanceTimersToNextTimer();
    const count = w.a.messages.length;
    stale.open(); stale.error(); stale.message({ data: 'stale verdict' });
    expect(w.a.messages).toHaveLength(count);
    expect(vi.getTimerCount()).toBe(0);
    const replacement = w.streams[1]!;
    replacement.readyState = 1; replacement.onopen!();
    expect(w.a.messages.at(-1)).toMatchObject({ type: 'open' });
  });
});
