/**
 * The proofs one middleware's wrappers leave for the transport
 * (`createPendingProofs`). Each waits under a one-time id until the transport
 * takes it, or is closed as not sent when its window passes or the waiting
 * proofs outgrow their count or size budget. What a proof no longer waiting
 * was about is remembered, within a count and a size budget of its own, so a
 * result sent after its proof closed can still be recorded against its tool.
 *
 * The budgets are the ones the module documents: 10,000 proofs waiting, or
 * 16 MiB of their JSON; 10,000 remembered, or 4 MiB of what each keeps; and an
 * audit context kept only up to 16 KiB of its JSON. Every size is in UTF-16
 * code units.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { McpAuditContext } from '../../audit/adapters/mcp.js';
import { createPendingProofs, type PendingAllowedProof, type PendingProof } from '../with-kya-os.pending-proofs.js';

const KIB = 1024;
const MIB = 1024 * KIB;
const COUNT_LIMIT = 10_000;

const proof = (toolName: string, members: Partial<PendingAllowedProof> = {}): PendingAllowedProof => ({
  kind: 'allowed',
  toolName,
  requestHash: `sha256:${'0'.repeat(64)}`,
  sessionId: 'session-1',
  ...members,
});

/** A proof whose JSON is `size` code units. */
const proofOfSize = (size: number): PendingProof => proof('t'.repeat(size - JSON.stringify(proof('')).length));

/** An audit context whose JSON is `size` code units. */
const contextOfSize = (size: number): McpAuditContext => ({
  correlationId: 'c'.repeat(size - JSON.stringify({ correlationId: '' }).length),
});

function store(ttlMs?: number) {
  const closed: PendingProof[] = [];
  const proofs = createPendingProofs(ttlMs, async (pending) => {
    closed.push(pending);
  });
  return { proofs, closed };
}

/** Leave `pending` and take it at once: a proof the transport sent. */
function sent(proofs: ReturnType<typeof store>['proofs'], pending: PendingProof): string {
  const id = proofs.leave(pending);
  proofs.take(id);
  return id;
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('a proof left for the transport', () => {
  it('waits under an id of 16 random bytes in base64url, which no other proof waits under', () => {
    vi.useFakeTimers();
    const { proofs } = store();
    const ids = [proofs.leave(proof('a')), proofs.leave(proof('b'))];
    for (const id of ids) expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(ids[0]).not.toBe(ids[1]);
    expect([...proofs.keys()]).toEqual(ids);
  });

  it('is taken once, by its id', () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    const pending = proof('a');
    const id = proofs.leave(pending);
    expect(proofs.take(id)).toBe(pending);
    expect(proofs.take(id)).toBeUndefined();
    expect([...proofs.keys()]).toEqual([]);
    expect(closed).toEqual([]);
  });

  it('is closed as not sent when its window passes untaken, and its timer is stopped when it is taken', async () => {
    vi.useFakeTimers();
    const { proofs, closed } = store(1_000);
    const [left, taken] = [proof('left'), proof('taken')];
    proofs.leave(left);
    const takenId = proofs.leave(taken);
    expect(vi.getTimerCount()).toBe(2);
    proofs.take(takenId);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(999);
    expect(closed).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(closed).toEqual([left]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('waits five minutes when no window is given', async () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    const pending = proof('a');
    proofs.leave(pending);
    await vi.advanceTimersByTimeAsync(5 * 60_000 - 1);
    expect(closed).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(closed).toEqual([pending]);
  });

  it('does not hold the process open while it waits', () => {
    const timeouts = vi.spyOn(globalThis, 'setTimeout');
    const { proofs } = store();
    const id = proofs.leave(proof('a'));
    const timer = timeouts.mock.results.at(-1)!.value as { hasRef(): boolean };
    expect(timer.hasRef()).toBe(false);
    proofs.take(id);
  });

  it('is remembered by its tool and audit context once it no longer waits', () => {
    vi.useFakeTimers();
    const { proofs } = store();
    const left = proof('records.read', { context: contextOfSize(64) });
    const id = proofs.leave(left);
    expect(proofs.closed(id)).toBeUndefined();
    expect(proofs.take(id)).toBe(left);
    expect(proofs.closed(id)).toMatchObject({ toolName: 'records.read', context: left.context });

    // One left with no audit context is remembered without one.
    const bare = sent(proofs, proof('records.list'));
    expect(proofs.closed(bare)).toMatchObject({ toolName: 'records.list' });
    expect(proofs.closed(bare)).not.toHaveProperty('context');
    expect(proofs.closed('an id no proof waited under')).toBeUndefined();
  });

  it('keeps its audit context once it no longer waits up to 16 KiB of JSON, and not past that', () => {
    vi.useFakeTimers();
    const { proofs } = store();
    const [atLimit, pastIt] = [contextOfSize(16 * KIB), contextOfSize(16 * KIB + 1)];
    const kept = sent(proofs, proof('a', { context: atLimit }));
    const dropped = sent(proofs, proof('b', { context: pastIt }));
    expect(proofs.closed(kept)?.context).toBe(atLimit);
    expect(proofs.closed(dropped)).toMatchObject({ toolName: 'b' });
    expect(proofs.closed(dropped)).not.toHaveProperty('context');
  });
});

describe('the proofs no longer waiting', () => {
  it('are remembered up to 10,000, the oldest forgotten past that', () => {
    vi.useFakeTimers();
    const { proofs } = store();
    const ids = Array.from({ length: COUNT_LIMIT }, (_, n) => sent(proofs, proof(`tool-${n}`)));
    expect(proofs.closed(ids[0]!)).toMatchObject({ toolName: 'tool-0' });
    sent(proofs, proof('one more'));
    expect(proofs.closed(ids[0]!)).toBeUndefined();
    expect(proofs.closed(ids[1]!)).toMatchObject({ toolName: 'tool-1' });
  });

  it('are remembered up to 4 MiB of their tool names and kept audit contexts, the oldest forgotten past that', () => {
    vi.useFakeTimers();
    const { proofs } = store();
    const context = contextOfSize(16 * KIB);
    // 2 MiB counted in two parts, then 2 MiB of a tool name alone: 4 MiB in all.
    const first = sent(proofs, proof('f'.repeat(2 * MIB - JSON.stringify(context).length), { context }));
    const second = sent(proofs, proof('s'.repeat(2 * MIB)));
    expect(proofs.closed(first)).toBeDefined();
    const third = sent(proofs, proof('t'));
    expect(proofs.closed(first)).toBeUndefined();
    expect(proofs.closed(second)).toBeDefined();
    expect(proofs.closed(third)).toBeDefined();
  });
});

describe('the proofs waiting', () => {
  it('may hold 16 MiB of JSON, the oldest closed as not sent past that', () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    const [a, b, c] = [proofOfSize(8 * MIB), proofOfSize(8 * MIB), proof('c')];
    const [idA, idB] = [proofs.leave(a), proofs.leave(b)];
    expect([...proofs.keys()]).toEqual([idA, idB]);
    expect(closed).toEqual([]);
    const idC = proofs.leave(c);
    expect([...proofs.keys()]).toEqual([idB, idC]);
    expect(closed).toEqual([a]);
  });

  it('no longer count a proof once it is taken', () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    sent(proofs, proofOfSize(8 * MIB));
    const ids = [proofs.leave(proofOfSize(8 * MIB)), proofs.leave(proofOfSize(8 * MIB))];
    expect([...proofs.keys()]).toEqual(ids);
    expect(closed).toEqual([]);
  });

  it('close the one proof waiting as not sent when the next does not fit beside it', () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    const first = proofOfSize(12 * MIB);
    proofs.leave(first);
    const next = proofs.leave(proofOfSize(8 * MIB));
    expect([...proofs.keys()]).toEqual([next]);
    expect(closed).toEqual([first]);
  });

  it('let a proof larger than the budget wait when no other does', () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    const id = proofs.leave(proofOfSize(16 * MIB + 1));
    expect([...proofs.keys()]).toEqual([id]);
    expect(closed).toEqual([]);
  });

  it('are 10,000 at most, the oldest closed as not sent past that', () => {
    vi.useFakeTimers();
    const { proofs, closed } = store();
    const pending = Array.from({ length: COUNT_LIMIT + 1 }, (_, n) => proof(`tool-${n}`));
    const ids = pending.slice(0, COUNT_LIMIT).map((left) => proofs.leave(left));
    expect(closed).toEqual([]);
    proofs.leave(pending[COUNT_LIMIT]!);
    expect(closed).toEqual([pending[0]]);
    expect([...proofs.keys()]).toHaveLength(COUNT_LIMIT);
    expect(proofs.closed(ids[0]!)).toMatchObject({ toolName: 'tool-0' });
  });
});
