import { describe, it, expect } from 'vitest';
import { withStatusCache } from '../status-cache.js';
import type { CredentialStatus } from '../../types/protocol.js';

const entry = (index: string): CredentialStatus => ({
  id: `https://status.example/1#${index}`,
  type: 'StatusList2021Entry',
  statusPurpose: 'revocation',
  statusListIndex: index,
  statusListCredential: 'https://status.example/1',
});

describe('withStatusCache', () => {
  it('serves the cached bit within maxStalenessMs (one upstream read)', async () => {
    let calls = 0;
    const cached = withStatusCache(
      { checkStatus: async () => { calls += 1; return false; } },
      { maxStalenessMs: 60_000 },
    );
    expect(await cached.checkStatus(entry('1'))).toBe(false);
    expect(await cached.checkStatus(entry('1'))).toBe(false);
    expect(calls).toBe(1);
  });

  it('re-reads upstream after maxStalenessMs — a revocation lands at the declared SLA', async () => {
    let calls = 0;
    let revoked = false;
    const cached = withStatusCache(
      { checkStatus: async () => { calls += 1; return revoked; } },
      { maxStalenessMs: 10 },
    );
    expect(await cached.checkStatus(entry('2'))).toBe(false);
    revoked = true;
    await new Promise((r) => setTimeout(r, 15));
    expect(await cached.checkStatus(entry('2'))).toBe(true);
    expect(calls).toBe(2);
  });

  it('never caches a throw (fail-closed retry)', async () => {
    let calls = 0;
    const cached = withStatusCache(
      {
        checkStatus: async () => {
          calls += 1;
          if (calls === 1) throw new Error('unreachable');
          return false;
        },
      },
      { maxStalenessMs: 60_000 },
    );
    await expect(cached.checkStatus(entry('3'))).rejects.toThrow('unreachable');
    expect(await cached.checkStatus(entry('3'))).toBe(false);
    expect(calls).toBe(2);
  });

  it('maxStalenessMs <= 0 is a pass-through (every call reads upstream)', async () => {
    let calls = 0;
    const cached = withStatusCache(
      { checkStatus: async () => { calls += 1; return false; } },
      { maxStalenessMs: 0 },
    );
    await cached.checkStatus(entry('4'));
    await cached.checkStatus(entry('4'));
    expect(calls).toBe(2);
  });

  it('keys entries independently (a revoked neighbor does not leak)', async () => {
    const bits: Record<string, boolean> = { '5': false, '6': true };
    const cached = withStatusCache(
      { checkStatus: async (s) => bits[s.statusListIndex] ?? true },
      { maxStalenessMs: 60_000 },
    );
    expect(await cached.checkStatus(entry('5'))).toBe(false);
    expect(await cached.checkStatus(entry('6'))).toBe(true);
  });
});
