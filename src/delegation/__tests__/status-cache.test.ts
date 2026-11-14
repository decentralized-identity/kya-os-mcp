import { describe, it, expect } from 'vitest';
import { withStatusCache } from '../status-cache.js';
import { describeValue } from '../../utils/describe-value.js';
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

  /** A cached resolver of two revocation lists, which refuses any other list or purpose. */
  const twoLists = () => {
    const lists = new Map<unknown, Map<unknown, boolean>>([
      ['https://status.example/1', new Map([['revocation', false]])],
      ['https://status.example/2', new Map([['revocation', true]])],
    ]);
    return withStatusCache(
      {
        checkStatus: async (s) => {
          const bit = lists.get(s.statusListCredential)?.get(s.statusPurpose);
          if (bit === undefined) throw new Error(`no list for statusPurpose ${describeValue(s.statusPurpose)}`);
          return bit;
        },
      },
      { maxStalenessMs: 60_000 },
    );
  };

  it("keys on the list and the purpose too (one entry's verdict never answers another's)", async () => {
    const cached = twoLists();
    expect(await cached.checkStatus(entry('7'))).toBe(false);
    expect(await cached.checkStatus({ ...entry('7'), statusListCredential: 'https://status.example/2' })).toBe(true);
    await expect(cached.checkStatus({ ...entry('7'), statusPurpose: 'suspension' })).rejects.toThrow(
      'no list for statusPurpose "suspension"',
    );
  });

  it('hands the resolver a purpose of any form as the credential states it, never converting it for the key', async () => {
    const cached = twoLists();
    const named: [unknown, string][] = [
      ['s'.repeat(100_000), `"${'s'.repeat(64)}"...`],
      [JSON.parse('{"toString":"revocation"}'), 'of type object'],
    ];
    for (const [statusPurpose, as] of named) {
      await expect(cached.checkStatus({ ...entry('7'), statusPurpose } as CredentialStatus)).rejects.toThrow(
        `no list for statusPurpose ${as}`,
      );
    }
  });
});
