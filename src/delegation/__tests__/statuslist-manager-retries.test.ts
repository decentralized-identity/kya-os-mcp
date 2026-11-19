/**
 * How a `StatusList2021Manager` retries a write a conditional store refused. Between tries it waits
 * a random part of a delay that doubles from 2 ms, under a ceiling of 100 ms or, where it is
 * longer, the length of the try just refused doubled every four refusals, and never more than
 * 10 s, so a manager that lost a race does not meet the winner's next write head on and many
 * managers with slow tries still each get a turn. It gives up after `maxWriteConflicts` refusals
 * with a coded error and nothing stored. Time and chance are injected, so each run takes one
 * course.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  StatusList2021Manager,
  StatusListWriteConflictError,
  isStatusListWriteConflict,
} from '../statuslist-manager.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import type { StatusList2021Credential } from '../../types/protocol.js';
import { RefusalError } from '../../utils/refusal.js';
import {
  VirtualClock,
  allocated,
  identity,
  proofOver,
  replica,
  seededRandom,
  sign,
  synchronousGzip,
} from './helpers/status-list-writers.js';

/**
 * A store where, while `contending` is on, another writer stores the list again just before each
 * conditional write a manager makes, so every such write is over a list that has since changed.
 */
class ContendedStore extends MemoryStatusListStorage {
  contending = true;
  conditionalWrites = 0;

  override async setStatusListIfMatch(
    statusListId: string,
    credential: StatusList2021Credential,
    etag: string | null,
  ): Promise<boolean> {
    this.conditionalWrites++;
    const current = await this.getStatusList(statusListId);
    if (this.contending && current) await this.setStatusList(statusListId, current);
    return super.setStatusListIfMatch(statusListId, credential, etag);
  }
}

/** A sleep that records each wait and returns at once. */
function recordedSleep(waits: number[]): (ms: number) => Promise<void> {
  return async (ms) => {
    waits.push(ms);
  };
}

describe('StatusList2021Manager retries under sustained load', () => {
  it.each([
    [2, 40],
    [4, 20],
  ])('lands every revocation when %i managers each make %i in a row on one list', async (managers, each) => {
    const storage = new MemoryStatusListStorage();
    const entries = await allocated(storage, managers * each);
    const clock = new VirtualClock();
    const random = seededRandom(20261118);
    const backoffs: number[] = [];
    // Signing takes a millisecond of the clock, so a manager that wins keeps writing while one that
    // lost waits, as busy replicas do.
    const slowSign = async (canonical: string) => {
      await clock.sleep(1);
      return proofOver(canonical);
    };
    const sleep = (ms: number) => {
      backoffs.push(ms);
      return clock.sleep(ms);
    };

    const outcomes = await clock.run(
      Promise.allSettled(
        Array.from({ length: managers }, async (_, m) => {
          const manager = replica(storage, {
            sign: slowSign,
            codec: synchronousGzip,
            options: { sleep, random, now: clock.now },
          });
          for (const entry of entries.filter((_, i) => i % managers === m)) await manager.updateStatus(entry, true);
        }),
      ),
    );

    expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toEqual([]);
    expect(await replica(storage).getRevokedIndices(entries[0]!.statusListCredential)).toHaveLength(managers * each);
    expect(backoffs.length).toBeGreaterThan(0);
    expect(backoffs.every((ms) => ms >= 0 && ms < 100)).toBe(true);
  });

  it.each([48, 200])('lands every revocation when %i managers each make one at once, and signing takes 150 ms', async (managers) => {
    const storage = new MemoryStatusListStorage();
    const entries = await allocated(storage, managers);
    const clock = new VirtualClock();
    const random = seededRandom(20261118);
    let longestWait = 0;
    const slowSign = async (canonical: string) => {
      await clock.sleep(150);
      return proofOver(canonical);
    };
    const sleep = (ms: number) => {
      longestWait = Math.max(longestWait, ms);
      return clock.sleep(ms);
    };

    const outcomes = await clock.run(
      Promise.allSettled(
        entries.map((entry) =>
          replica(storage, { sign: slowSign, codec: synchronousGzip, options: { sleep, random, now: clock.now } })
            .updateStatus(entry, true),
        ),
      ),
    );

    expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toEqual([]);
    expect(await replica(storage).getRevokedIndices(entries[0]!.statusListCredential)).toHaveLength(managers);
    expect(longestWait).toBeGreaterThan(100);
  });
});

describe('StatusList2021Manager retry budget', () => {
  it('waits a random part of a delay that doubles to a 100 ms cap, and tries maxWriteConflicts + 1 times', async () => {
    const storage = new ContendedStore();
    const [entry] = await allocated(storage, 1);
    const before = storage.conditionalWrites;
    const waits: number[] = [];
    const manager = replica(storage, {
      options: { maxWriteConflicts: 9, sleep: recordedSleep(waits), random: () => 0.5, now: () => 0 },
    });

    const error = await manager.updateStatus(entry!, true).catch((thrown: unknown) => thrown);

    expect(error).toMatchObject({ code: 'STATUS_LIST_WRITE_CONFLICT', attempts: 10 });
    expect(storage.conditionalWrites - before).toBe(10);
    expect(waits).toEqual([1, 2, 4, 8, 16, 32, 50, 50, 50]);
  });

  it('raises the ceiling past 100 ms to the length of the try just refused, doubled every four refusals', async () => {
    const storage = new ContendedStore();
    const [entry] = await allocated(storage, 1);
    const waits: number[] = [];
    let time = 0;
    // Each try takes 50 ms, all of it signing.
    const slowSign = async (canonical: string) => {
      time += 50;
      return proofOver(canonical);
    };
    const manager = replica(storage, {
      sign: slowSign,
      options: { maxWriteConflicts: 16, sleep: recordedSleep(waits), random: () => 0.5, now: () => time },
    });

    await expect(manager.updateStatus(entry!, true)).rejects.toMatchObject({ attempts: 17 });
    expect(waits).toHaveLength(16);
    expect(waits.slice(0, 7)).toEqual([1, 2, 4, 8, 16, 32, 64]);
    // Half the ceiling from the eighth refusal: 50 ms doubled for each four refusals, 200, 400, 800.
    expect([waits[7], waits[11], waits[15]]).toEqual([100, 200, 400]);
  });

  it('never waits more than 10 s at once, so a change of 10 s tries gives up within 32 waits and 33 tries', async () => {
    const storage = new ContendedStore();
    const [entry] = await allocated(storage, 1);
    const waits: number[] = [];
    let time = 0;
    // Each try takes 10 s, all of it signing, and the clock moves through each wait too.
    const slowSign = async (canonical: string) => {
      time += 10_000;
      return proofOver(canonical);
    };
    const sleep = async (ms: number) => {
      waits.push(ms);
      time += ms;
    };
    const manager = replica(storage, {
      sign: slowSign,
      options: { sleep, random: () => 0.999, now: () => time },
    });

    await expect(manager.updateStatus(entry!, true)).rejects.toMatchObject({ attempts: 33 });
    expect(waits).toHaveLength(32);
    expect(Math.max(...waits)).toBeLessThanOrEqual(10_000);
    // From the 14th refusal the doubling delay passes 10 s, and each wait is a part of 10 s.
    expect(waits.slice(13).every((ms) => ms === 0.999 * 10_000)).toBe(true);
    expect(time).toBeLessThanOrEqual(32 * (10_000 + 10_000) + 10_000);
  });

  it('throws a coded error after 33 tries by default, and never stores a stale list', async () => {
    const storage = new ContendedStore();
    const [entry] = await allocated(storage, 1);
    const id = entry!.statusListCredential;
    const created = await storage.getStatusList(id);
    const before = storage.conditionalWrites;
    const waits: number[] = [];
    const manager = replica(storage, { options: { sleep: recordedSleep(waits) } });

    const error = await manager.updateStatus(entry!, true).catch((thrown: unknown) => thrown);

    expect(error).toBeInstanceOf(StatusListWriteConflictError);
    expect(error).toMatchObject({
      name: 'StatusListWriteConflictError',
      code: 'STATUS_LIST_WRITE_CONFLICT',
      statusListId: id,
      attempts: 33,
    });
    expect((error as Error).message).toMatch(/was not written.*Make the change again\.$/);
    expect(storage.conditionalWrites - before).toBe(33);
    expect(waits).toHaveLength(32);
    // Every list the store kept is the one the other writer stored, so nothing this manager signed
    // over a list it read was stored.
    const versions = await storage.getStatusListVersionCount(id);
    expect(versions).toBe(1 + 33);
    for (let version = 1; version <= versions; version++) {
      expect(await storage.getStatusListVersion(id, version)).toEqual(created);
    }

    // Made again once the other writer stops, the change is stored.
    storage.contending = false;
    await manager.updateStatus(entry!, true);
    expect(await manager.checkStatus(entry!)).toBe(true);
  });

  it('tries once, and waits for nothing, when maxWriteConflicts is 0', async () => {
    const storage = new ContendedStore();
    const [entry] = await allocated(storage, 1);
    const waits: number[] = [];
    const manager = replica(storage, { options: { maxWriteConflicts: 0, sleep: recordedSleep(waits) } });

    await expect(manager.updateStatus(entry!, true)).rejects.toMatchObject({ attempts: 1 });
    expect(waits).toEqual([]);
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '3', null])(
    'refuses maxWriteConflicts %s with a TypeError that names the option',
    (value) => {
      expect(() =>
        new StatusList2021Manager(new MemoryStatusListStorage(), identity, sign, undefined, undefined, {
          maxWriteConflicts: value as number,
        }),
      ).toThrow(/^\[kya-os\] maxWriteConflicts must be a whole number, 0 or more \(got /);
    },
  );
});

describe('isStatusListWriteConflict', () => {
  it('knows a write conflict by its code, from any copy of the package', async () => {
    expect(isStatusListWriteConflict(new StatusListWriteConflictError('https://status.example/list', 3))).toBe(true);

    vi.resetModules();
    const copy = await import('../statuslist-manager.js');
    const fromCopy = new copy.StatusListWriteConflictError('https://status.example/list', 3);
    expect(fromCopy instanceof StatusListWriteConflictError).toBe(false);
    expect(isStatusListWriteConflict(fromCopy)).toBe(true);
  });

  it('is false for any other error or value', () => {
    for (const value of [
      new Error('STATUS_LIST_WRITE_CONFLICT'),
      new RefusalError('status_unavailable', 'no list'),
      Object.assign(new Error('x'), { code: 'STATUS_LIST_WRITE_CONFLICTS' }),
      'STATUS_LIST_WRITE_CONFLICT',
      null,
      undefined,
    ]) {
      expect(isStatusListWriteConflict(value)).toBe(false);
    }
  });
});
