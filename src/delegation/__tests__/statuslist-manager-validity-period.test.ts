/**
 * A status list that states no end is read until its issuer replaces it, so a copy signed before a
 * revocation reads as current for as long as its key verifies (SPEC.md §6.6). A manager built with
 * `validityPeriodMs` states an end on every version it signs, that long after it signs it, so such
 * a copy stops being readable within that time; `renewStatusList` signs the list again with a new
 * end, its bits unchanged, so a list nobody changes stays readable. The end is the `expirationDate`
 * of a `StatusList2021Credential`, the format these tests leave as it is; the `validUntil` of a
 * `BitstringStatusListCredential` is in `statuslist-manager-format.test.ts`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isIndexSet } from '../bitstring.js';
import { StatusList2021Manager } from '../statuslist-manager.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import { acceptStatusListValidity } from '../../utils/statuslist-validity.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { statusListIssuer } from '../../__tests__/utils/status-list-manager.js';
import { RefusalError } from '../../utils/refusal.js';

const DAY_MS = 24 * 60 * 60 * 1000;
/** A century of 365.25 days, the longest validity period a manager gives its lists. */
const CENTURY_MS = 36_525 * DAY_MS;

afterEach(() => {
  vi.useRealTimers();
});

/** A manager over its own store, whose lists are valid for `validityPeriodMs` when it is given. */
const managed = (validityPeriodMs?: number) => statusListIssuer(validityPeriodMs === undefined ? {} : { validityPeriodMs });

describe('StatusList2021Manager: validityPeriodMs', () => {
  it('states an end on every version, so a copy from before a revocation is not readable a validity period on', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse('2026-11-18T12:00:00Z'));
    const { manager, storage } = await managed(7 * DAY_MS);
    const entry = await manager.allocateStatusEntry('revocation');
    const before = await storage.getStatusList(entry.statusListCredential);
    expect(before!.expirationDate).toBe('2026-11-25T12:00:00.000Z');

    vi.setSystemTime(Date.parse('2026-11-19T12:00:00Z'));
    await manager.updateStatus(entry, true);
    const after = await storage.getStatusList(entry.statusListCredential);
    // The revocation is signed with its own end; the list keeps the date it was first issued.
    expect(after!.expirationDate).toBe('2026-11-26T12:00:00.000Z');
    expect(after!.issuanceDate).toBe(before!.issuanceDate);

    expect(await isIndexSet(before!.credentialSubject.encodedList, Number(entry.statusListIndex))).toBe(false);
    const aYearOn = Date.parse('2027-11-19T12:00:00Z');
    expect(acceptStatusListValidity(before, aYearOn).valid).toBe(false);
    expect(acceptStatusListValidity(after, Date.parse('2026-11-20T12:00:00Z')).valid).toBe(true);
  });

  it("refuses its own list once the list's end has passed, as any reader does", async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse('2026-11-18T12:00:00Z'));
    const { manager } = await managed(DAY_MS);
    const entry = await manager.allocateStatusEntry('revocation');
    vi.setSystemTime(Date.parse('2026-11-20T12:00:00Z'));
    await expect(manager.checkStatus(entry)).rejects.toMatchObject({ code: 'status_unavailable' });
  });

  it('states no end without it, as before', async () => {
    const { manager, storage } = await managed();
    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(entry, true);
    const list = await storage.getStatusList(entry.statusListCredential);
    expect(list).not.toHaveProperty('expirationDate');
    expect(list).not.toHaveProperty('validUntil');
  });

  it('signs lists that live a century, each with an end a reader reads', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse('2026-11-18T12:00:00Z'));
    const { manager, storage } = await managed(CENTURY_MS);
    const entry = await manager.allocateStatusEntry('revocation');
    const list = await storage.getStatusList(entry.statusListCredential);
    // 36,525 days on, past 24 leap days, as 2100 is none.
    expect(list!.expirationDate).toBe('2126-11-19T12:00:00.000Z');
    expect(acceptStatusListValidity(list, Date.parse('2126-11-19T11:00:00Z')).valid).toBe(true);
  });

  // A validity period past a century, up to the largest safe integer, would end a list where no date-time a
  // reader reads can say, or where no Date is, so every list the manager signed would throw.
  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '86400000', null, CENTURY_MS + 1, 8.7e15, Number.MAX_SAFE_INTEGER])(
    'throws a TypeError naming the option for %s',
    (validityPeriodMs) => {
      expect(
        () =>
          new StatusList2021Manager(
            new MemoryStatusListStorage(),
            { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#k' },
            async () => ({ type: 'Ed25519Signature2020', proofValue: 'x' }),
            statusListGzipCodec,
            statusListGzipCodec,
            { validityPeriodMs: validityPeriodMs as number },
          ),
      ).toThrow(/^\[kya-os\] validityPeriodMs must be a whole number of milliseconds from 1 to 3155760000000, a century/);
    },
  );
});

describe('StatusList2021Manager.renewStatusList', () => {
  it('signs the list again with a new end and the same bits', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse('2026-11-18T12:00:00Z'));
    const { manager, storage } = await managed(7 * DAY_MS);
    const entry = await manager.allocateStatusEntry('revocation');
    await manager.updateStatus(entry, true);
    const before = await storage.getStatusList(entry.statusListCredential);

    vi.setSystemTime(Date.parse('2026-11-22T12:00:00Z'));
    await manager.renewStatusList(entry.statusListCredential);
    const renewed = await storage.getStatusList(entry.statusListCredential);
    expect(renewed!.expirationDate).toBe('2026-11-29T12:00:00.000Z');
    expect(renewed!.credentialSubject).toEqual(before!.credentialSubject);
    expect(renewed!.proof).not.toEqual(before!.proof);
    expect(await manager.checkStatus(entry)).toBe(true);
  });

  it('throws a TypeError naming the option from a manager that gives its lists no validity period, and changes nothing', async () => {
    const { manager, storage } = await managed();
    const entry = await manager.allocateStatusEntry('revocation');
    const before = await storage.getStatusList(entry.statusListCredential);
    await expect(manager.renewStatusList(entry.statusListCredential)).rejects.toThrow(
      new TypeError('[kya-os] renewStatusList gives a list a new end, and this manager gives its lists none: set validityPeriodMs'),
    );
    expect(await storage.getStatusList(entry.statusListCredential)).toEqual(before);
  });

  it('throws for a list it does not hold, and for one stored under another id', async () => {
    const { manager, storage } = await managed(DAY_MS);
    await expect(manager.renewStatusList('https://status.example/revocation/v1')).rejects.toThrow(
      'Status list not found: https://status.example/revocation/v1',
    );
    const entry = await manager.allocateStatusEntry('revocation');
    const stored = await storage.getStatusList(entry.statusListCredential);
    await storage.setStatusList('https://status.example/other', stored!);
    await expect(manager.renewStatusList('https://status.example/other')).rejects.toBeInstanceOf(RefusalError);
  });
});
