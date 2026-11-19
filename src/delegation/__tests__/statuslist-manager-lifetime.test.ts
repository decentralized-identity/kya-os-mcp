/**
 * A status list that states no end is read until its issuer replaces it, so a copy signed before a
 * revocation reads as current for as long as its key verifies (SPEC.md §6.6). A manager built with
 * `listLifetimeMs` states an end on every version it signs, `listLifetimeMs` after it signs it, so
 * such a copy stops being readable within that time; `renewStatusList` signs the list again with a
 * new end, its bits unchanged, so a list nobody changes stays readable.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { isIndexSet } from '../bitstring.js';
import { StatusList2021Manager } from '../statuslist-manager.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import { acceptStatusListValidity } from '../../utils/statuslist-validity.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealSigningFunction,
} from '../../__tests__/audit/helpers/crypto-helpers.js';
import { RefusalError } from '../../utils/refusal.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const crypto = createRealCryptoProvider();

afterEach(() => {
  vi.useRealTimers();
});

/** A manager over its own store, whose lists live `listLifetimeMs` when it is given. */
async function managed(listLifetimeMs?: number) {
  const issuer = await createRealIdentity(crypto);
  const storage = new MemoryStatusListStorage();
  const manager = new StatusList2021Manager(
    storage,
    { getDid: () => issuer.did, getKeyId: () => issuer.kid },
    createRealSigningFunction(crypto, issuer),
    statusListGzipCodec,
    statusListGzipCodec,
    { statusListBaseUrl: 'https://status.example', ...(listLifetimeMs === undefined ? {} : { listLifetimeMs }) },
  );
  return { manager, storage };
}

describe('StatusList2021Manager: listLifetimeMs', () => {
  it('states an end on every version, so a copy from before a revocation is not readable a lifetime on', async () => {
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

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '86400000', null])(
    'throws a TypeError naming the option for %s',
    (listLifetimeMs) => {
      expect(
        () =>
          new StatusList2021Manager(
            new MemoryStatusListStorage(),
            { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#k' },
            async () => ({ type: 'Ed25519Signature2020', proofValue: 'x' }),
            statusListGzipCodec,
            statusListGzipCodec,
            { listLifetimeMs: listLifetimeMs as number },
          ),
      ).toThrow(/^\[kya-os\] listLifetimeMs must be a whole number of milliseconds greater than 0/);
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

  it('throws a TypeError from a manager that gives its lists no lifetime, and changes nothing', async () => {
    const { manager, storage } = await managed();
    const entry = await manager.allocateStatusEntry('revocation');
    const before = await storage.getStatusList(entry.statusListCredential);
    await expect(manager.renewStatusList(entry.statusListCredential)).rejects.toThrow(TypeError);
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
