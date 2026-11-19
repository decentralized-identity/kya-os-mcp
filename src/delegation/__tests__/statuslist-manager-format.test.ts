/**
 * A `StatusList2021Manager` writes its lists and their entries in one of two data models, which its
 * `format` option names. `StatusList2021`, the default through 1.x, is a `StatusList2021Credential`
 * of the Verifiable Credentials Data Model 1.1. `BitstringStatusList` is W3C Bitstring Status List
 * v1.0: a `BitstringStatusListCredential` of the Data Model 2.0, which bounds a list by `validFrom`
 * and `validUntil` and may state `credentialSubject.ttl`, with `BitstringStatusListEntry` entries
 * (its §2.1 and §2.2). A stored list keeps the format it was created in, whatever manager signs it
 * again, and a manager allocates no entry on a list of the other format.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BitstringManager, isIndexSet } from '../bitstring.js';
import { StatusList2021Manager, type StatusList2021ManagerOptions } from '../statuslist-manager.js';
import { MemoryStatusListStorage } from '../storage/memory-statuslist-storage.js';
import { statusListGzipCodec } from '../../utils/statuslist-gzip.js';
import { statusListIssuer } from '../../__tests__/utils/status-list-manager.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const CENTURY_MS = 36_525 * DAY_MS;
const NOON = '2026-11-19T12:00:00.000Z';
const LIST = 'https://status.example/revocation/v1';
const W3C = { format: 'BitstringStatusList' } as const;

afterEach(() => {
  vi.useRealTimers();
});

/** Hold the clock at `time`, an RFC 3339 date-time. */
function at(time: string): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(Date.parse(time));
}

/** The list stored under `url` without its proof, and the proof. */
async function stored(storage: MemoryStatusListStorage, url = LIST) {
  const { proof, ...list } = (await storage.getStatusList(url)) as Record<string, unknown>;
  return { list, proof, subject: list.credentialSubject as Record<string, unknown> };
}

/** How many entries `encodedList` holds. */
async function entriesOf(encodedList: unknown): Promise<number> {
  const bits = await BitstringManager.decode(encodedList as string, statusListGzipCodec, statusListGzipCodec);
  return bits.getRawBits().length * 8;
}

describe('StatusList2021Manager: format', () => {
  it.each([
    ['is not set', {}],
    ['is "StatusList2021"', { format: 'StatusList2021' as const }],
  ])('writes a StatusList2021Credential and StatusList2021Entry entries when it %s, as on 1.25.0', async (_label, options) => {
    at(NOON);
    const { manager, storage, issuer } = await statusListIssuer(options);
    const entry = await manager.allocateStatusEntry('revocation');
    expect(entry).toEqual({
      id: `${LIST}#${entry.statusListIndex}`,
      type: 'StatusList2021Entry',
      statusPurpose: 'revocation',
      statusListIndex: expect.stringMatching(/^\d+$/),
      statusListCredential: LIST,
    });
    const { list } = await stored(storage);
    expect(list).toEqual({
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
      id: LIST,
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: issuer.did,
      issuanceDate: NOON,
      credentialSubject: { id: `${LIST}#list`, type: 'StatusList2021', statusPurpose: 'revocation', encodedList: expect.stringMatching(/^u/) },
    });
  });

  it('writes a BitstringStatusListCredential as W3C Bitstring Status List v1.0 §2.2 has one', async () => {
    at(NOON);
    const { manager, storage, issuer } = await statusListIssuer(W3C);
    await manager.allocateStatusEntry('revocation');
    const { list, proof, subject } = await stored(storage);
    expect(list).toEqual({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: LIST,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: issuer.did,
      validFrom: NOON,
      credentialSubject: { id: `${LIST}#list`, type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: expect.stringMatching(/^u/) },
    });
    expect(proof).toMatchObject({ verificationMethod: issuer.kid, proofPurpose: 'assertionMethod' });
    // "The uncompressed bitstring MUST be at least 16KB in size."
    expect(await entriesOf(subject.encodedList)).toBe(131_072);
  });

  it('allocates BitstringStatusListEntry entries as its §2.1 has one, each purpose on a list of its own', async () => {
    const { manager, storage } = await statusListIssuer(W3C);
    const first = await manager.allocateStatusEntry('revocation');
    const second = await manager.allocateStatusEntry('revocation');
    expect(first).toEqual({
      id: `${LIST}#${first.statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: expect.stringMatching(/^\d+$/),
      statusListCredential: LIST,
    });
    // "It MUST NOT be the URL for the status list."
    expect(first.id).not.toBe(LIST);
    expect(second.statusListIndex).not.toBe(first.statusListIndex);

    const suspension = await manager.allocateStatusEntry('suspension');
    const suspensions = 'https://status.example/suspension/v1';
    expect(suspension).toMatchObject({ type: 'BitstringStatusListEntry', statusPurpose: 'suspension', statusListCredential: suspensions });
    expect((await stored(storage, suspensions)).subject).toMatchObject({ type: 'BitstringStatusList', statusPurpose: 'suspension' });
  });

  it('states validUntil, validityPeriodMs after it signs each version, and ttl as given', async () => {
    at(NOON);
    const { manager, storage } = await statusListIssuer({ ...W3C, validityPeriodMs: 7 * DAY_MS, ttl: 300_000 });
    const entry = await manager.allocateStatusEntry('revocation');
    const created = await stored(storage);
    expect(created.list).toMatchObject({ validFrom: NOON, validUntil: '2026-11-26T12:00:00.000Z' });
    expect(created.subject.ttl).toBe(300_000);
    expect(created.list).not.toHaveProperty('issuanceDate');
    expect(created.list).not.toHaveProperty('expirationDate');

    at('2026-11-20T12:00:00.000Z');
    await manager.updateStatus(entry, true);
    const revoked = await stored(storage);
    // The list keeps the day it was first valid from, and each version has an end of its own.
    expect(revoked.list).toMatchObject({ type: created.list.type, validFrom: NOON, validUntil: '2026-11-27T12:00:00.000Z' });
    expect(revoked.subject).toMatchObject({ type: 'BitstringStatusList', ttl: 300_000 });
    expect(await isIndexSet(revoked.subject.encodedList as string, Number(entry.statusListIndex))).toBe(true);

    at('2026-11-24T12:00:00.000Z');
    await manager.renewStatusList(LIST);
    const renewed = await stored(storage);
    expect(renewed.list).toMatchObject({ validFrom: NOON, validUntil: '2026-12-01T12:00:00.000Z' });
    expect(renewed.subject).toEqual(revoked.subject);
    expect(renewed.list).not.toHaveProperty('expirationDate');
    expect(await manager.checkStatus(entry)).toBe(true);
  });

  it('refuses its own BitstringStatusListCredential once its validUntil has passed', async () => {
    at(NOON);
    const { manager } = await statusListIssuer({ ...W3C, validityPeriodMs: DAY_MS });
    const entry = await manager.allocateStatusEntry('revocation');
    expect(await manager.checkStatus(entry)).toBe(false);
    at('2026-11-21T12:00:00.000Z');
    await expect(manager.checkStatus(entry)).rejects.toMatchObject({ code: 'status_unavailable' });
  });
});

/** A manager built with `options` over nothing it uses before it is built. */
const built = (options: Record<string, unknown>) => () =>
  new StatusList2021Manager(
    new MemoryStatusListStorage(),
    { getDid: () => 'did:web:issuer.example', getKeyId: () => 'did:web:issuer.example#k' },
    async () => ({ type: 'Ed25519Signature2020', proofValue: 'x' }),
    statusListGzipCodec,
    statusListGzipCodec,
    options as StatusList2021ManagerOptions,
  );

describe('StatusList2021Manager: options one format has', () => {
  it.each(['bitstring', 'BitstringStatusListCredential', 'statuslist2021', '', null, 1])(
    'throws a TypeError naming the option for the format %j',
    (format) => {
      expect(built({ format })).toThrow(TypeError);
      expect(built({ format })).toThrow(/^\[kya-os\] format must be "StatusList2021" or "BitstringStatusList" \(got /);
    },
  );

  it.each([
    ['is not set', {}],
    ['is "StatusList2021"', { format: 'StatusList2021' }],
  ])('refuses ttl where format %s, since a StatusList2021 has no such member', (_label, options) => {
    expect(built({ ...options, ttl: 300_000 })).toThrow(
      new TypeError(
        '[kya-os] ttl is a member of a BitstringStatusList, and a StatusList2021 has none: set format to "BitstringStatusList", or leave ttl out',
      ),
    );
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '300000', null, CENTURY_MS + 1])(
    'throws a TypeError naming the option for a ttl of %s',
    (ttl) => {
      expect(built({ ...W3C, ttl })).toThrow(TypeError);
      expect(built({ ...W3C, ttl })).toThrow(/^\[kya-os\] ttl must be a whole number of milliseconds from 1 to 3155760000000, a century/);
    },
  );

  it('refuses a ttl longer than validityPeriodMs, which no reader could keep to, and takes one as long', () => {
    expect(built({ ...W3C, validityPeriodMs: DAY_MS, ttl: DAY_MS + 1 })).toThrow(
      new TypeError(
        '[kya-os] ttl (86400001) must not be longer than validityPeriodMs (86400000): a list is not read past its validUntil, whatever its ttl',
      ),
    );
    expect(built({ ...W3C, validityPeriodMs: DAY_MS, ttl: DAY_MS })).not.toThrow();
    expect(built({ ...W3C, ttl: CENTURY_MS })).not.toThrow();
  });

  it('refuses a BitstringStatusList of fewer than 131,072 entries, and writes a StatusList2021 of any size as before', async () => {
    expect(built({ ...W3C, defaultListSize: 131_071 })).toThrow(
      new TypeError(
        '[kya-os] defaultListSize must be at least 131072 where format is "BitstringStatusList", the fewest entries one may hold (got 131071)',
      ),
    );
    expect(built({ ...W3C, defaultListSize: 262_144 })).not.toThrow();
    const { manager, storage } = await statusListIssuer({ defaultListSize: 1024 });
    await manager.allocateStatusEntry('revocation');
    expect(await entriesOf((await stored(storage)).subject.encodedList)).toBe(1024);
  });
});

describe('StatusList2021Manager: a store that holds a list of the other format', () => {
  it('signs a StatusList2021 list again in its own terms, and allocates no BitstringStatusListEntry on it', async () => {
    at(NOON);
    const first = await statusListIssuer({ validityPeriodMs: 7 * DAY_MS });
    const entry = await first.manager.allocateStatusEntry('revocation');
    const { manager } = await statusListIssuer({ ...W3C, validityPeriodMs: DAY_MS, ttl: 60_000 }, first);

    await manager.updateStatus(entry, true);
    const revoked = await stored(first.storage);
    expect(revoked.list).toMatchObject({
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuanceDate: NOON,
      expirationDate: '2026-11-20T12:00:00.000Z',
    });
    expect(revoked.list).not.toHaveProperty('validUntil');
    expect(revoked.subject).not.toHaveProperty('ttl');
    expect(await manager.checkStatus(entry)).toBe(true);

    at('2026-11-20T00:00:00.000Z');
    await manager.renewStatusList(LIST);
    const renewed = await stored(first.storage);
    expect(renewed.list.expirationDate).toBe('2026-11-21T00:00:00.000Z');
    expect(renewed.subject).toEqual(revoked.subject);

    const before = await first.storage.getStatusList(LIST);
    await expect(manager.allocateStatusEntry('revocation')).rejects.toThrow(
      new TypeError(
        `[kya-os] Status list ${LIST} is a StatusList2021, and this manager allocates the entries of a ` +
          'BitstringStatusList: set format to "StatusList2021", or give the manager a statusListBaseUrl of its own',
      ),
    );
    expect(await first.storage.getStatusList(LIST)).toEqual(before);
  });

  it('signs a BitstringStatusListCredential again in its own terms, and allocates no StatusList2021Entry on it', async () => {
    at(NOON);
    const first = await statusListIssuer({ ...W3C, ttl: 60_000 });
    const entry = await first.manager.allocateStatusEntry('revocation');
    const { manager } = await statusListIssuer({ validityPeriodMs: DAY_MS }, first);

    await manager.updateStatus(entry, true);
    const revoked = await stored(first.storage);
    expect(revoked.list).toMatchObject({
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      validFrom: NOON,
      validUntil: '2026-11-20T12:00:00.000Z',
    });
    expect(revoked.list).not.toHaveProperty('expirationDate');
    expect(revoked.subject.ttl).toBe(60_000);
    expect(await manager.checkStatus(entry)).toBe(true);

    await expect(manager.allocateStatusEntry('revocation')).rejects.toThrow(
      new TypeError(
        `[kya-os] Status list ${LIST} is a BitstringStatusList, and this manager allocates the entries of a ` +
          'StatusList2021: set format to "BitstringStatusList", or give the manager a statusListBaseUrl of its own',
      ),
    );
  });

  it('holds a stored list typed as neither format to be a StatusList2021, as every list stored before the manager had a format is', async () => {
    at(NOON);
    const first = await statusListIssuer();
    const entry = await first.manager.allocateStatusEntry('revocation');
    const untyped = { ...(await first.storage.getStatusList(LIST))!, type: ['VerifiableCredential'] as [string] };
    await first.storage.setStatusList(LIST, untyped as never);
    const { manager } = await statusListIssuer({ ...W3C, validityPeriodMs: DAY_MS, ttl: 60_000 }, first);

    await manager.updateStatus(entry, true);
    const { list, subject } = await stored(first.storage);
    expect(list).toMatchObject({ type: ['VerifiableCredential'], expirationDate: '2026-11-20T12:00:00.000Z' });
    expect(list).not.toHaveProperty('validUntil');
    expect(subject).not.toHaveProperty('ttl');
    await expect(manager.allocateStatusEntry('revocation')).rejects.toThrow(
      /is a StatusList2021, and this manager allocates the entries of a BitstringStatusList/,
    );
  });
});
