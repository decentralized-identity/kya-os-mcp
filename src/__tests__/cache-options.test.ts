/**
 * Every option that bounds a cache a verifier or resolver keeps is checked where that verifier or
 * resolver is built, as `dependencyTimeoutMs` is. A TTL must be a finite number of milliseconds, 0
 * or more, and a capacity a whole number greater than 0; any other value throws a `TypeError`
 * naming the option. An option left out keeps its default. Unchecked, a TTL read as
 * `Number(process.env.UNSET)` is `NaN`, which the cache read as never expiring, so a "not revoked"
 * verdict outlived any staleness the host meant to allow, and a capacity of `NaN` never evicted.
 */

import { describe, expect, it, vi } from 'vitest';
import { withStatusCache } from '../delegation/status-cache.js';
import { createDelegationVerifier, DelegationCredentialVerifier } from '../delegation/vc-verifier.js';
import { createDidWebResolver, DidWebResolver } from '../delegation/did-web-resolver.js';
import { cheqdResolver, DidCheqdResolver } from '../integrations/cheqd/resolver.js';
import { CheqdStatusListResolver } from '../integrations/cheqd/statuslist-resolver.js';
import type { CryptoProvider, FetchProvider } from '../providers/base.js';
import type { KyaOsDelegationConfig } from '../middleware/with-kya-os.config-types.js';
import { delegationGate } from '../middleware/__tests__/helpers/delegation-gate.js';

const fetchProvider = { fetch: vi.fn() } as unknown as FetchProvider;
const statusListResolver = { checkStatus: vi.fn(async () => false) };
const resolverUrl = 'https://resolver.example';
const cheqdStatusOptions = {
  fetchProvider,
  didResolver: { resolve: async () => null },
  cryptoProvider: {} as CryptoProvider,
  expectedIssuerDid: 'did:cheqd:testnet:issuer',
  decompressor: async (bytes: Uint8Array) => bytes,
};
const ROOT = 'did:web:root.example';
const middleware = (config: KyaOsDelegationConfig) => delegationGate({ trustedRootIssuers: [ROOT], config });

type Build = (value: unknown) => unknown;

/** Each public way to build a cache with a TTL, and the name of the option that sets it. */
const TTL_OPTIONS: [string, string, Build][] = [
  ['withStatusCache', 'maxStalenessMs', (value) => withStatusCache(statusListResolver, { maxStalenessMs: value as number })],
  ['DelegationCredentialVerifier', 'cacheTtl', (value) => new DelegationCredentialVerifier({ cacheTtl: value as number })],
  ['createDelegationVerifier', 'cacheTtl', (value) => createDelegationVerifier({ cacheTtl: value as number })],
  ['CheqdStatusListResolver', 'cacheTtlMs', (value) => new CheqdStatusListResolver({ ...cheqdStatusOptions, cacheTtlMs: value as number })],
  ['DidWebResolver', 'cacheTtl', (value) => new DidWebResolver(fetchProvider, { cacheTtl: value as number })],
  ['createDidWebResolver', 'cacheTtl', (value) => createDidWebResolver(fetchProvider, { cacheTtl: value as number })],
  ['DidCheqdResolver', 'cacheTtl', (value) => new DidCheqdResolver(fetchProvider, { resolverUrl, cacheTtl: value as number })],
  ['cheqdResolver', 'cacheTtl', (value) => cheqdResolver({ resolverUrl, cacheTtl: value as number })(fetchProvider)],
  ['createKyaOsMiddleware', 'delegation.verificationCache.ttlMs', (value) => middleware({ verificationCache: { ttlMs: value as number } })],
];

/** Each public way to set how many entries a cache keeps, and the name of the option. */
const CAPACITY_OPTIONS: [string, string, Build][] = [
  ['withStatusCache', 'maxEntries', (value) => withStatusCache(statusListResolver, { maxStalenessMs: 60_000, maxEntries: value as number })],
  ['DelegationCredentialVerifier', 'maxCacheSize', (value) => new DelegationCredentialVerifier({ maxCacheSize: value as number })],
  ['createDelegationVerifier', 'maxCacheSize', (value) => createDelegationVerifier({ maxCacheSize: value as number })],
  ['createKyaOsMiddleware', 'delegation.verificationCache.maxEntries', (value) => middleware({ verificationCache: { maxEntries: value as number } })],
];

const REFUSED_TTLS: [string, unknown, string][] = [
  ['NaN, as Number(process.env.UNSET) gives', Number.NaN, 'NaN'],
  ['Infinity', Number.POSITIVE_INFINITY, 'Infinity'],
  ['a negative number', -1, '-1'],
  ['a string', '60000', 'a value "60000"'],
  ['null', null, 'a value of type null'],
];

const REFUSED_CAPACITIES: [string, unknown, string][] = [
  ['NaN', Number.NaN, 'NaN'],
  ['0', 0, '0'],
  ['a negative number', -1, '-1'],
  ['a fraction', 1.5, '1.5'],
  ['Infinity', Number.POSITIVE_INFINITY, 'Infinity'],
  ['a string', '1000', 'a value "1000"'],
  ['null', null, 'a value of type null'],
];

const ttlTypeError = (option: string, got: string) =>
  new TypeError(`[kya-os] ${option} must be a finite number of milliseconds, 0 or more (got ${got})`);
const capacityTypeError = (option: string, got: string) =>
  new TypeError(`[kya-os] ${option} must be a whole number greater than 0 (got ${got})`);

/** What building with `value` comes to, a throw and a rejection alike. */
const built = (build: Build, value: unknown) => Promise.resolve().then(() => build(value));

describe.each(TTL_OPTIONS)('%s and its %s', (_api, option, build) => {
  it.each(REFUSED_TTLS)('throws a TypeError naming the option for %s', async (_label, value, got) => {
    await expect(built(build, value)).rejects.toThrow(ttlTypeError(option, got));
  });

  it.each([0, 1, 60_000])('builds with %d', async (value) => {
    await expect(built(build, value)).resolves.toBeDefined();
  });
});

describe.each(CAPACITY_OPTIONS)('%s and its %s', (_api, option, build) => {
  it.each(REFUSED_CAPACITIES)('throws a TypeError naming the option for %s', async (_label, value, got) => {
    await expect(built(build, value)).rejects.toThrow(capacityTypeError(option, got));
  });

  it.each([1, 1000])('builds with %d', async (value) => {
    await expect(built(build, value)).resolves.toBeDefined();
  });
});

describe('an option left out', () => {
  it.each([...TTL_OPTIONS.slice(1), ...CAPACITY_OPTIONS.slice(1)])('keeps its default: %s, %s', async (_api, _option, build) => {
    await expect(built(build, undefined)).resolves.toBeDefined();
  });

  it('throws for withStatusCache, whose maxStalenessMs has no default', () => {
    expect(() => withStatusCache(statusListResolver, {} as { maxStalenessMs: number }))
      .toThrow(ttlTypeError('maxStalenessMs', 'a value of type undefined'));
  });
});
