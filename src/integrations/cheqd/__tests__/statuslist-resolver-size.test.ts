/**
 * CheqdStatusListResolver reads one bit per entry, so it refuses an entry whose `statusSize` is not
 * 1 before it fetches any list: an entry of two bits at index 7 has its value at bits 14 and 15, and
 * bit 7 is another entry's. A real signed list, served through a stub transport that counts its
 * fetches, as in `statuslist-resolver-acceptance.test.ts`.
 */
import { describe, expect, it } from 'vitest';
import {
  createRealCryptoProvider,
  createRealIdentity,
  createRealStatusListManager,
} from '../../../__tests__/audit/helpers/crypto-helpers.js';
import {
  MALFORMED_STATUS_SIZES,
  malformedSizeReason,
  TWO_BIT_MESSAGES,
  wideSizeReason,
} from '../../../__tests__/utils/status-sizes.js';
import { createDidKeyResolver } from '../../../delegation/did-key-resolver.js';
import type { FetchProvider } from '../../../providers/base.js';
import type { CredentialStatus } from '../../../types/protocol.js';
import { statusListGzipCodec } from '../../../utils/statuslist-gzip.js';
import { CheqdStatusListResolver } from '../statuslist-resolver.js';

/** A resolver pinned to an issuer whose list has `revoked` set among 16 entries, its entry 7, and a fetch count. */
async function resolverOver(revoked: number[]) {
  const crypto = createRealCryptoProvider();
  const pinned = await createRealIdentity(crypto);
  const { manager, storage } = createRealStatusListManager(crypto, pinned, { statusListBaseUrl: 'https://status.example' });
  const entries: CredentialStatus[] = [];
  for (let index = 0; index < 16; index += 1) entries.push(await manager.allocateStatusEntry('revocation'));
  for (const index of revoked) await manager.updateStatus(entries[index]!, true);
  let fetches = 0;
  const fetchProvider = {
    async fetch(url: string) {
      fetches += 1;
      const body = await storage.getStatusList(url);
      return new Response(JSON.stringify(body ?? null), { status: body == null ? 404 : 200 });
    },
  } as unknown as FetchProvider;
  const resolver = new CheqdStatusListResolver({
    fetchProvider,
    didResolver: createDidKeyResolver(),
    cryptoProvider: crypto,
    expectedIssuerDid: pinned.did,
    decompressor: statusListGzipCodec,
    cacheTtlMs: 0,
  });
  return { resolver, entry: entries[7]!, fetches: () => fetches };
}

describe('CheqdStatusListResolver and the size of a status entry', () => {
  it.each([
    ['its value is set at bits 14 and 15 and bit 7 is clear', [14, 15]],
    ['only bit 7, which is entry 3 of two bits, is set', [7]],
  ])('refuses an entry of two bits before any fetch when %s', async (_label, revoked) => {
    const { resolver, entry, fetches } = await resolverOver(revoked);
    await expect(resolver.checkStatus({ ...entry, statusSize: 2, statusMessage: TWO_BIT_MESSAGES })).rejects.toThrow(
      new Error(wideSizeReason(2)),
    );
    expect(fetches()).toBe(0);
  });

  it.each([
    ['states a statusSize of 1', { statusSize: 1 }],
    ['states no statusSize', {}],
  ])('reads the bit at the index of an entry that %s', async (_label, members) => {
    const clear = await resolverOver([6, 8, 14, 15]);
    expect(await clear.resolver.checkStatus({ ...clear.entry, ...members })).toBe(false);
    expect(clear.fetches()).toBe(1);
    const set = await resolverOver([7]);
    expect(await set.resolver.checkStatus({ ...set.entry, ...members })).toBe(true);
  });

  it.each(MALFORMED_STATUS_SIZES)('refuses an entry whose statusSize is %s before any fetch', async (_label, statusSize, named) => {
    const { resolver, entry, fetches } = await resolverOver([]);
    await expect(resolver.checkStatus({ ...entry, statusSize })).rejects.toThrow(new Error(malformedSizeReason(named)));
    expect(fetches()).toBe(0);
  });
});
