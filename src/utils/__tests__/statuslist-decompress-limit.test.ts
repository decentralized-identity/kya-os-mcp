/**
 * Every status-list reader tells its decompressor the most bytes a bitstring may inflate to, so an
 * injected decompressor, such as one a Workers deployment builds on `DecompressionStream`, can stop
 * a decompression bomb while it inflates rather than hand back the whole of it for the size check
 * after. The shipped codec stops at the cap it is given.
 */

import { gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';
import { createRealCryptoProvider, createRealIdentity, createRealStatusListManager } from '../../__tests__/audit/helpers/crypto-helpers.js';
import { webStreamsGunzip } from '../../__tests__/utils/web-streams-gzip.js';
import { createRevocationChecker } from '../../card/revocation.js';
import { BitstringManager, isIndexSet } from '../../delegation/bitstring.js';
import { createDidKeyResolver } from '../../delegation/did-key-resolver.js';
import { CheqdStatusListResolver } from '../../integrations/cheqd/statuslist-resolver.js';
import type { FetchProvider } from '../../providers/base.js';
import type { SafeFetch } from '../safe-fetch.js';
import { decodeStatusListPayload, MAX_STATUS_LIST_BYTES, type DecompressLimits } from '../statuslist-bits.js';
import { statusListGzipCodec } from '../statuslist-gzip.js';

const LIMITS: DecompressLimits = { maxBytes: MAX_STATUS_LIST_BYTES };
const encoded = (bits: Uint8Array): string => `u${gzipSync(bits).toString('base64url')}`;

/**
 * A `DecompressionStream` decompressor that stops reading once its output passes `maxBytes`, as a
 * Workers deployment would write one, counting the bytes it inflated.
 */
function boundedWebGunzip() {
  let inflated = 0;
  const decompress = vi.fn(async (bytes: Uint8Array, limits?: DecompressLimits): Promise<Uint8Array> => {
    const reader = new Blob([new Uint8Array(bytes)]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
    const chunks: Uint8Array[] = [];
    for (let read = await reader.read(); !read.done; read = await reader.read()) {
      inflated += read.value.length;
      if (inflated > (limits?.maxBytes ?? Infinity)) {
        await reader.cancel();
        throw new Error('status list inflates past its cap');
      }
      chunks.push(read.value);
    }
    return new Uint8Array(await new Blob(chunks).arrayBuffer());
  });
  return { decompress, inflated: () => inflated };
}

describe("a status-list decompressor is told the reader's cap", () => {
  it('by the shared decoder', async () => {
    const decompress = vi.fn(webStreamsGunzip);
    await decodeStatusListPayload(encoded(new Uint8Array(32)), decompress);
    expect(decompress).toHaveBeenCalledWith(expect.any(Uint8Array), LIMITS);
  });

  it('by the Entity Card checker, so an injected one stops a bomb while it inflates', async () => {
    const bomb = { credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation', encodedList: encoded(new Uint8Array(MAX_STATUS_LIST_BYTES + 1024 * 1024)) } };
    const fetch: SafeFetch = async () => ({ ok: true, status: 200, json: async () => bomb });
    const web = boundedWebGunzip();
    const check = createRevocationChecker({ fetch, decompress: web.decompress });
    const entry = { statusListCredential: 'https://issuer.example/status/1', statusListIndex: '5', statusPurpose: 'revocation' as const };
    expect(await check(entry)).toMatchObject({ revoked: true, fresh: false });
    expect(web.decompress).toHaveBeenCalledWith(expect.any(Uint8Array), LIMITS);
    expect(web.inflated()).toBeLessThan(MAX_STATUS_LIST_BYTES + 1024 * 1024);
  });

  it("through a DecompressionFunction, by BitstringManager and isIndexSet", async () => {
    const decompressor = { decompress: vi.fn(webStreamsGunzip) };
    await BitstringManager.decode(encoded(new Uint8Array(32)), undefined, decompressor);
    expect(await isIndexSet(encoded(new Uint8Array([0x80])), 0, decompressor)).toBe(true);
    expect(decompressor.decompress.mock.calls.map(([, limits]) => limits)).toEqual([LIMITS, LIMITS]);
  });

  it('through a DecompressionFunction, by CheqdStatusListResolver', async () => {
    const crypto = createRealCryptoProvider();
    const pinned = await createRealIdentity(crypto);
    const { manager, storage } = createRealStatusListManager(crypto, pinned, { statusListBaseUrl: 'https://status.example' });
    const entry = await manager.allocateStatusEntry('revocation');
    const fetchProvider = {
      fetch: async (url: string) => new Response(JSON.stringify(await storage.getStatusList(url))),
    } as unknown as FetchProvider;
    const decompressor = { decompress: vi.fn(webStreamsGunzip) };
    const resolver = new CheqdStatusListResolver({
      fetchProvider, didResolver: createDidKeyResolver(), cryptoProvider: crypto, expectedIssuerDid: pinned.did, decompressor, cacheTtlMs: 0,
    });
    expect(await resolver.checkStatus(entry)).toBe(false);
    expect(decompressor.decompress).toHaveBeenCalledWith(expect.any(Uint8Array), LIMITS);
  });
});

describe("the shipped codec's decompress", () => {
  it('stops at the cap it is given, and reads a bitstring that fits', async () => {
    const payload = gzipSync(new Uint8Array(1025));
    await expect(statusListGzipCodec.decompress(payload, { maxBytes: 1024 })).rejects.toThrow();
    expect(await statusListGzipCodec.decompress(payload, { maxBytes: 1025 })).toHaveLength(1025);
    expect(await statusListGzipCodec.decompress(payload)).toHaveLength(1025);
  });
});
