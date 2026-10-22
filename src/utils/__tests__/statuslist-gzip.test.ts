import { describe, it, expect, vi } from 'vitest';
import { MAX_STATUS_LIST_BYTES } from '../statuslist-bits.js';
import { statusListGzipCodec } from '../statuslist-gzip.js';
import { webStreamsGunzip, webStreamsGzip } from '../../__tests__/utils/web-streams-gzip.js';
import { statusListGzipCodec as fromRoot } from '../../index.js';
import { statusListGzipCodec as fromDelegation } from '../../delegation/index.js';

describe('statusListGzipCodec', () => {
  it('is the one codec the package root and the delegation entry both export', () => {
    expect(fromRoot).toBe(statusListGzipCodec);
    expect(fromDelegation).toBe(statusListGzipCodec);
  });

  it('round-trips a bitstring through GZIP', async () => {
    const bits = new Uint8Array([0b10100000, 0, 0b00000001]);
    const compressed = await statusListGzipCodec.compress(bits);
    expect([compressed[0], compressed[1]]).toEqual([0x1f, 0x8b]);
    expect(await statusListGzipCodec.decompress(compressed)).toEqual(bits);
  });

  it('interoperates with GZIP made by the Web Streams API', async () => {
    const bits = new Uint8Array([0xff, 0x00, 0x80]);
    expect(await statusListGzipCodec.decompress(await webStreamsGzip(bits))).toEqual(bits);
    expect(await webStreamsGunzip(await statusListGzipCodec.compress(bits))).toEqual(bits);
  });

  it('rejects a payload that is not GZIP', async () => {
    await expect(statusListGzipCodec.decompress(new Uint8Array([1, 2, 3]))).rejects.toThrow();
  });

  it('refuses to inflate past the status-list cap', async () => {
    const bomb = await statusListGzipCodec.compress(new Uint8Array(MAX_STATUS_LIST_BYTES + 1));
    await expect(statusListGzipCodec.decompress(bomb)).rejects.toThrow();
  });

  it('loads node:zlib only once a codec function runs', async () => {
    vi.resetModules();
    const loaded = vi.fn();
    vi.doMock('node:zlib', async (importOriginal) => {
      loaded();
      return importOriginal();
    });
    try {
      const { createRevocationChecker } = await import('../../card/revocation.js');
      const { statusListGzipCodec: codec } = await import('../statuslist-gzip.js');

      // A checker given an edge decompressor reads a GZIP list without node:zlib.
      const encodedList = `u${Buffer.from(await webStreamsGzip(new Uint8Array([0x40]))).toString('base64url')}`;
      const check = createRevocationChecker({
        fetch: async () => ({
          ok: true,
          status: 200,
          json: async () => ({ credentialSubject: { statusPurpose: 'revocation', encodedList } }),
        }),
        decompress: webStreamsGunzip,
      });
      expect((await check({ statusListCredential: 'https://issuer.example/s', statusListIndex: '1' })).revoked).toBe(true);
      expect(loaded).not.toHaveBeenCalled();

      await codec.compress(new Uint8Array(1));
      expect(loaded).toHaveBeenCalledOnce();
    } finally {
      vi.doUnmock('node:zlib');
      vi.resetModules();
    }
  });
});
