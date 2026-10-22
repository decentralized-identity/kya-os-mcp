/**
 * The GZIP codec for status-list bitstrings — the ONE implementation every
 * publisher and reader in this package defaults to (StatusList2021 and W3C
 * Bitstring Status List v1.0 both require the `encodedList` bitstring to be
 * GZIP-compressed).
 *
 * `node:zlib` is loaded with a DYNAMIC import on first use, never statically,
 * so a Workers / Deno / browser bundle that injects its own codec (for example
 * one built on `CompressionStream` / `DecompressionStream`) keeps `node:zlib`
 * out of its graph.
 *
 * Inflation is bounded to {@link MAX_STATUS_LIST_BYTES} while it runs, so a
 * decompression bomb is refused mid-stream rather than allocated whole.
 */
import { MAX_STATUS_LIST_BYTES } from './statuslist-bits.js';

type ZlibCallback = (error: Error | null, result: Uint8Array) => void;

/** Run a callback-style `node:zlib` operation as a promise of a plain `Uint8Array`. */
function settle(run: (done: ZlibCallback) => void): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    run((error, result) => (error ? reject(error) : resolve(new Uint8Array(result))));
  });
}

/** GZIP-compress a raw status bitstring. */
async function gzip(bits: Uint8Array): Promise<Uint8Array> {
  const zlib = await import('node:zlib');
  return settle((done) => zlib.gzip(bits, done));
}

/**
 * Inflate a GZIP status-list payload, refusing (rejecting) one that is not
 * GZIP or that inflates past {@link MAX_STATUS_LIST_BYTES}.
 */
async function gunzip(payload: Uint8Array): Promise<Uint8Array> {
  const zlib = await import('node:zlib');
  return settle((done) => zlib.gunzip(payload, { maxOutputLength: MAX_STATUS_LIST_BYTES }, done));
}

/**
 * The default status-list codec. One object serves as both the
 * `CompressionFunction` and the `DecompressionFunction` that
 * `StatusList2021Manager` and `BitstringManager` take, and its `decompress`
 * is the bare `Decompress` the Entity Card revocation checker takes.
 */
export const statusListGzipCodec = {
  compress: gzip,
  decompress: gunzip,
} as const;
