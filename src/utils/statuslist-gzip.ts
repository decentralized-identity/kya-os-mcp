/**
 * The GZIP codec for status-list bitstrings — the ONE implementation every
 * publisher and reader in this package defaults to (StatusList2021 and W3C
 * Bitstring Status List v1.0 both require the `encodedList` bitstring to be
 * GZIP-compressed).
 *
 * `node:zlib` is loaded with a DYNAMIC import on first use, never statically,
 * so a Workers / Deno / browser bundle that injects its own codec (for example
 * one built on `CompressionStream` / `DecompressionStream`) keeps `node:zlib`
 * out of its graph. The import handles its own failure, so a bundler for such
 * a runtime leaves it unresolved rather than failing the build, as it must now
 * that the pinned transport decodes a gzip response body through this codec.
 *
 * Inflation is bounded to {@link MAX_STATUS_LIST_BYTES} while it runs, so a
 * decompression bomb is refused mid-stream rather than allocated whole.
 */
import { MAX_STATUS_LIST_BYTES, type DecompressLimits } from './statuslist-bits.js';

type ZlibCallback = (error: Error | null, result: Uint8Array) => void;

type NodeZlib = typeof import('node:zlib');
let nodeZlibPromise: Promise<NodeZlib> | undefined;

/**
 * Load (and cache) `node:zlib`. Where it is absent, fail with a pointer to the
 * codec seam rather than a module-resolution error.
 */
function loadNodeZlib(): Promise<NodeZlib> {
  return (nodeZlibPromise ??= import('node:zlib').catch((cause: unknown) => {
    throw new Error(
      'statusListGzipCodec: node:zlib is unavailable in this runtime; inject a codec of your own, such as one built on DecompressionStream',
      { cause },
    );
  }));
}

/** Run a callback-style `node:zlib` operation as a promise of a plain `Uint8Array`. */
function settle(run: (done: ZlibCallback) => void): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    run((error, result) => (error ? reject(error) : resolve(new Uint8Array(result))));
  });
}

/** GZIP-compress a raw status bitstring. */
async function gzip(bits: Uint8Array): Promise<Uint8Array> {
  const zlib = await loadNodeZlib();
  return settle((done) => zlib.gzip(bits, done));
}

/**
 * Inflate a GZIP status-list payload, refusing (rejecting) one that is not
 * GZIP or that inflates past the reader's `limits.maxBytes`, or past
 * {@link MAX_STATUS_LIST_BYTES} when it is called with none.
 */
async function gunzip(payload: Uint8Array, limits?: DecompressLimits): Promise<Uint8Array> {
  const zlib = await loadNodeZlib();
  const maxOutputLength = limits?.maxBytes ?? MAX_STATUS_LIST_BYTES;
  return settle((done) => zlib.gunzip(payload, { maxOutputLength }, done));
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
