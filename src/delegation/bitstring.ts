/**
 * Bitstring Utilities for W3C status lists (StatusList2021 / Bitstring Status List v1.0).
 *
 * Implements GZIP compression + base64url encoding for efficient status lists.
 * Each bit represents credential status:
 * - 0: Not revoked/suspended
 * - 1: Revoked/suspended
 *
 * Bit order is MSB-FIRST within each byte (index 0 → the 0x80 bit), matching the W3C spec and
 * the Digital Bazaar reference `Bitstring` (`0x80 >> bit`). This is the SAME order the Entity Card
 * revocation reader (`src/card/revocation.ts`) uses, so both code paths read an identical
 * `encodedList` to the SAME verdict.
 *
 * Related Spec: W3C Bitstring Status List v1.0 (successor to StatusList2021)
 */

import {
  decodeStatusListPayload,
  encodeStatusListPayload,
  readStatusBit,
} from '../utils/statuslist-bits.js';
import { statusListGzipCodec } from '../utils/statuslist-gzip.js';

/**
 * Compresses a status bitstring for publication. MUST produce GZIP: it is the
 * only compression a status-list reader accepts, and `encode()` throws on
 * anything else. {@link statusListGzipCodec} is the shipped implementation
 * and the default.
 */
export interface CompressionFunction {
  compress(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Inflates a GZIP status-list payload. MUST reject input that is not GZIP;
 * a decoder throws when it returns its input unchanged. {@link statusListGzipCodec}
 * is the shipped implementation and the default.
 */
export interface DecompressionFunction {
  decompress(data: Uint8Array): Promise<Uint8Array>;
}

/** Inflate an `encodedList` to its raw bitstring, with the shipped GZIP codec by default. */
function inflate(
  encodedList: string,
  decompressor: DecompressionFunction = statusListGzipCodec
): Promise<Uint8Array> {
  return decodeStatusListPayload(encodedList, (bytes) => decompressor.decompress(bytes));
}

export class BitstringManager {
  private bits: Uint8Array;
  private size: number;

  /**
   * @param compressor - GZIP-compresses the bitstring on `encode()`. Defaults
   *   to {@link statusListGzipCodec}; `encode()` throws on output that is not GZIP.
   * @param _decompressor - Accepted for signature symmetry with `decode()` and
   *   `fromSetBits()`, and for back-compat. The instance never decompresses:
   *   `decode()` inflates before construction, so nothing is stored.
   */
  constructor(
    size: number,
    private compressor: CompressionFunction = statusListGzipCodec,
    _decompressor?: DecompressionFunction
  ) {
    this.size = size;
    const byteCount = Math.ceil(size / 8);
    this.bits = new Uint8Array(byteCount);
  }

  setBit(index: number, value: boolean): void {
    if (!Number.isInteger(index) || index < 0 || index >= this.size) {
      // `!Number.isInteger` also rejects NaN — a NaN index (e.g. parseInt("abc") upstream) would
      // otherwise slip past `< 0 || >= size` and read bits[NaN] = undefined = "not set" (fail-open).
      throw new Error(`Bit index ${index} out of range (0-${this.size - 1})`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    if (value) {
      this.bits[byteIndex]! |= 0x80 >> bitIndex; // MSB-first (W3C): index 0 → 0x80
    } else {
      this.bits[byteIndex]! &= 0xff ^ (0x80 >> bitIndex);
    }
  }

  getBit(index: number): boolean {
    if (!Number.isInteger(index) || index < 0 || index >= this.size) {
      // `!Number.isInteger` also rejects NaN — a NaN index (e.g. parseInt("abc") upstream) would
      // otherwise slip past `< 0 || >= size` and read bits[NaN] = undefined = "not set" (fail-open).
      throw new Error(`Bit index ${index} out of range (0-${this.size - 1})`);
    }

    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;

    return (this.bits[byteIndex]! & (0x80 >> bitIndex)) !== 0; // MSB-first (W3C)
  }

  getSetBits(): number[] {
    const setBits: number[] = [];
    for (let i = 0; i < this.size; i++) {
      if (this.getBit(i)) {
        setBits.push(i);
      }
    }
    return setBits;
  }

  async encode(): Promise<string> {
    return encodeStatusListPayload(this.bits, (bytes) => this.compressor.compress(bytes));
  }

  /**
   * Decode an `encodedList` into a manager.
   *
   * @param compressor - Used by the returned manager's `encode()`. Defaults to
   *   {@link statusListGzipCodec}.
   * @param decompressor - Inflates the GZIP payload. Defaults to
   *   {@link statusListGzipCodec}; decoding throws on a payload that is not
   *   GZIP and on a decompressor that returns its input unchanged.
   */
  static async decode(
    encodedList: string,
    compressor?: CompressionFunction,
    decompressor?: DecompressionFunction
  ): Promise<BitstringManager> {
    const decompressed = await inflate(encodedList, decompressor);

    const size = decompressed.length * 8;
    const manager = new BitstringManager(size, compressor, decompressor);
    manager.bits = decompressed;
    return manager;
  }

  getRawBits(): Uint8Array {
    return this.bits;
  }

  getSize(): number {
    return this.size;
  }

  /**
   * A manager of `size` entries with `setBits` set.
   *
   * @param compressor - Used by `encode()`. Defaults to {@link statusListGzipCodec}.
   * @param decompressor - Accepted for symmetry with `decode()`; unused.
   */
  static fromSetBits(
    size: number,
    setBits: number[],
    compressor?: CompressionFunction,
    decompressor?: DecompressionFunction
  ): BitstringManager {
    const manager = new BitstringManager(size, compressor, decompressor);
    for (const index of setBits) {
      manager.setBit(index, true);
    }
    return manager;
  }
}

/**
 * Read one status bit straight off an `encodedList` (decode + bounded inflate +
 * MSB-first read via `utils/statuslist-bits`). Fail-CLOSED: an out-of-range or
 * NaN index cannot be proven clear, so `readStatusBit` throws rather than
 * reading as "not set".
 *
 * @param decompressor - Inflates the GZIP payload. Defaults to
 *   {@link statusListGzipCodec}; reading throws on a payload that is not GZIP
 *   and on a decompressor that returns its input unchanged.
 */
export async function isIndexSet(
  encodedList: string,
  index: number,
  decompressor?: DecompressionFunction
): Promise<boolean> {
  return readStatusBit(await inflate(encodedList, decompressor), index);
}
