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
  MULTIBASE_BASE64URL,
  decodeStatusListPayload,
  readStatusBit,
} from '../utils/statuslist-bits.js';

export interface CompressionFunction {
  compress(data: Uint8Array): Promise<Uint8Array>;
}

export interface DecompressionFunction {
  decompress(data: Uint8Array): Promise<Uint8Array>;
}

export class BitstringManager {
  private bits: Uint8Array;
  private size: number;

  constructor(
    size: number,
    private compressor: CompressionFunction,
    // Accepted for signature symmetry with decode()/fromSetBits() and public
    // back-compat, but the INSTANCE never decompresses: decode() inflates via
    // the shared inflateStatusList() before construction, so no field is stored.
    _decompressor: DecompressionFunction
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
    const compressed = await this.compressor.compress(this.bits);
    return MULTIBASE_BASE64URL + this.base64urlEncode(compressed);
  }

  static async decode(
    encodedList: string,
    compressor: CompressionFunction,
    decompressor: DecompressionFunction
  ): Promise<BitstringManager> {
    const decompressed = await decodeStatusListPayload(encodedList, (bytes) =>
      decompressor.decompress(bytes)
    );

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

  private base64urlEncode(data: Uint8Array): string {
    const base64 = this.bytesToBase64(data);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private bytesToBase64(bytes: Uint8Array): string {
    const binary = Array.from(bytes)
      .map((byte) => String.fromCharCode(byte))
      .join('');
    return btoa(binary);
  }

  static fromSetBits(
    size: number,
    setBits: number[],
    compressor: CompressionFunction,
    decompressor: DecompressionFunction
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
 */
export async function isIndexSet(
  encodedList: string,
  index: number,
  decompressor: DecompressionFunction
): Promise<boolean> {
  const decompressed = await decodeStatusListPayload(encodedList, (bytes) =>
    decompressor.decompress(bytes)
  );
  return readStatusBit(decompressed, index);
}
