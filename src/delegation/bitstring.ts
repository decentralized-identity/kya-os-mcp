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

export interface CompressionFunction {
  compress(data: Uint8Array): Promise<Uint8Array>;
}

export interface DecompressionFunction {
  decompress(data: Uint8Array): Promise<Uint8Array>;
}

/** Fixed ceiling on an inflated status bitstring (16 MiB ≈ 134M entries) — fail-closed against a
 *  decompression bomb. Mirrors the cap in the card revocation reader (src/card/revocation.ts). */
const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/** The W3C Bitstring Status List `encodedList` multibase prefix (base64url, no padding). `encode`
 *  emits it and `base64urlDecode` strips it, so this reader is interoperable with the card
 *  revocation reader (src/card/revocation.ts) and any conformant issuer. A gzip stream's fixed
 *  magic byte (0x1f) makes its base64url start with `H`, never `u`, so a leading `u` is
 *  unambiguously the multibase code rather than payload. */
const MULTIBASE_BASE64URL = 'u';

export class BitstringManager {
  private bits: Uint8Array;
  private size: number;

  constructor(
    size: number,
    private compressor: CompressionFunction,
    private decompressor: DecompressionFunction
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
    const decompressed = await inflateStatusList(encodedList, decompressor);

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
 * Decode a base64url `encodedList`, stripping an optional leading W3C multibase `u` prefix so this
 * module's own `encode` output and a conformant issuer's `encodedList` decode identically (matches
 * src/card/revocation.ts). Standalone so both {@link BitstringManager.decode} and {@link isIndexSet}
 * share ONE reader (no private-visibility casts).
 */
function decodeBase64urlMultibase(encoded: string): Uint8Array {
  const payload = encoded[0] === MULTIBASE_BASE64URL ? encoded.slice(1) : encoded;
  let standard = payload.replace(/-/g, '+').replace(/_/g, '/');
  standard += '='.repeat((4 - (standard.length % 4)) % 4);
  const binary = atob(standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Decode + decompress a status-list `encodedList`, FAIL-CLOSED against a decompression bomb via a
 * post-inflation size cap. The single reader path shared by {@link BitstringManager.decode} and
 * {@link isIndexSet}, so both bound inflation identically. (Production decompressors SHOULD also
 * bound output DURING inflation.)
 */
async function inflateStatusList(
  encodedList: string,
  decompressor: DecompressionFunction
): Promise<Uint8Array> {
  const decompressed = await decompressor.decompress(decodeBase64urlMultibase(encodedList));
  if (decompressed.length > MAX_STATUS_LIST_BYTES) {
    throw new Error(`Status list too large: ${decompressed.length} bytes exceeds ${MAX_STATUS_LIST_BYTES}`);
  }
  return decompressed;
}

export async function isIndexSet(
  encodedList: string,
  index: number,
  decompressor: DecompressionFunction
): Promise<boolean> {
  const decompressed = await inflateStatusList(encodedList, decompressor);

  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;

  if (!Number.isInteger(index) || index < 0 || byteIndex >= decompressed.length) {
    // Fail-CLOSED: an out-of-range/NaN index cannot be proven clear, so it must NOT read as "not
    // set". `!Number.isInteger` is required because `byteIndex >= length` is FALSE for a NaN index
    // (any comparison with NaN is false), which would otherwise slip past and read bits[NaN] =
    // undefined = live (the fail-open getBit already rejects, but this standalone reader did not).
    throw new Error(`Bit index ${index} out of range for the status list`);
  }

  return (decompressed[byteIndex]! & (0x80 >> bitIndex)) !== 0; // MSB-first (W3C)
}
