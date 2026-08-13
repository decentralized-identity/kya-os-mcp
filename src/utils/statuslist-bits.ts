/**
 * Status-list primitives — the ONE home for the mechanics every W3C
 * status-list reader AND publisher in this package shares (StatusList2021 /
 * Bitstring Status List v1.0): canonical index parsing, bounded payload
 * inflation, the MSB-first bit read, and the anchor-fitness guard.
 *
 * Consumers: `delegation/bitstring.ts` (+ `statuslist-manager.ts`) and
 * `card/revocation.ts` — previously each carried its own copy of exactly this
 * knowledge, with the drift risk the source comments could only pledge away.
 * The seams' POLICIES stay where they are (the delegation path throws and the
 * caller maps to `status_unresolvable`; the card path catches everything into
 * `FAIL_CLOSED` and models freshness) — only the mechanics live here.
 *
 * FAIL-CLOSED throughout: a non-canonical index, an oversized inflation, or
 * an unreadable bit throws rather than reading as "not revoked".
 */
import { base64urlDecodeToBytes } from './base64.js';
import { isRecord } from './guards.js';

/**
 * Hard ceiling on an INFLATED status bitstring (16 MiB ≈ 134M entries — far
 * beyond any herd-privacy list). A fixed cap costs nothing legitimate while
 * stopping a decompression bomb; exceeding it throws (fail-closed).
 */
export const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/**
 * The W3C Bitstring Status List `encodedList` multibase prefix (base64url,
 * no padding). A gzip stream's fixed magic byte (0x1f) makes its base64url
 * start with `H`, never `u`, so a leading `u` is unambiguously the multibase
 * code rather than payload.
 */
export const MULTIBASE_BASE64URL = 'u';

/**
 * Parse a decimal `statusListIndex` (a non-negative integer expressed as a
 * string), fail-closed. Canonical decimal ONLY: `Number()` alone would coerce
 * whitespace (`" "` → 0), hex (`"0x2A"` → 42), `"+42"`, and `"1e1"` → 10 —
 * silently reading a DIFFERENT (often clear) bit than the credential names,
 * so a revoked credential could read as live.
 */
export function parseStatusListIndex(raw: string): number {
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error(
      `Invalid statusListIndex "${raw}" — must be a canonical non-negative decimal`,
    );
  }
  const index = Number(raw);
  if (!Number.isSafeInteger(index)) {
    throw new Error(`statusListIndex "${raw}" exceeds the safe integer range`);
  }
  return index;
}

/**
 * Decode a status-list `encodedList` to the raw bitstring: strip the optional
 * multibase `u` prefix, base64url-decode, run the injected decompressor, and
 * re-check the {@link MAX_STATUS_LIST_BYTES} cap POST-inflation as a backstop
 * (a production decompressor SHOULD also bound output during inflation).
 * The decompressor is the bare-function common denominator — an
 * object-shaped `DecompressionFunction` adapts inline:
 * `(b) => decompressor.decompress(b)`.
 */
export async function decodeStatusListPayload(
  encodedList: string,
  decompress: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>,
): Promise<Uint8Array> {
  const payload =
    encodedList[0] === MULTIBASE_BASE64URL ? encodedList.slice(1) : encodedList;
  const inflated = await decompress(base64urlDecodeToBytes(payload));
  if (inflated.length > MAX_STATUS_LIST_BYTES) {
    throw new Error(
      `Status list too large: ${inflated.length} bytes exceeds ${MAX_STATUS_LIST_BYTES}`,
    );
  }
  return inflated instanceof Uint8Array ? inflated : new Uint8Array(inflated);
}

/**
 * Read the status bit at `index` — MSB-first within each byte (W3C Bitstring
 * encoding). Uses FULL-PRECISION arithmetic (`Math.floor(index / 8)`) rather
 * than 32-bit bitwise ops, which coerce to uint32 first: an index ≥ 2^32
 * would silently wrap onto a low byte and read the WRONG — often clear — bit,
 * turning an out-of-range index that MUST fail-closed into a fail-OPEN "not
 * revoked". NaN/negative/fractional/out-of-buffer indexes throw.
 */
export function readStatusBit(bits: Uint8Array, index: number): boolean {
  const byte = Number.isInteger(index) && index >= 0
    ? bits[Math.floor(index / 8)]
    : undefined;
  if (byte === undefined) {
    throw new Error(
      `Bit index ${index} out of range for the status list`,
    );
  }
  return (byte & (0x80 >> index % 8)) !== 0;
}

/**
 * Assert a status-list credential is fit to ANCHOR (publish) — signed, and
 * actually carrying a bitstring. Method-agnostic on purpose: the cheqd DLR
 * publisher enforces it today; any future anchoring integration (another
 * DLR-bearing DID method, a different chain) imports the same guard rather
 * than re-deriving "what makes a status list publishable". An unsigned or
 * bitstring-less list anchored on-chain would be an unverifiable — and
 * therefore fail-closed-unusable — revocation source for every holder.
 */
export function assertAnchorableStatusListCredential(content: unknown): void {
  if (!isRecord(content)) {
    throw new Error('Status list credential must be an object');
  }
  if (!content.proof) {
    throw new Error('Refusing to publish an UNSIGNED status list credential');
  }
  const subject = content.credentialSubject;
  if (
    !isRecord(subject) ||
    typeof subject.encodedList !== 'string' ||
    subject.encodedList.length === 0
  ) {
    throw new Error(
      'Status list credential is missing credentialSubject.encodedList',
    );
  }
}
