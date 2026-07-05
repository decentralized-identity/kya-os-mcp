/**
 * KYA-OS Entity Card — REVOCATION seam (W3C Bitstring Status List v1.0).
 *
 * Capability + delegation credentials are revocable, so a verifier must be able to ask "is
 * THIS credential still live?" without the question's shape leaking into callers. This module
 * ships that question as a pluggable seam — `RevocationChecker` — so the VC-2.0 / status-list
 * churn stays behind one interface (the same injected-seam discipline `verifyCard` already
 * uses for its capability / attestation / accountability verifiers; NO `mcp-i-core` runtime
 * dependency leaks into `@kya-os/mcp`).
 *
 * `createRevocationChecker` is the DEFAULT implementation over W3C Bitstring Status List v1.0
 * (`BitstringStatusListEntry` — the StatusList2021 SUCCESSOR). It resolves the entry's
 * `statusListCredential` through the injected, SSRF-hardened {@link SafeFetch} seam, inflates
 * the multibase / GZIP `encodedList` bitstring, and reads the bit at `statusListIndex`.
 *
 * FAIL-CLOSED is the invariant: an unreachable status list, a malformed credential, a
 * mismatched `statusPurpose`, or an out-of-range index all resolve to `{ revoked: true }` —
 * the absence of proof-of-liveness is treated as revoked, never as "probably fine".
 *
 * Each verdict also reports `fresh`: `true` only when read from a LIVE, in-validity-window
 * status list. A stale (past `validUntil`) or not-yet-valid list still yields a readable bit
 * but `fresh: false`. {@link evaluateRevocationChain} walks a delegation chain root→leaf and
 * fail-closes (cascading: a revoked parent invalidates the whole subtree) on the first
 * revoked/unresolvable hop, threading `fresh` through every hop. The caller decides the gate:
 * L2 accepts a non-revoked chain (cached / offline-verifiable); L3 additionally requires
 * `fresh` (a live status check). NOT wired into `verifyCard` here — a later step injects it.
 */

import { base64urlDecodeToBytes } from '../utils/base64.js';
import { isRecord } from '../utils/guards.js';
import { assertStatusPurpose } from '../utils/statuslist-purpose.js';
import type { SafeFetch } from '../utils/safe-fetch.js';
import type { BitstringStatusListEntry } from './schema.js';

/** The `statusPurpose` this checker evaluates by default (revocation, not suspension). */
export const STATUS_PURPOSE_REVOCATION = 'revocation';

/**
 * Inflate a GZIP `encodedList` payload to the raw status bitstring. The seam that keeps this
 * verifier ISOMORPHIC: the default is Node-only (`node:zlib`), but a Workers / Deno / browser
 * deployment injects a `DecompressionStream`-based impl so the bundle never pulls `node:zlib`.
 * MAY be sync or async; MUST reject (throw / reject) on non-inflatable input (fail-closed).
 */
export type Decompress = (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>;

/** Multibase prefix for an unpadded base64url payload (W3C Bitstring Status List `encodedList`). */
const MULTIBASE_BASE64URL = 'u';

/**
 * Hard ceiling on the INFLATED status bitstring (16 MiB ⇒ ~134M entries — far beyond any
 * herd-privacy list). A status bitstring is fixed-size, so a generous fixed cap costs nothing
 * legitimate while stopping a decompression bomb: without it, the ~786 KB of GZIP that fits
 * inside SafeFetch's 1 MiB body cap inflates to ~800 MB, blocking the event loop on a synchronous
 * `gunzipSync`. Exceeding the cap makes `gunzipSync` throw, which the checker converts to
 * FAIL_CLOSED — preserving the module's uniform fail-closed posture. */
const MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024;

/** Verdict for ONE status entry. */
export interface RevocationStatus {
  /** True iff the status bit is set OR the status could not be proven clear (fail-closed). */
  revoked: boolean;
  /** True iff read from a LIVE, in-validity-window status list (drives the L2/L3 gate). */
  fresh: boolean;
}

/**
 * The injected revocation seam: resolve a `BitstringStatusListEntry` to a {@link RevocationStatus}.
 * A runtime supplies an implementation (the default is {@link createRevocationChecker}); a
 * caller may inject a cache-backed or offline variant. Implementations MUST fail closed.
 */
export type RevocationChecker = (entry: BitstringStatusListEntry) => Promise<RevocationStatus>;

/** Result of a cascading root→leaf chain walk. */
export interface RevocationChainResult {
  /** True iff EVERY hop is non-revoked (fail-closed: any revoked/unresolvable hop ⇒ false). */
  ok: boolean;
  /** True iff EVERY checked hop was read from a live, in-window status list. */
  fresh: boolean;
  /** Fail-closed reasons (empty ⇒ ok). */
  reasons: string[];
}

/** Dependencies for the default Bitstring Status List v1.0 checker. */
export interface RevocationCheckerDeps {
  /** SSRF-hardened fetch seam used to resolve the `statusListCredential`. */
  fetch: SafeFetch;
  /** Injectable clock returning epoch MILLISECONDS (deterministic freshness tests). */
  now?: () => number;
  /** `statusPurpose` to honour; default {@link STATUS_PURPOSE_REVOCATION}. */
  statusPurpose?: string;
  /**
   * Injectable GZIP inflation seam ({@link Decompress}). DEFAULT = `node:zlib` `gunzipSync` bounded
   * to the 16 MiB {@link MAX_STATUS_LIST_BYTES} `maxOutputLength` cap (so a decompression bomb
   * THROWS mid-inflation ⇒ fail-closed, never allocating the whole payload). Non-Node runtimes
   * inject a `DecompressionStream`-based impl; when they do, the default is never referenced so a
   * bundler tree-shakes `node:zlib` out of the graph. An injected impl SHOULD bound its own output
   * — {@link decodeStatusList} still applies the cap as a post-inflation backstop regardless.
   */
  decompress?: Decompress;
}

/** Fail-closed verdict: status indeterminate ⇒ treat as revoked AND not fresh. */
const FAIL_CLOSED: RevocationStatus = { revoked: true, fresh: false };

/**
 * Build the default `RevocationChecker` over W3C Bitstring Status List v1.0. Every outbound
 * request rides the injected {@link SafeFetch}; any failure on the path (unreachable, non-2xx,
 * malformed, wrong purpose, out-of-range index) resolves {@link FAIL_CLOSED}.
 */
export function createRevocationChecker(deps: RevocationCheckerDeps): RevocationChecker {
  const clock = deps.now ?? (() => Date.now());
  const wantedPurpose = deps.statusPurpose ?? STATUS_PURPOSE_REVOCATION;
  const decompress = deps.decompress ?? defaultNodeGunzip;
  return async function check(entry: BitstringStatusListEntry): Promise<RevocationStatus> {
    try {
      const credential = await fetchStatusList(entry.statusListCredential, deps.fetch);
      assertStatusPurpose(statusListSubject(credential).statusPurpose, wantedPurpose);
      const bits = await decodeStatusList(credential, decompress);
      const revoked = readBit(bits, parseIndex(entry.statusListIndex));
      return { revoked, fresh: isLive(credential, clock()) };
    } catch {
      return FAIL_CLOSED;
    }
  };
}

/**
 * Walk a delegation/capability chain root→leaf and fail-close on the first revoked or
 * unresolvable hop (cascading — a revoked ancestor invalidates the subtree, so the walk
 * short-circuits). `fresh` is the AND of every checked hop's liveness.
 *
 * An empty set of status entries is trivially `ok` (nothing is revoked — an offline/L2-acceptable
 * verdict) but is NOT `fresh`: freshness is a LIVE-check signal, and zero checks obtained no live
 * signal. An L3 liveness gate that requires `fresh` therefore cannot be satisfied by a chain that
 * simply omits all `credentialStatus` entries — it must consult at least one live status list.
 */
export async function evaluateRevocationChain(
  entries: readonly BitstringStatusListEntry[],
  check: RevocationChecker,
): Promise<RevocationChainResult> {
  let fresh = entries.length > 0; // no entries ⇒ no live signal ⇒ not fresh (fail-closed for L3)
  for (const [hop, entry] of entries.entries()) {
    const status = await check(entry);
    fresh = fresh && status.fresh;
    if (status.revoked) {
      return {
        ok: false,
        fresh: false,
        reasons: [
          `revocation: hop ${hop} (${entry.statusListCredential}#${entry.statusListIndex}) ` +
            'is revoked or unresolvable — fail-closed, subtree invalidated',
        ],
      };
    }
  }
  return { ok: true, fresh, reasons: [] };
}

// ── Internals ──────────────────────────────────────────────────────────────────

/** GET the status-list credential through SafeFetch (throws on non-2xx / non-object body). */
async function fetchStatusList(url: string, fetch: SafeFetch): Promise<Record<string, unknown>> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`revocation: status-list GET ${url} → ${res.status}`);
  const body = await res.json();
  if (!isRecord(body)) throw new Error('revocation: status-list credential is not an object');
  return body;
}

/** The `credentialSubject` of a status-list credential (throws if absent). */
function statusListSubject(credential: Record<string, unknown>): Record<string, unknown> {
  const subject = credential.credentialSubject;
  if (!isRecord(subject)) throw new Error('revocation: status-list has no credentialSubject');
  return subject;
}


/**
 * DEFAULT {@link Decompress}: `node:zlib` `gunzipSync` bounded to {@link MAX_STATUS_LIST_BYTES}
 * so an oversized inflation THROWS mid-stream (fail-closed) instead of allocating the whole bomb.
 * Pulled in via a DYNAMIC `import('node:zlib')` — only when no `decompress` was injected — so a
 * Workers / Deno / browser bundle that supplies its own seam keeps `node:zlib` out of the graph.
 */
async function defaultNodeGunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const { gunzipSync } = await import('node:zlib');
  return new Uint8Array(gunzipSync(bytes, { maxOutputLength: MAX_STATUS_LIST_BYTES }));
}

/**
 * Inflate the multibase / GZIP `encodedList` into the raw status bitstring bytes through the
 * injected {@link Decompress} seam. The 16 MiB cap is re-checked here as a POST-inflation backstop:
 * the default gunzip caps mid-stream, but an injected (edge) decompressor that does not bound its
 * own output is still fail-closed against an oversized bitstring at this seam.
 */
async function decodeStatusList(
  credential: Record<string, unknown>,
  decompress: Decompress,
): Promise<Uint8Array> {
  const encoded = statusListSubject(credential).encodedList;
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('revocation: status-list has no encodedList');
  }
  const base64url = encoded[0] === MULTIBASE_BASE64URL ? encoded.slice(1) : encoded;
  const inflated = await decompress(base64urlDecodeToBytes(base64url));
  if (inflated.length > MAX_STATUS_LIST_BYTES) {
    throw new Error(
      `revocation: status list too large: ${inflated.length} bytes exceeds ${MAX_STATUS_LIST_BYTES}`,
    );
  }
  return inflated instanceof Uint8Array ? inflated : new Uint8Array(inflated);
}

/**
 * Parse the decimal `statusListIndex` (a non-negative integer expressed as a string), fail-closed.
 * MUST be canonical decimal only: `Number()` alone would coerce whitespace (`" "` → 0), hex
 * (`"0x2A"` → 42), octal, `"+42"`, and `"1e1"` → 10 — silently reading a DIFFERENT (often clear) bit
 * than the credential names, so a revoked credential could read as live. Reject anything that is not
 * `[0-9]+`.
 */
function parseIndex(raw: string): number {
  if (!/^[0-9]+$/.test(raw)) {
    throw new Error(`revocation: statusListIndex must be a canonical non-negative decimal (got "${raw}")`);
  }
  const index = Number(raw);
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error(`revocation: statusListIndex out of range "${raw}"`);
  }
  return index;
}

/**
 * Read the status bit at `index` — MSB-first within each byte (W3C Bitstring encoding).
 * Uses FULL-PRECISION arithmetic (`Math.floor(index / 8)`, `index % 8`) rather than the 32-bit
 * bitwise ops `>>>`/`&`, which coerce their operand to uint32 first: an index ≥ 2^32 would
 * silently wrap onto a low byte (e.g. 2^32+5 ⇒ byte 0, bit 5) and read the WRONG — often clear —
 * bit, turning an out-of-range index that MUST fail-closed into a fail-OPEN "not revoked". With
 * full-precision arithmetic an out-of-range byte offset indexes past the bitstring, yielding
 * `undefined` ⇒ throw ⇒ FAIL_CLOSED. */
function readBit(bits: Uint8Array, index: number): boolean {
  const byte = bits[Math.floor(index / 8)];
  if (byte === undefined) {
    throw new Error(`revocation: statusListIndex ${index} is out of range for the status list`);
  }
  return (byte & (0x80 >> (index % 8))) !== 0;
}

/** True iff `nowMs` falls inside the credential's `[validFrom, validUntil]` window (if declared). */
function isLive(credential: Record<string, unknown>, nowMs: number): boolean {
  const validUntil = parseDate(credential.validUntil ?? credential.expirationDate);
  if (validUntil !== undefined && validUntil < nowMs) return false; // stale → cached-OK at L2 only
  const validFrom = parseDate(credential.validFrom ?? credential.issuanceDate);
  if (validFrom !== undefined && validFrom > nowMs) return false; // not yet valid
  return true;
}

/** Parse an ISO-8601 date string to epoch ms, or `undefined` when absent / unparseable. */
function parseDate(value: unknown): number | undefined {
  if (typeof value !== 'string') return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
}
