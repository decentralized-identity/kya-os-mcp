import { describe, it, expect } from 'vitest';
import { gzipSync } from 'node:zlib';
import {
  createRevocationChecker,
  evaluateRevocationChain,
  STATUS_PURPOSE_REVOCATION,
  type RevocationChecker,
} from '../revocation.js';
import type { SafeFetch } from '../../utils/safe-fetch.js';
import type { BitstringStatusListEntry } from '../schema.js';

// ── Fixtures ────────────────────────────────────────────────────────────────

const STATUS_URL = 'https://issuer.example/status/1';
const BYTE_LEN = 32; // 256 bits — ample headroom for the test indices

/** Multibase / GZIP `encodedList` over a bitstring with the given indices set. */
function encodedListFor(revoked: number[], multibase = true): string {
  const bytes = new Uint8Array(BYTE_LEN);
  for (const i of revoked) {
    const byteIndex = i >>> 3;
    bytes[byteIndex] = (bytes[byteIndex] ?? 0) | (0x80 >> (i & 7));
  }
  const b64url = Buffer.from(gzipSync(Buffer.from(bytes))).toString('base64url');
  return multibase ? `${'u'}${b64url}` : b64url;
}

interface CredOpts {
  validFrom?: string;
  validUntil?: string;
  statusPurpose?: string;
  multibase?: boolean;
}

/** A W3C Bitstring Status List v1.0 credential with the given revoked indices. */
function statusCredential(revoked: number[], opts: CredOpts = {}): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: STATUS_URL,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    ...(opts.validFrom ? { validFrom: opts.validFrom } : {}),
    ...(opts.validUntil ? { validUntil: opts.validUntil } : {}),
    credentialSubject: {
      id: `${STATUS_URL}#list`,
      type: 'BitstringStatusList',
      statusPurpose: opts.statusPurpose ?? STATUS_PURPOSE_REVOCATION,
      encodedList: encodedListFor(revoked, opts.multibase ?? true),
    },
  };
}

/** A SafeFetch that serves one JSON body at every URL. */
function jsonFetch(body: unknown, status = 200): SafeFetch {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  });
}

function entryAt(index: number, url = STATUS_URL): BitstringStatusListEntry {
  return { statusListCredential: url, statusListIndex: String(index) };
}

const NOW = () => Date.parse('2026-06-30T00:00:00Z');

// ── Default checker over Bitstring Status List v1.0 ──────────────────────────

describe('createRevocationChecker (W3C Bitstring Status List v1.0)', () => {
  it('reports REVOKED + fresh when the entry index bit is set', async () => {
    const check = createRevocationChecker({ fetch: jsonFetch(statusCredential([5])), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: true });
  });

  it('reports FRESH + not-revoked when the entry index bit is clear', async () => {
    const check = createRevocationChecker({ fetch: jsonFetch(statusCredential([5])), now: NOW });
    expect(await check(entryAt(6))).toEqual({ revoked: false, fresh: true });
  });

  it('decodes a non-multibase encodedList too (back-compat with raw base64url)', async () => {
    const cred = statusCredential([7], { multibase: false });
    const check = createRevocationChecker({ fetch: jsonFetch(cred), now: NOW });
    expect(await check(entryAt(7))).toEqual({ revoked: true, fresh: true });
  });

  it('demotes to NOT fresh for a stale (past validUntil) list — still readable, cached-OK at L2', async () => {
    const cred = statusCredential([5], { validUntil: '2020-01-01T00:00:00Z' });
    const check = createRevocationChecker({ fetch: jsonFetch(cred), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  it('demotes to NOT fresh for a not-yet-valid (future validFrom) list', async () => {
    const cred = statusCredential([], { validFrom: '2099-01-01T00:00:00Z' });
    const check = createRevocationChecker({ fetch: jsonFetch(cred), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: false, fresh: false });
  });

  it('FAIL-CLOSED when the status list is unreachable (fetch throws)', async () => {
    const check = createRevocationChecker({
      fetch: async () => {
        throw new Error('ECONNREFUSED');
      },
    });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  it('FAIL-CLOSED on a non-2xx status-list response', async () => {
    const check = createRevocationChecker({ fetch: jsonFetch({}, 404), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  it('FAIL-CLOSED on a malformed (non-inflatable) encodedList', async () => {
    const cred = statusCredential([5]);
    (cred.credentialSubject as Record<string, unknown>).encodedList = 'u_not_gzip_';
    const check = createRevocationChecker({ fetch: jsonFetch(cred), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  it('FAIL-CLOSED on a statusListIndex out of range for the bitstring', async () => {
    const check = createRevocationChecker({ fetch: jsonFetch(statusCredential([5])), now: NOW });
    expect(await check(entryAt(99_999))).toEqual({ revoked: true, fresh: false });
  });

  it('FAIL-CLOSED when the list is for a different statusPurpose (suspension ≠ revocation)', async () => {
    const cred = statusCredential([5], { statusPurpose: 'suspension' });
    const check = createRevocationChecker({ fetch: jsonFetch(cred), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  // ── Security regressions (fail-closed hardening) ───────────────────────────

  it('FAIL-CLOSED on a decompression-bomb encodedList (inflates past the output cap)', async () => {
    // ~17 MiB of zeros gzips to a few KB yet inflates beyond MAX_STATUS_LIST_BYTES (16 MiB).
    // Pre-fix `gunzipSync` had no `maxOutputLength`, so it allocated the whole ~17 MiB (the DoS)
    // and read a clear bit ⇒ {revoked:false}. With the cap, `gunzipSync` throws ⇒ FAIL_CLOSED.
    const cred = statusCredential([]);
    const bomb = Buffer.from(gzipSync(Buffer.alloc(17 * 1024 * 1024))).toString('base64url');
    (cred.credentialSubject as Record<string, unknown>).encodedList = `u${bomb}`;
    const check = createRevocationChecker({ fetch: jsonFetch(cred), now: NOW });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  it('FAIL-CLOSED on a statusListIndex ≥ 2^32 (no 32-bit wrap onto a clear low bit)', async () => {
    // 2^32 + 5 = 4_294_967_301. The old `index >>> 3` / `index & 7` coerced to uint32, wrapping
    // this onto byte 0 / bit 5 — clear on an empty list ⇒ fail-OPEN {revoked:false}. Full-precision
    // arithmetic indexes past the 32-byte bitstring ⇒ out-of-range ⇒ FAIL_CLOSED.
    const check = createRevocationChecker({ fetch: jsonFetch(statusCredential([])), now: NOW });
    expect(await check(entryAt(4_294_967_301))).toEqual({ revoked: true, fresh: false });
  });
});

// ── Injectable decompression seam (isomorphic: non-node:zlib runtimes) ───────

describe('createRevocationChecker (injected decompress seam)', () => {
  /** A NON-gzip `encodedList`: raw bitstring, base64url'd, so only an IDENTITY decompress reads it. */
  function rawEncodedListFor(revoked: number[], multibase = true): string {
    const bytes = new Uint8Array(BYTE_LEN);
    for (const i of revoked) {
      const byteIndex = i >>> 3;
      bytes[byteIndex] = (bytes[byteIndex] ?? 0) | (0x80 >> (i & 7));
    }
    const b64url = Buffer.from(bytes).toString('base64url');
    return multibase ? `u${b64url}` : b64url;
  }

  /** Serve a credential whose `encodedList` is NOT gzip — the default node:zlib path would throw. */
  function rawCredential(revoked: number[], multibase = true): Record<string, unknown> {
    const cred = statusCredential(revoked);
    (cred.credentialSubject as Record<string, unknown>).encodedList = rawEncodedListFor(revoked, multibase);
    return cred;
  }

  const identity = (bytes: Uint8Array): Uint8Array => bytes; // stands in for a DecompressionStream impl

  it('reads a REVOKED bit true through an INJECTED (non-node:zlib) decompress', async () => {
    const check = createRevocationChecker({
      fetch: jsonFetch(rawCredential([5])),
      now: NOW,
      decompress: identity,
    });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: true });
  });

  it('reads a CLEAR bit false through an INJECTED decompress (async, Promise-returning)', async () => {
    const check = createRevocationChecker({
      fetch: jsonFetch(rawCredential([5])),
      now: NOW,
      decompress: async (bytes) => identity(bytes), // async seam (mirrors DecompressionStream)
    });
    expect(await check(entryAt(6))).toEqual({ revoked: false, fresh: true });
  });

  it('still strips the multibase `u` prefix under an injected decompress', async () => {
    const check = createRevocationChecker({
      fetch: jsonFetch(rawCredential([7], /* multibase */ true)),
      now: NOW,
      decompress: identity,
    });
    expect(await check(entryAt(7))).toEqual({ revoked: true, fresh: true });
  });

  it('FAIL-CLOSED on a bomb via the injected seam (output past the 16 MiB backstop cap)', async () => {
    const check = createRevocationChecker({
      fetch: jsonFetch(rawCredential([])),
      now: NOW,
      decompress: () => new Uint8Array(17 * 1024 * 1024), // an unbounded edge impl inflates past the cap
    });
    expect(await check(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });

  it('FAIL-CLOSED on an out-of-range index under an injected decompress (MSB read still guards)', async () => {
    const check = createRevocationChecker({
      fetch: jsonFetch(rawCredential([])),
      now: NOW,
      decompress: identity,
    });
    expect(await check(entryAt(99_999))).toEqual({ revoked: true, fresh: false });
  });

  it('DEFAULT (node:zlib) path is unchanged — inflates real gzip AND rejects non-gzip bytes', async () => {
    // No `decompress` injected ⇒ the default node:zlib gunzip seam. A genuine gzip list reads;
    // the SAME raw (non-gzip) bytes the identity seam accepts must FAIL-CLOSED here (proving the
    // default really is gunzip, not a pass-through).
    const gzipped = createRevocationChecker({ fetch: jsonFetch(statusCredential([5])), now: NOW });
    expect(await gzipped(entryAt(5))).toEqual({ revoked: true, fresh: true });
    const rawUnderDefault = createRevocationChecker({ fetch: jsonFetch(rawCredential([5])), now: NOW });
    expect(await rawUnderDefault(entryAt(5))).toEqual({ revoked: true, fresh: false });
  });
});

// ── Cascading chain evaluation (root → leaf, fail-closed) ────────────────────

describe('evaluateRevocationChain (cascading, fail-closed)', () => {
  const allClear: RevocationChecker = async () => ({ revoked: false, fresh: true });

  it('is ok + fresh when every hop is clear and live', async () => {
    const result = await evaluateRevocationChain([entryAt(0), entryAt(1)], allClear);
    expect(result).toEqual({ ok: true, fresh: true, reasons: [] });
  });

  it('treats an empty chain as ok but NOT fresh (zero live checks cannot prove liveness)', async () => {
    expect(await evaluateRevocationChain([], allClear)).toEqual({ ok: true, fresh: false, reasons: [] });
  });

  it('FAIL-CLOSED and short-circuits the subtree on the first revoked hop', async () => {
    let calls = 0;
    const check: RevocationChecker = async (entry) => {
      calls += 1;
      return entry.statusListIndex === '0'
        ? { revoked: true, fresh: true }
        : { revoked: false, fresh: true };
    };
    const result = await evaluateRevocationChain([entryAt(0), entryAt(1)], check);
    expect(result.ok).toBe(false);
    expect(result.fresh).toBe(false);
    expect(result.reasons).toHaveLength(1);
    expect(result.reasons[0]).toMatch(/hop 0/);
    expect(calls).toBe(1); // a revoked root invalidates the subtree — the leaf is never checked
  });

  it('stays ok but NOT fresh when a hop is clear yet stale (L2 passes, L3 demoted)', async () => {
    const check: RevocationChecker = async (entry) => ({
      revoked: false,
      fresh: entry.statusListIndex !== '1',
    });
    const result = await evaluateRevocationChain([entryAt(0), entryAt(1)], check);
    expect(result).toEqual({ ok: true, fresh: false, reasons: [] });
  });

  it('integrates with the default checker: a revoked leaf fails the chain', async () => {
    const rootUrl = 'https://issuer.example/status/root';
    const leafUrl = 'https://issuer.example/status/leaf';
    const fetch: SafeFetch = async (url) => ({
      ok: true,
      status: 200,
      json: () => Promise.resolve(url.includes('root') ? statusCredential([]) : statusCredential([3])),
    });
    const check = createRevocationChecker({ fetch, now: NOW });
    const result = await evaluateRevocationChain(
      [entryAt(0, rootUrl), entryAt(3, leafUrl)],
      check,
    );
    expect(result.ok).toBe(false);
    expect(result.reasons[0]).toMatch(/leaf/);
  });
});
