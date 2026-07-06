/**
 * KYA-OS Entity Card — DevX middleware (the 10-minute adoption path).
 *
 * Two ergonomic wrappers hide the RFC 9421 / 9449 / 8785 machinery behind one call each:
 *
 *   - `withKyaOsCard(card)` — the EMIT side. Bundles the three artifacts a server must publish
 *     (the `card.json` body, the `KyaOsEntityCard` DID-document service entry, and the
 *     `server.json` `_meta['org.kya-os/card']` fragment) and MOUNTS them onto existing objects —
 *     merging the `_meta` into a server.json and appending the service entry to a DID document,
 *     both immutably (a shallow clone; a stripped `_meta` degrades to a fetch, never a failure).
 *
 *   - `requireProof(deps, { minLevel? })` — the VERIFY side. Returns a per-request guard that
 *     reads the holder-of-key proof from `_meta['org.kya-os/proof@1']`, RECOMPUTES it via
 *     `./proof` ({@link verifyCardProof}) — every binding, fail-closed — enforces a minimum
 *     assurance, and returns a 401-shaped result on any failure. The caller passes the exact
 *     `{ method, params }` the client signed (i.e. WITHOUT `_meta`), so the recomputed
 *     `requestHash` matches.
 *
 * Pure composition over the shipped engine — no new crypto, no runtime (`mcp-i-core`) dependency.
 */

import type { ToolRequest } from '../proof/generator.js';
import { isRecord } from '../utils/guards.js';
import {
  toDidServiceEntry,
  toServerCardMeta,
  type DidServiceEntry,
  type ServerCardMeta,
} from './emit.js';
import {
  verifyCardProof,
  KYA_OS_CARD_PROOF_META_KEY,
  type ProofAssurance,
  type ProofVerifyResult,
  type VerifyProofDeps,
} from './proof/index.js';
import type { EntityCard } from './schema.js';

// ── Emit side: withKyaOsCard ────────────────────────────────────────────────

/** A structurally-typed MCP `server.json` (open shape; only `_meta` is read/merged). */
export interface ServerJsonLike {
  _meta?: Record<string, unknown>;
  [key: string]: unknown;
}

/** A structurally-typed DID document (open shape; only `service[]` is read/appended). */
export interface DidDocumentLike {
  service?: unknown[];
  [key: string]: unknown;
}

/** The three publishable artifacts of a card + immutable mounters for a server.json / DID doc. */
export interface KyaOsCardMount {
  /** Serve this at the entity's `card.json` endpoint (the canonical source of truth). */
  cardJson: EntityCard;
  /**
   * Add this to the entity's `did:web` DID-document `service[]` (the card's canonical home).
   * `undefined` for a `did:key` card, which has no HTTPS card endpoint — publish `serverMeta` instead.
   */
  didServiceEntry?: DidServiceEntry;
  /** Merge this into an MCP `server.json` / catalog `_meta`. */
  serverMeta: ServerCardMeta;
  /** Return a shallow clone of `serverJson` with the card `_meta` merged in (other keys preserved). */
  mountServerJson<T extends ServerJsonLike>(serverJson: T): T & { _meta: Record<string, unknown> };
  /** Return a shallow clone of `didDoc` with the `KyaOsEntityCard` service entry appended (dedup by id). */
  mountDidDocument<T extends DidDocumentLike>(didDoc: T): T & { service: unknown[] };
}

/**
 * Bundle a card into its three discovery artifacts and hand back immutable mounters. `opts.byRef`
 * projects the `_meta` as a lazy-fetch `cardRef` instead of an inline summary. NOTE: the DID
 * service entry (and a by-ref `_meta`) require a path-form `did:web` — a `did:key` dev card has no
 * HTTPS card endpoint and this fails closed (see `didWebToCardUrl`).
 */
export function withKyaOsCard(card: EntityCard, opts: { byRef?: boolean } = {}): KyaOsCardMount {
  const isDidWeb = card.id.startsWith('did:web:');
  if (opts.byRef && !isDidWeb) {
    throw new Error(
      `withKyaOsCard: { byRef } needs an HTTPS card URL that only a did:web card has (got "${card.id}"); ` +
        'use the default inline summary for a did:key card',
    );
  }
  // The DID-document service entry anchors the card at an HTTPS endpoint — only a did:web card has
  // one. A did:key dev card still projects an inline `serverMeta`; it just has no web service entry,
  // so building one is skipped rather than thrown (the caller may only want `mountServerJson`).
  const didServiceEntry = isDidWeb ? toDidServiceEntry(card) : undefined;
  const serverMeta = toServerCardMeta(card, opts);
  return {
    cardJson: card,
    didServiceEntry,
    serverMeta,
    mountServerJson: (serverJson) => mergeServerMeta(serverJson, serverMeta),
    mountDidDocument: (didDoc) => {
      if (!didServiceEntry) {
        throw new Error(
          `withKyaOsCard: card "${card.id}" is not a did:web card, so it has no DID-document service ` +
            'entry to mount — publish its inline serverMeta with mountServerJson instead',
        );
      }
      return appendService(didDoc, didServiceEntry);
    },
  };
}

/** Merge the card `_meta` fragment into a server.json `_meta` (shallow clone; card key wins). */
function mergeServerMeta<T extends ServerJsonLike>(
  serverJson: T,
  meta: ServerCardMeta,
): T & { _meta: Record<string, unknown> } {
  return { ...serverJson, _meta: { ...(serverJson._meta ?? {}), ...meta } };
}

/** Append the `KyaOsEntityCard` service entry to a DID document's `service[]` (dedup by id, clone). */
function appendService<T extends DidDocumentLike>(
  didDoc: T,
  entry: DidServiceEntry,
): T & { service: unknown[] } {
  const existing = Array.isArray(didDoc.service) ? didDoc.service : [];
  const deduped = existing.filter((s) => !(isRecord(s) && s.id === entry.id));
  return { ...didDoc, service: [...deduped, entry] };
}

// ── Verify side: requireProof ───────────────────────────────────────────────

/** A minimum proof assurance the guard enforces. Default: any valid proof (`L3-minus`) passes. */
export type MinProofLevel = ProofAssurance;

/** A snake_case rejection code (aligned to the `./proof` reason vocabulary). */
export type ProofGateCode = 'proof_missing' | 'proof_invalid' | 'proof_level_insufficient';

/** A 401-shaped rejection: a stable `code`, a human message, and the raw recompute `reasons`. */
export interface ProofGateError {
  code: ProofGateCode;
  message: string;
  reasons: string[];
}

/** The guard verdict: a pass carries the accountable principal + assurance; a fail is 401-shaped. */
export type ProofGateResult =
  | { ok: true; did: string; level: ProofAssurance; warnings?: string[] }
  | { ok: false; status: 401; error: ProofGateError };

/**
 * A per-request holder-of-key guard. Pass the exact request the client SIGNED (`{ method, params }`
 * without `_meta`) and the `_meta` bag that carried the proof; the guard recomputes every binding.
 */
export type ProofGuard = (req: ToolRequest, meta: unknown) => Promise<ProofGateResult>;

/** Options for {@link requireProof}. */
export interface RequireProofOptions {
  /** Minimum assurance a valid proof must carry (`L3` requires the AS `cnf` fusion). */
  minLevel?: MinProofLevel;
}

/** Assurance ordering for the `minLevel` gate (`L3-minus` is the floor, `L3` the ceiling). */
const ASSURANCE_RANK: Record<ProofAssurance, number> = { 'L3-minus': 1, L3: 2 };

/**
 * Build a per-request holder-of-key guard from the pre-bound proof-verification seams. The returned
 * guard reads `_meta['org.kya-os/proof@1']`, RECOMPUTES it against the request via {@link verifyCardProof},
 * enforces `opts.minLevel`, and returns `{ ok: true, did, level }` or a 401-shaped rejection. Fail-closed
 * throughout: a missing proof, a broken binding, a throwing verifier, or an assurance below `minLevel`
 * all reject.
 *
 * REPLAY DEFENSE (do NOT skip): `deps.consumeNonceIfFresh` MUST be an ATOMIC test-AND-set — it
 * records the nonce and returns `false` on a replay (SPEC §12.2). A pure read that never persists
 * the nonce is a replay hole. Wire the batteries-included `InMemoryNonceCache` (single-process,
 * race-free) or `consumeFromNonceCacheProvider` (shared store); with neither seam supplied every
 * request FAILS CLOSED (`nonce_seam_missing`).
 */
export function requireProof(deps: VerifyProofDeps, opts: RequireProofOptions = {}): ProofGuard {
  return async (req, meta) => {
    const proof = readCardProof(meta);
    if (proof === undefined) {
      return fail('proof_missing', 'no org.kya-os/proof@1 in _meta', ['proof_missing']);
    }
    const result = await recompute(proof, req, deps);
    if (!result.ok || result.did === undefined || result.level === undefined) {
      return fail('proof_invalid', 'holder-of-key proof did not verify', result.reasons);
    }
    const level = result.level;
    if (opts.minLevel && ASSURANCE_RANK[level] < ASSURANCE_RANK[opts.minLevel]) {
      const message = `proof assurance ${level} is below the required ${opts.minLevel}`;
      return fail('proof_level_insufficient', message, ['proof_level_insufficient']);
    }
    return {
      ok: true,
      did: result.did,
      level,
      ...(result.warnings ? { warnings: result.warnings } : {}),
    };
  };
}

/** Read the card proof (`org.kya-os/proof@1`) out of a `_meta` record (undefined when absent / not an
 *  object). A legacy session proof under `org.kya-os/proof` is a different key and is simply not seen. */
export function readCardProof(meta: unknown): unknown {
  return isRecord(meta) ? meta[KYA_OS_CARD_PROOF_META_KEY] : undefined;
}

/** Recompute the proof, fail-closed: a throwing verifier demotes to a rejected result (never escapes). */
async function recompute(
  proof: unknown,
  req: ToolRequest,
  deps: VerifyProofDeps,
): Promise<ProofVerifyResult> {
  try {
    return await verifyCardProof(proof, req, deps);
  } catch {
    return { ok: false, reasons: ['proof_verifier_threw'] };
  }
}

/** A 401-shaped rejection. */
function fail(code: ProofGateCode, message: string, reasons: string[]): ProofGateResult {
  return { ok: false, status: 401, error: { code, message, reasons } };
}
