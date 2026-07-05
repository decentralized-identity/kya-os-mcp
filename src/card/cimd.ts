/**
 * KYA-OS Entity Card — CIMD L1 on-ramp bind.
 *
 * CIMD (draft-ietf-oauth-client-id-metadata-document, the MCP default since 2025-11-25) is
 * the L1 on-ramp with zero new infra: the OAuth `client_id` IS the entity's `did:web` in its
 * HTTPS form, and the `jwks_uri` the AS validates `private_key_jwt` against IS a mechanical
 * projection of the DID document's keys — so OAuth client-authentication becomes a DID-key
 * proof, and the access token the AS mints can be sender-constrained (RFC 9449 `cnf.jkt`) to
 * the exact key the per-request holder-of-key proof later carries (closing L1 → L3).
 *
 *   - `bindClientId` / `didFromClientId` — the W3C `did:web` ⇄ HTTPS bijection
 *     (`did:web:host:a:b` ⇄ `https://host/a/b`, the authority colon percent-encoded for ports).
 *   - `didKeyedJwks`        — DID-document `verificationMethod[]` Ed25519 → an OKP JWK set
 *     (`kid` preserved), stripping any private `d` and skipping non-Ed25519 methods.
 *   - `toClientMetadata`    — PROJECT the card into the CIMD doc served at the `client_id` URL
 *     (`token_endpoint_auth_method: private_key_jwt`, `_meta['org.kya-os/did']` = the DID).
 *   - `cardFromClientMetadata` — DERIVE the L1 card from a CIMD doc (a pure-CIMD client with
 *     no DID still onboards: a `did:web` is minted from its `client_id`).
 *   - `verifyCimdBind`      — the anti-substitution graft, FAIL-CLOSED: origin-equality
 *     (`did:web` host === `client_id` origin === `jwks_uri` origin) AND a reciprocal
 *     `alsoKnownAs` bind, so a hostile CIMD pointing `jwks_uri` at someone else's keys (or
 *     claiming a victim's DID) fails closed.
 *
 * Pure + deterministic — no I/O, no crypto. All key material is projected, never minted, so
 * no runtime (mcp-i-core) dependency leaks into `@kya-os/mcp`.
 */

import { isRecord } from '../utils/guards.js';
import { parseCard } from './resolve.js';
import type { CimdBinding, Ed25519PublicJwk, EntityCard } from './schema.js';

/** The OAuth `client_id` metadata-document prefix this module transforms. */
const DID_WEB_PREFIX = 'did:web:';

/** CIMD `token_endpoint_auth_method` — `private_key_jwt` IS the DID-key proof. */
export const PRIVATE_KEY_JWT = 'private_key_jwt';

/** Reverse-DNS `_meta` key carrying the entity's DID inside a CIMD document. */
export const KYA_OS_DID_META_KEY = 'org.kya-os/did';

// ── Shapes ──────────────────────────────────────────────────────────────────

/** A CIMD (client_id metadata document) projected from / parsed into an EntityCard. */
export interface ClientMetadata {
  client_id: string;
  client_name: string;
  token_endpoint_auth_method: typeof PRIVATE_KEY_JWT;
  jwks_uri: string;
  _meta: Record<typeof KYA_OS_DID_META_KEY, string>;
}

/** A JSON Web Key Set — the DID-keyed JWKS served at a CIMD `jwks_uri`. */
export interface Jwks {
  keys: Ed25519PublicJwk[];
}

/** The fail-closed result of `verifyCimdBind` — `ok` iff there are no `reasons`. */
export interface CimdBindResult {
  ok: boolean;
  reasons: string[];
}

// ── client_id ⇄ did:web bijection ─────────────────────────────────────────────

/**
 * Bind a `did:web` to its OAuth `client_id` (the W3C HTTPS form):
 *   `did:web:host:a:b`        → `https://host/a/b`
 *   `did:web:host%3A3000:a`   → `https://host:3000/a`   (authority colon percent-decoded)
 *   `did:web:host`            → `https://host`
 */
export function bindClientId(did: string): string {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new Error(`bindClientId: only did:web has an HTTPS client_id form (got "${did}")`);
  }
  const [authority, ...segments] = didWebSegments(did);
  if (!authority) throw new Error(`bindClientId: did:web "${did}" has no host authority`);
  const path = segments.length ? `/${segments.join('/')}` : '';
  return `https://${authority}${path}`;
}

/**
 * The inverse of `bindClientId`: an HTTPS `client_id` → its `did:web` (authority colon
 * percent-encoded for ports). `https://host/a/b` → `did:web:host:a:b`. https-only,
 * fail-closed.
 */
export function didFromClientId(clientId: string): string {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw new Error(`didFromClientId: client_id is not a valid URL ("${clientId}")`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`didFromClientId: client_id must be https (got "${url.protocol}")`);
  }
  const authority = encodeURIComponent(url.host);
  const segments = url.pathname.split('/').filter((s) => s.length > 0).map(encodeURIComponent);
  return `${DID_WEB_PREFIX}${[authority, ...segments].join(':')}`;
}

// ── DID-keyed JWKS ─────────────────────────────────────────────────────────────

/**
 * Project a DID document's `verificationMethod[]` into the JWKS the AS validates
 * `private_key_jwt` against. Only Ed25519 (`OKP`) keys are projected; `kid` is preserved
 * (the JWK's own `kid`, else the verification method `id`); any private `d` is stripped.
 */
export function didKeyedJwks(didDoc: unknown): Jwks {
  const vms =
    isRecord(didDoc) && Array.isArray(didDoc.verificationMethod) ? didDoc.verificationMethod : [];
  const keys: Ed25519PublicJwk[] = [];
  for (const vm of vms) {
    const jwk = vmToOkpJwk(vm);
    if (jwk) keys.push(jwk);
  }
  return { keys };
}

// ── CIMD document projection / derivation ──────────────────────────────────────

/**
 * Project a card into the CIMD document served at its `client_id` URL. The
 * `token_endpoint_auth_method` is `private_key_jwt` — so the AS validating it against
 * `jwks_uri` is verifying a DID-key signature.
 */
export function toClientMetadata(card: EntityCard, opts: { jwksUri: string }): ClientMetadata {
  return {
    client_id: bindClientId(card.id),
    client_name: card.name,
    token_endpoint_auth_method: PRIVATE_KEY_JWT,
    jwks_uri: opts.jwksUri,
    _meta: { [KYA_OS_DID_META_KEY]: card.id },
  };
}

/**
 * Derive the L1 card from a CIMD document. The DID is read from `_meta['org.kya-os/did']`
 * when present, else MINTED from the `client_id` (a pure-CIMD client still onboards). The
 * card is `entityType: 'client'` and carries the CIMD coordinates when a `jwks_uri` is given.
 * Fail-closed: the result is validated through `parseCard`.
 */
export function cardFromClientMetadata(meta: unknown): EntityCard {
  if (!isRecord(meta)) {
    throw new Error('cardFromClientMetadata: client metadata must be an object');
  }
  const clientId = meta.client_id;
  if (typeof clientId !== 'string') {
    throw new Error('cardFromClientMetadata: missing string client_id');
  }
  const did = didFromMeta(meta, clientId);
  const jwksUri = typeof meta.jwks_uri === 'string' ? meta.jwks_uri : undefined;
  const card: Record<string, unknown> = {
    id: did,
    entityType: 'client',
    name: typeof meta.client_name === 'string' && meta.client_name.length > 0 ? meta.client_name : did,
  };
  if (jwksUri !== undefined) card.cimd = { clientId, jwksUri };
  return parseCard(card);
}

// ── Anti-substitution bind (FAIL-CLOSED) ───────────────────────────────────────

/**
 * Verify a CIMD binding against the entity's DID document, FAIL-CLOSED. Enforces:
 *   1. origin-equality — `did:web` host === `client_id` origin === `jwks_uri` origin
 *      (a hostile CIMD pointing `jwks_uri` at another origin's keys fails here);
 *   2. a reciprocal `alsoKnownAs` bind — the DID document lists the `client_id` URL, so a
 *      CIMD cannot unilaterally claim a DID it does not control.
 * `ok` is true iff there are no `reasons`.
 */
export function verifyCimdBind(cimd: CimdBinding, didDoc: unknown): CimdBindResult {
  const reasons: string[] = [];
  const doc = isRecord(didDoc) ? didDoc : {};
  const did = typeof doc.id === 'string' ? doc.id : '';

  const didOrigin = safeDidOrigin(did, reasons);
  const clientOrigin = safeOrigin(cimd.clientId, 'client_id', reasons);
  const jwksOrigin = safeOrigin(cimd.jwksUri, 'jwks_uri', reasons);

  if (didOrigin && clientOrigin && didOrigin !== clientOrigin) {
    reasons.push(`origin mismatch: did:web (${didOrigin}) !== client_id (${clientOrigin})`);
  }
  if (clientOrigin && jwksOrigin && clientOrigin !== jwksOrigin) {
    reasons.push(`origin mismatch: client_id (${clientOrigin}) !== jwks_uri (${jwksOrigin})`);
  }
  if (!aliasListed(doc.alsoKnownAs, cimd.clientId)) {
    reasons.push(
      `DID document alsoKnownAs does not list client_id "${cimd.clientId}" (no reciprocal bind)`,
    );
  }
  return { ok: reasons.length === 0, reasons };
}

// ── Internals ──────────────────────────────────────────────────────────────────

/** Split a `did:web` into its percent-decoded `:`-separated segments (authority, then path). */
function didWebSegments(did: string): string[] {
  return did.slice(DID_WEB_PREFIX.length).split(':').map(decodeURIComponent);
}

/** The DID for a derived card: a declared `_meta['org.kya-os/did']`, else minted from client_id. */
function didFromMeta(meta: Record<string, unknown>, clientId: string): string {
  const block = isRecord(meta._meta) ? meta._meta : undefined;
  const declared = block?.[KYA_OS_DID_META_KEY];
  return typeof declared === 'string' ? declared : didFromClientId(clientId);
}

/** Project one verification method to a public OKP JWK (Ed25519 only; `d` stripped), or null. */
function vmToOkpJwk(vm: unknown): Ed25519PublicJwk | null {
  if (!isRecord(vm)) return null;
  const jwk = vm.publicKeyJwk;
  if (!isRecord(jwk) || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    return null;
  }
  const okp: Ed25519PublicJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  const kid = typeof jwk.kid === 'string' ? jwk.kid : typeof vm.id === 'string' ? vm.id : undefined;
  if (kid !== undefined) okp.kid = kid;
  return okp;
}

/** The HTTPS origin of a `did:web`'s `client_id` form, or null (recording a reason). */
function safeDidOrigin(did: string, reasons: string[]): string | null {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    reasons.push(`DID document id is not a did:web ("${did}")`);
    return null;
  }
  try {
    return new URL(bindClientId(did)).origin;
  } catch {
    reasons.push(`DID document id has no resolvable origin ("${did}")`);
    return null;
  }
}

/** The HTTPS origin of a URL, or null (recording a reason); non-https fails closed. */
function safeOrigin(url: string, label: string, reasons: string[]): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    reasons.push(`${label} is not a valid URL ("${url}")`);
    return null;
  }
  if (parsed.protocol !== 'https:') {
    reasons.push(`${label} must be https (got "${parsed.protocol}")`);
    return null;
  }
  return parsed.origin;
}

/** Whether the DID document's `alsoKnownAs` reciprocally lists the `client_id` URL. */
function aliasListed(alsoKnownAs: unknown, clientId: string): boolean {
  if (!Array.isArray(alsoKnownAs)) return false;
  return alsoKnownAs.some((aka) => typeof aka === 'string' && sameUrl(aka, clientId));
}

/** Normalized URL equality (tolerant of trailing-slash differences), fail-closed on invalid. */
function sameUrl(a: string, b: string): boolean {
  try {
    return new URL(a).href === new URL(b).href;
  } catch {
    return false;
  }
}
