/**
 * KYA-OS Entity Card proof — canonicalization + hashing (the single source of truth).
 *
 * Both the minter ({@link buildCardProof}) and the verifier ({@link verifyCardProof}) derive
 * their signing input from HERE, so the two can never drift. Reuses `json-canonicalize` (RFC
 * 8785 / JCS) — the same canonicalizer `src/proof/generator.ts` uses — and the same
 * `{ method, params }` request shape, so the `requestHash` is cross-implementation stable.
 *
 * `requestHash` is emitted in the RFC 9421 Content-Digest structured-field form
 * (`sha-256=:<base64>:`) so the HTTP Message Signature sibling can carry it verbatim.
 */

import { canonicalize } from 'json-canonicalize';
import type { ToolRequest } from '../../proof/generator.js';
import { base64ToBytes, base64urlDecodeToBytes, bytesToBase64 } from '../../utils/base64.js';
import type { CardProofMeta } from './types.js';

const encoder = new TextEncoder();

/** A signing JWK (Ed25519 OKP or P-256 EC; public, or private with `d`) — typed locally to avoid a
 *  DOM lib dependency. `y` is present only for EC (P-256) keys. */
export interface RawSigningJwk {
  kty: string;
  crv: string;
  x: string;
  y?: string;
  d?: string;
}

/** Opaque WebCrypto key handle (avoids a DOM-lib `CryptoKey` dependency). */
type CryptoKeyLike = object;

/** The minimal WebCrypto surface this module needs — typed locally to avoid a DOM lib dependency. */
interface SubtleCryptoLike {
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  importKey(
    format: 'jwk',
    keyData: RawSigningJwk,
    algorithm: { name: string; namedCurve?: string },
    extractable: boolean,
    keyUsages: string[],
  ): Promise<CryptoKeyLike>;
  sign(algorithm: { name: string; hash?: string }, key: CryptoKeyLike, data: Uint8Array): Promise<ArrayBuffer>;
  verify(
    algorithm: { name: string; hash?: string },
    key: CryptoKeyLike,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;
}

const ED25519 = { name: 'Ed25519' } as const;
const ES256_IMPORT = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ES256_SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

/** The WebCrypto subtle (Node ≥ 20 / Workers via `globalThis.crypto`), fail-closed when absent. */
function subtle(): SubtleCryptoLike {
  const c = (globalThis as { crypto?: { subtle?: SubtleCryptoLike } }).crypto;
  if (!c?.subtle) throw new Error('card/proof: WebCrypto SubtleCrypto is unavailable');
  return c.subtle;
}

/** SHA-256 over `bytes`. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-256', bytes));
}

/**
 * A RAW EdDSA signature (NOT JWS-framed) over `data` with an Ed25519 private JWK. This is the
 * signature a stock RFC 9421 verifier expects over the signature base — distinct from the detached
 * JWS, whose signature also covers the protected header and so can never satisfy a 9421 verifier.
 */
export async function ed25519SignRaw(privateJwk: RawSigningJwk, data: Uint8Array): Promise<Uint8Array> {
  const s = subtle();
  const key = await s.importKey('jwk', privateJwk, ED25519, false, ['sign']);
  return new Uint8Array(await s.sign(ED25519, key, data));
}

/** Verify a RAW EdDSA signature over `data` against an Ed25519 public JWK. Fail-closed on error. */
export async function ed25519VerifyRaw(
  publicJwk: RawSigningJwk,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  try {
    const s = subtle();
    const key = await s.importKey('jwk', { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x }, ED25519, false, ['verify']);
    return await s.verify(ED25519, key, signature, data);
  } catch {
    return false;
  }
}

/**
 * A RAW ES256 signature (ECDSA P-256 over SHA-256, `r||s` — NOT DER, NOT JWS-framed) over `data`
 * with a P-256 private JWK. This is the RFC 9421 `ecdsa-p256-sha256` form a stock 9421 verifier
 * reconstructs over the signature base — the FIPS-eligible sibling to {@link ed25519SignRaw}.
 */
export async function es256SignRaw(privateJwk: RawSigningJwk, data: Uint8Array): Promise<Uint8Array> {
  const s = subtle();
  const key = await s.importKey('jwk', privateJwk, ES256_IMPORT, false, ['sign']);
  return new Uint8Array(await s.sign(ES256_SIGN, key, data));
}

/** Verify a RAW ES256 signature over `data` against a P-256 public JWK. Fail-closed on error. */
export async function es256VerifyRaw(
  publicJwk: RawSigningJwk,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  try {
    const s = subtle();
    const key = await s.importKey(
      'jwk',
      { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
      ES256_IMPORT,
      false,
      ['verify'],
    );
    return await s.verify(ES256_SIGN, key, signature, data);
  } catch {
    return false;
  }
}

/**
 * Bind a request to its `requestHash`: SHA-256 over `JCS({ method, params })`, emitted as the RFC
 * 9421 Content-Digest structured field `sha-256=:<base64>:` (chosen so the HTTP Message Signature
 * sibling can carry it verbatim, §8.3/§8.5).
 *
 * INPUT-SHAPE parity, OUTPUT-FORMAT difference: the JCS input mirrors the legacy hasher's
 * `{ method, params }` shape, so the underlying digest BYTES are identical — but the legacy hasher
 * ({@link computeCanonicalHashes}) emits `sha256:<hex>`, so the two STRINGS never compare equal.
 * A card proof is verified ONLY by the card verifier (which recomputes this exact form); do not
 * string-compare it against a legacy `sha256:<hex>` value — use {@link digestsEqual} to compare the
 * underlying digests across formats.
 */
export async function computeRequestHash(req: ToolRequest): Promise<string> {
  const params = stripParamsMeta(req.params);
  const canonicalRequest = { method: req.method, ...(params ? { params } : {}) };
  const digest = await sha256(
    encoder.encode(canonicalize(canonicalRequest as Parameters<typeof canonicalize>[0])),
  );
  return `sha-256=:${bytesToBase64(digest)}:`;
}

/**
 * The §8.3 pre-signing transformation: remove the `_meta` member of `params` before
 * canonicalizing. `_meta` is the transport-metadata carrier - it carries the proof itself, so it
 * can never be part of the signed material; hashing it verbatim on the verify side would make the
 * definition circular (the received `params._meta` contains the proof being verified). Only the
 * top-level `_meta` member is removed; nothing nested below other members is touched. Requests
 * without `params._meta` hash byte-identically to the untransformed shape.
 */
function stripParamsMeta(params: unknown): unknown {
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return params;
  if (!('_meta' in (params as Record<string, unknown>))) return params;
  const { _meta: _stripped, ...rest } = params as Record<string, unknown>;
  return rest;
}

/** Hex of the SHA-256 digest carried by a `sha-256=:<base64>:` (RFC 9421) or `sha256:<hex>` (legacy)
 *  string, or `null` if it is neither form. Lets integrators compare the two formats by digest. */
function digestHex(value: string): string | null {
  const rfc9421 = /^sha-256=:([A-Za-z0-9+/=]+):$/.exec(value.trim());
  if (rfc9421?.[1]) {
    return Array.from(base64ToBytes(rfc9421[1]), (b) => b.toString(16).padStart(2, '0')).join('');
  }
  const legacy = /^sha256:([0-9a-fA-F]+)$/.exec(value.trim());
  return legacy?.[1] ? legacy[1].toLowerCase() : null;
}

/**
 * True iff two request-hash strings carry the SAME SHA-256 digest, accepting EITHER the card's RFC
 * 9421 `sha-256=:<base64>:` form or the legacy `sha256:<hex>` form. The two forms are never
 * string-equal for the same digest, so cross-format integrators MUST compare with this, not `===`.
 */
export function digestsEqual(a: string, b: string): boolean {
  const ha = digestHex(a);
  const hb = digestHex(b);
  return ha !== null && ha === hb;
}

/** The COVERED claims (every proof field except `jws`) — the object the JWS actually signs. */
export function coveredClaims(meta: CardProofMeta): Record<string, unknown> {
  return {
    prf: meta.prf,
    alg: meta.alg,
    did: meta.did,
    kid: meta.kid,
    audience: meta.audience,
    nonce: meta.nonce,
    created: meta.created,
    expires: meta.expires,
    requestHash: meta.requestHash,
    ...(meta.cnf ? { cnf: meta.cnf } : {}),
  };
}

/** The JCS canonical bytes of the covered claims — the exact detached-JWS signing payload. */
export function canonicalPayloadBytes(meta: CardProofMeta): Uint8Array {
  return encoder.encode(canonicalize(coveredClaims(meta) as Parameters<typeof canonicalize>[0]));
}

/** Re-encode a base64url value (a JWS signature) as standard base64 (an RFC 9421 byte sequence). */
export function base64urlToBase64(b64url: string): string {
  return bytesToBase64(base64urlDecodeToBytes(b64url));
}
