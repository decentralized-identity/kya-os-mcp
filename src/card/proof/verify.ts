/**
 * KYA-OS Entity Card proof — VERIFY (`verifyCardProof`), fail-closed.
 *
 * Recompute EVERY binding a stateless `org.kya-os/proof@1` asserts and reject on the first thing
 * that does not hold. The signature only proves the proof is AUTHENTIC (signed by the holder of
 * `kid`); accountability requires binding that key to the accountable principal `did`:
 *
 *   1. `kid`'s DID part MUST equal `proof.did` (`kid.split('#')[0] === did`) — closes the
 *      forgeable-principal gap where a proof claims a victim `did` while `kid` points elsewhere;
 *   2. the resolved signing key MUST be a verificationMethod of `proof.did`, via the injected
 *      `resolveDidKeys` seam (RFC 7638 thumbprint membership) — closes a key that merely shares
 *      the DID's `kid` prefix but is not actually published by that DID.
 *
 * Plus: `audience` → the verifier, `requestHash` → THIS body, `nonce` → unseen, `created`/`expires`
 * → NOW (±skew), the detached JWS → the covered claims, and the `cnf.jkt` fusion
 * (`token.cnf.jkt === proof.cnf.jkt === thumbprint(resolve(kid))`). Any failure appends a reason;
 * `ok` is true iff there are none.
 */

import { calculateJwkThumbprint, flattenedVerify, importJWK } from 'jose';
import type { JWK } from 'jose';
import { base64urlDecodeToString, base64urlEncodeFromBytes } from '../../utils/base64.js';
import type { ToolRequest } from '../../proof/generator.js';
import type { ProofPublicJwk } from '../schema.js';
import { canonicalPayloadBytes, computeRequestHash } from './canonical.js';
import {
  CardProofMetaSchema,
  DEFAULT_SKEW_SEC,
  MAX_TTL_SEC,
  type CardProofMeta,
  type ProofAssurance,
  type ProofVerifyResult,
  type VerifyProofDeps,
} from './types.js';

/**
 * Verify an `org.kya-os/proof@1` against the request it should bind and the injected seams.
 * Fail-closed: returns `{ ok:false, reasons }` on any broken binding; on success returns the
 * derived assurance (`L3` on full cnf fusion, `L3-minus` without an AS `cnf`) and the principal.
 */
export async function verifyCardProof(
  proof: unknown,
  req: ToolRequest,
  deps: VerifyProofDeps,
): Promise<ProofVerifyResult> {
  const reasons: string[] = [];
  const parsed = CardProofMetaSchema.safeParse(proof);
  if (!parsed.success) return { ok: false, reasons: ['malformed_proof'] };
  const meta = parsed.data;

  if (meta.kid.split('#')[0] !== meta.did) reasons.push('kid_did_mismatch');

  // `resolveKey` (DID-key resolution, possibly a network fetch) and `computeRequestHash` (local JCS +
  // SHA-256) are INDEPENDENT — run them concurrently. Fail-closed semantics are unchanged: each still
  // appends its own reason. Caching the resolved key belongs at the injected `resolveKey` seam (the
  // consumer owns it); verifyCardProof stays a pure, stateless function — no cross-tenant global cache.
  const [key, computedHash] = await Promise.all([resolveKey(meta.kid, deps, reasons), computeRequestHash(req)]);
  if (key) await assertDidMembership(key, meta.did, deps, reasons);
  // Bind the declared alg to the resolved key type: an ES256 claim MUST carry a P-256 key, an EdDSA
  // claim an Ed25519 key. `alg` is a signed covered claim, but the KEY type is authoritative here —
  // this closes alg/key confusion. Gate the signature check on it so import always uses a matching alg.
  const algOk = key !== undefined && keyMatchesAlg(key, meta.alg);
  if (key && !algOk) reasons.push('alg_key_mismatch');

  if (meta.audience !== deps.expectedAudience) reasons.push('audience_mismatch');
  if (meta.requestHash !== computedHash) reasons.push('request_hash_mismatch');
  checkWindow(meta, deps, reasons);
  await consumeNonce(meta, deps, reasons);
  if (key && algOk && !(await verifyDetachedJws(meta, key))) reasons.push('invalid_signature');

  const warnings: string[] = [];
  let level: ProofAssurance = 'L3-minus';
  if (key) level = await checkCnfFusion(meta, key, deps, reasons, warnings);

  const ok = reasons.length === 0;
  const withWarnings = warnings.length > 0 ? { warnings } : {};
  return ok
    ? { ok, reasons, level, did: meta.did, ...withWarnings }
    : { ok, reasons, ...withWarnings };
}

/** Resolve the signing key for `kid`; fail-closed (records `key_unresolvable`) on throw. */
async function resolveKey(
  kid: string,
  deps: VerifyProofDeps,
  reasons: string[],
): Promise<ProofPublicJwk | undefined> {
  try {
    return await deps.resolveKey(kid);
  } catch {
    reasons.push('key_unresolvable');
    return undefined;
  }
}

/**
 * Cryptographically bind the signing key to `did`: it MUST be one of the DID document's
 * verification keys (RFC 7638 thumbprint membership), via the injected `resolveDidKeys` seam.
 * SECURE BY DEFAULT:
 *   - `resolveDidKeys` PRESENT → run the independent membership proof (always);
 *   - `resolveDidKeys` ABSENT → there is NO independent proof, so FAIL CLOSED
 *     (`did_membership_unverifiable`) unless the caller explicitly attests its `resolveKey` is
 *     authoritative via `trustResolveKeyAuthority` (dev/test or a trusted internal resolver).
 * Fail-closed on an unresolvable document.
 */
async function assertDidMembership(
  key: ProofPublicJwk,
  did: string,
  deps: VerifyProofDeps,
  reasons: string[],
): Promise<void> {
  if (!deps.resolveDidKeys) {
    // No membership seam: a minimal verifier must not silently trust an unbound key.
    if (!deps.trustResolveKeyAuthority) reasons.push('did_membership_unverifiable');
    return;
  }
  let didKeys: ProofPublicJwk[];
  try {
    didKeys = await deps.resolveDidKeys(did);
  } catch {
    reasons.push('did_keys_unresolvable');
    return;
  }
  let keyJkt: string;
  let published: string[];
  try {
    keyJkt = await thumbprint(key);
    published = await Promise.all(didKeys.map(thumbprint));
  } catch {
    // A structurally-typed but invalid JWK from the seam (jose throws) must fail CLOSED with a
    // reason, never as an unhandled rejection out of verifyCardProof — matches the seam-catch above.
    reasons.push('thumbprint_computation_failed');
    return;
  }
  if (!published.includes(keyJkt)) reasons.push('kid_not_in_did_document');
}

/**
 * Atomically CONSUME the nonce via the injected `consumeNonceIfFresh` replay seam (test-AND-set —
 * SPEC §12.2). A `false` return is a replay (`nonce_replayed`). When the seam is not supplied there
 * is no replay defense to run, so we FAIL CLOSED (`nonce_seam_missing`) rather than skip the check.
 */
async function consumeNonce(
  meta: CardProofMeta,
  deps: VerifyProofDeps,
  reasons: string[],
): Promise<void> {
  const consume = deps.consumeNonceIfFresh;
  if (!consume) {
    reasons.push('nonce_seam_missing');
    return;
  }
  if (!(await consume(meta.nonce, meta.did))) reasons.push('nonce_replayed');
}

/** Enforce the created/expires window: sane bounds, capped TTL, and ±skew freshness. */
function checkWindow(meta: CardProofMeta, deps: VerifyProofDeps, reasons: string[]): void {
  const skew = deps.skewSec ?? DEFAULT_SKEW_SEC;
  const now = Math.floor((deps.now?.() ?? Date.now()) / 1000);
  if (meta.expires <= meta.created) reasons.push('invalid_window');
  if (meta.expires - meta.created > MAX_TTL_SEC) reasons.push('ttl_too_long');
  if (meta.created > now + skew) reasons.push('created_in_future');
  if (meta.expires < now - skew) reasons.push('expired');
}

/**
 * Verify the DETACHED JWS over the reconstructed covered claims. The header is NOT trusted: its `alg`
 * MUST equal the (schema-allow-listed `EdDSA`|`ES256`, and signed) `meta.alg`, and its `kid` MUST equal
 * `meta.kid`. Verification is PINNED to that single alg — never negotiated. The payload is recomputed
 * from the meta (JCS), so any tampered covered field (including `alg`) yields a different signing input.
 */
async function verifyDetachedJws(meta: CardProofMeta, key: ProofPublicJwk): Promise<boolean> {
  const parts = meta.jws.split('.');
  if (parts.length !== 3 || parts[1] !== '') return false;
  const [protectedB64, , signatureB64] = parts;
  const header = decodeHeader(protectedB64);
  if (!header || header.alg !== meta.alg || header.kid !== meta.kid) return false;
  try {
    const pub = await importJWK(toJwk(key), meta.alg);
    await flattenedVerify(
      {
        protected: protectedB64,
        payload: base64urlEncodeFromBytes(canonicalPayloadBytes(meta)),
        signature: signatureB64!,
      },
      pub,
      { algorithms: [meta.alg] },
    );
    return true;
  } catch {
    return false;
  }
}

/** True iff the resolved key's type is the one the declared `alg` requires (anti-confusion). */
function keyMatchesAlg(key: ProofPublicJwk, alg: 'EdDSA' | 'ES256'): boolean {
  return alg === 'ES256'
    ? key.kty === 'EC' && key.crv === 'P-256'
    : key.kty === 'OKP' && key.crv === 'Ed25519';
}

/**
 * The `cnf.jkt` fusion (SPEC §8): a present `cnf.jkt` MUST equal the signing key's thumbprint,
 * and when the AS supplies a token `cnf.jkt` the three MUST fuse
 * (`token.cnf.jkt === proof.cnf.jkt === thumbprint(resolve(kid))`) for L3. No token `cnf` degrades
 * to L3-minus; a token `cnf` with no proof `cnf` is a downgrade attack and fails closed.
 */
async function checkCnfFusion(
  meta: CardProofMeta,
  key: ProofPublicJwk,
  deps: VerifyProofDeps,
  reasons: string[],
  warnings: string[],
): Promise<ProofAssurance> {
  let keyJkt: string;
  try {
    keyJkt = await thumbprint(key);
  } catch {
    // Same fail-closed contract as assertDidMembership: an invalid JWK denies with a reason.
    reasons.push('thumbprint_computation_failed');
    return 'L3-minus';
  }
  if (meta.cnf && meta.cnf.jkt !== keyJkt) reasons.push('cnf_key_mismatch');
  if (deps.tokenCnfJkt === undefined) {
    // No token cnf.jkt was supplied, so there is nothing to fuse against and assurance is L3-minus.
    // If the client nonetheless PRESENTED a sender-constraint (`cnf`), the proof was capable of L3 —
    // it degraded only because `tokenCnfJkt` was not wired. That is a valid L3-minus proof, not a
    // failure, so it is a warning (not a reason): it lets an integrator who intended L3 notice the
    // silent downgrade rather than assume token-theft resistance they are not actually getting.
    if (meta.cnf) warnings.push('cnf_present_but_token_unfused');
    return 'L3-minus';
  }
  if (!meta.cnf) {
    reasons.push('cnf_required_by_token');
    return 'L3-minus';
  }
  if (meta.cnf.jkt !== deps.tokenCnfJkt) {
    reasons.push('cnf_token_mismatch');
    return 'L3-minus';
  }
  return meta.cnf.jkt === keyJkt ? 'L3' : 'L3-minus';
}

/** Decode a base64url JWS protected header to `{ alg, kid }`, or null on malformed input. */
function decodeHeader(b64: string | undefined): { alg?: string; kid?: string } | null {
  if (!b64) return null;
  try {
    return JSON.parse(base64urlDecodeToString(b64)) as { alg?: string; kid?: string };
  } catch {
    return null;
  }
}

/** The RFC 7638 thumbprint of an Ed25519 public JWK (canonical `{crv,kty,x}` only). */
function thumbprint(key: ProofPublicJwk): Promise<string> {
  return calculateJwkThumbprint(toJwk(key), 'sha256');
}

/** Project a proof public JWK to the canonical `jose` JWK (drop `kid`/`use`; EC carries `x`+`y`). */
function toJwk(key: ProofPublicJwk): JWK {
  return key.kty === 'EC'
    ? { kty: 'EC', crv: 'P-256', x: key.x, y: key.y }
    : { kty: 'OKP', crv: 'Ed25519', x: key.x };
}
