/**
 * KYA-OS Entity Card proof — VERIFY (`verifyCardProof`), fail-closed.
 *
 * Recompute EVERY binding a stateless `org.kya-os/proof.v1` asserts and reject on the first thing
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
 *
 * What the proof's own claims decide is checked first and needs no key: whose key it names, its
 * audience, the request it signs and its window. A proof names its key before anything has verified
 * it, and resolving one may be a network read of a document the caller chose, so a proof its claims
 * refuse is answered with those reasons alone: no key is read for it and no nonce is spent.
 *
 * A proof also states, in the JWS protected header its signature covers, the delegation its call
 * presents (SPEC.md §7.8). The statement is read from the header that verified and returned for the
 * delegation check to hold the chain to; one that is neither a credential digest nor `none` is
 * refused here.
 */

import { calculateJwkThumbprint, flattenedVerify, importJWK } from 'jose';
import type { JWK } from 'jose';
import { statedDelegationOf, type StatedDelegation } from '../../delegation/stated-delegation.js';
import { answerWithinDeadline, dependencyTimeout } from '../../utils/deadline.js';
import { base64urlDecodeToString, base64urlEncodeFromBytes } from '../../utils/base64.js';
import type { ToolRequest } from '../../proof/generator.js';
import { nonceRetentionSeconds } from '../../providers/nonce-retention.js';
import { isSmallOrderEd25519CryptoKey } from '../../utils/ed25519-public-key.js';
import { isRecord } from '../../utils/guards.js';
import type { ProofPublicJwk } from '../schema.js';
import { canonicalPayloadBytes, requestHashMatches } from './canonical.js';
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
 * Verify an `org.kya-os/proof.v1` against the request it should bind and the injected seams.
 * Fail-closed: returns `{ ok:false, reasons }` on any broken binding; on success returns the
 * derived assurance (`L3` on full cnf fusion, `L3-minus` without an AS `cnf`) and the principal.
 * Rejects with a `TypeError` for a `dependencyTimeoutMs` that is not a number of milliseconds it
 * can wait.
 */
export async function verifyCardProof(
  proof: unknown,
  req: ToolRequest,
  deps: VerifyProofDeps,
): Promise<ProofVerifyResult> {
  const timeoutMs = dependencyTimeout(deps.dependencyTimeoutMs);
  const parsed = CardProofMetaSchema.safeParse(proof);
  if (!parsed.success) return refused(['malformed_proof']);
  const meta = parsed.data;

  // Nothing has verified the key a proof names, so none is read for a proof its own claims refuse.
  const reasons = await claimRefusals(meta, req, deps);
  if (reasons.length > 0) return refused(reasons);

  // Caching the resolved key belongs at the injected `resolveKey` seam (the consumer owns it);
  // verifyCardProof stays a pure, stateless function, with no cross-tenant global cache.
  const key = await resolveKey(meta.kid, deps, reasons, timeoutMs);
  if (key) await assertDidMembership(key, meta.did, deps, reasons, timeoutMs);
  // Bind the declared alg to the resolved key type: an ES256 claim MUST carry a P-256 key, an EdDSA
  // claim an Ed25519 key. `alg` is a signed covered claim, but the KEY type is authoritative here —
  // this closes alg/key confusion. Gate the signature check on it so import always uses a matching alg.
  const algOk = key !== undefined && keyMatchesAlg(key, meta.alg);
  if (key && !algOk) reasons.push('alg_key_mismatch');

  const header = key && algOk ? await verifiedHeader(meta, key) : undefined;
  if (key && algOk && header === undefined) reasons.push('invalid_signature');
  // What the proof states of its delegation, from the header the signature just verified over.
  const statedDelegation: StatedDelegation = statedDelegationOf(header);
  if (statedDelegation.kind === 'malformed') reasons.push('delegation_statement_malformed');

  const warnings: string[] = [];
  let level: ProofAssurance = 'L3-minus';
  if (key) level = await checkCnfFusion(meta, key, deps, reasons, warnings);

  // Authenticate every binding before claiming state. The shared cache must
  // atomically decide which validated request, if any, first admits this nonce.
  if (reasons.length === 0) await consumeNonce(meta, deps, reasons, timeoutMs);

  const ok = reasons.length === 0;
  const withWarnings = warnings.length > 0 ? { warnings } : {};
  return ok
    ? { ok, reasons, level, did: meta.did, ...withWarnings, statedDelegation }
    : { ok, reasons, ...withWarnings };
}

/** A proof refused before any key is read. Its reasons are its codes. */
function refused(reasons: string[]): ProofVerifyResult {
  return { ok: false, reasons };
}

/**
 * Why a proof's own claims refuse it, decided with no key and no seam beside the clock: that its
 * `kid` is a key of its `did`, its audience, the request it signs and its window.
 */
async function claimRefusals(meta: CardProofMeta, req: ToolRequest, deps: VerifyProofDeps): Promise<string[]> {
  const reasons: string[] = [];
  if (meta.kid.split('#')[0] !== meta.did) reasons.push('kid_did_mismatch');
  if (meta.audience !== deps.expectedAudience) reasons.push('audience_mismatch');
  if (!(await requestHashMatches(meta.requestHash, req))) reasons.push('request_hash_mismatch');
  checkWindow(meta, deps, reasons);
  return reasons;
}

/** Resolve the signing key for `kid`; fail-closed (records `key_unresolvable`) on throw. */
async function resolveKey(
  kid: string,
  deps: VerifyProofDeps,
  reasons: string[],
  timeoutMs: number,
): Promise<ProofPublicJwk | undefined> {
  try {
    return await answerWithinDeadline('the key resolver', () => deps.resolveKey(kid), timeoutMs);
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
  timeoutMs: number,
): Promise<void> {
  if (!deps.resolveDidKeys) {
    // No membership seam: a minimal verifier must not silently trust an unbound key.
    if (!deps.trustResolveKeyAuthority) reasons.push('did_membership_unverifiable');
    return;
  }
  let didKeys: ProofPublicJwk[];
  try {
    const resolveDidKeys = deps.resolveDidKeys;
    didKeys = await answerWithinDeadline('the DID key resolver', () => resolveDidKeys(did), timeoutMs);
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
  timeoutMs: number,
): Promise<void> {
  const consume = deps.consumeNonceIfFresh;
  if (!consume) {
    reasons.push('nonce_seam_missing');
    return;
  }
  try {
    const minTtlSec = nonceRetentionSeconds(
      1,
      meta.expires + (deps.skewSec ?? DEFAULT_SKEW_SEC),
      deps.now?.() ?? Date.now(),
    );
    const fresh = await answerWithinDeadline('the nonce cache', () => consume(meta.nonce, meta.did, minTtlSec), timeoutMs);
    if (fresh !== true) reasons.push('nonce_replayed');
  } catch {
    reasons.push('nonce_cache_unavailable');
  }
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
 * Verify the DETACHED JWS over the reconstructed covered claims, and return the protected header it
 * verified over, or `undefined` when it does not verify. The header is NOT trusted: its `alg`
 * MUST equal the (schema-allow-listed `EdDSA`|`ES256`, and signed) `meta.alg`, and its `kid` MUST equal
 * `meta.kid`. Verification is PINNED to that single alg — never negotiated. The payload is recomputed
 * from the meta (JCS), so any tampered covered field (including `alg`) yields a different signing input.
 */
async function verifiedHeader(meta: CardProofMeta, key: ProofPublicJwk): Promise<Record<string, unknown> | undefined> {
  const parts = meta.jws.split('.');
  if (parts.length !== 3 || parts[1] !== '') return undefined;
  const [protectedB64, , signatureB64] = parts;
  const header = decodeHeader(protectedB64);
  if (!header || header.alg !== meta.alg || header.kid !== meta.kid) return undefined;
  try {
    const pub = await importJWK(toJwk(key), meta.alg);
    // jose verifies under a small-order Ed25519 key, where one signature fits every payload.
    if (await isSmallOrderEd25519CryptoKey(pub)) return undefined;
    await flattenedVerify(
      {
        protected: protectedB64,
        payload: base64urlEncodeFromBytes(canonicalPayloadBytes(meta)),
        signature: signatureB64!,
      },
      pub,
      { algorithms: [meta.alg] },
    );
    return header;
  } catch {
    return undefined;
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

/** Decode a base64url JWS protected header to its JSON object, or null on malformed input. */
function decodeHeader(b64: string | undefined): Record<string, unknown> | null {
  if (!b64) return null;
  try {
    const header: unknown = JSON.parse(base64urlDecodeToString(b64));
    return isRecord(header) ? header : null;
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
