/**
 * KYA-OS Entity Card proof — MINT (`buildCardProof`).
 *
 * Mint a stateless, sender-constrained `org.kya-os/proof@1` for one request and return it under the
 * card proof's OWN `_meta` key ({@link KYA_OS_CARD_PROOF_META_KEY} = `org.kya-os/proof.v1`), distinct
 * from the legacy session proof's `org.kya-os/proof` so the two coexist. The proof binds:
 * `requestHash` → THIS body (JCS), `audience` → THIS recipient, `nonce` + `created`/`expires` → NOW,
 * `kid` → the signing DID key, and (optionally) `cnf.jkt` → the token's RFC 9449 sender-constraint.
 * Crypto is entirely inside the injected {@link ProofSigner}.
 */

import type { ToolRequest } from '../../proof/generator.js';
import { canonicalPayloadBytes, computeRequestHash } from './canonical.js';
import { httpSignatureBaseBytes } from './http-sig.js';
import {
  DEFAULT_TTL_SEC,
  KYA_OS_CARD_PROOF_META_KEY,
  MAX_TTL_SEC,
  PROOF_PROFILE_V1,
  type BuildProofContext,
  type CardProofMeta,
  type ProofSigner,
} from './types.js';

/**
 * Mint an `org.kya-os/proof@1` for `req`, signed by `signer`, bound to `ctx`. Returns the proof
 * keyed by {@link KYA_OS_CARD_PROOF_META_KEY} so it can be spread straight into an MCP request
 * `_meta`. The `cnf.jkt` is `ctx.cnfJkt` when given, else the signer's own key thumbprint, else
 * omitted (an L3-minus proof — still bound by request + audience + nonce + key).
 */
export async function buildCardProof(
  req: ToolRequest,
  signer: ProofSigner,
  ctx: BuildProofContext,
): Promise<{ [KYA_OS_CARD_PROOF_META_KEY]: CardProofMeta }> {
  const created = Math.floor((ctx.now?.() ?? Date.now()) / 1000);
  const ttlSec = ctx.ttlSec ?? DEFAULT_TTL_SEC;
  // Fail FAST at mint: a proof longer than the profile cap is guaranteed to be rejected by the
  // verifier (ttl_too_long), so surface the caller's error here rather than emit a doomed proof.
  // The verifier remains the authoritative enforcer; both reference the one shared MAX_TTL_SEC.
  if (ttlSec > MAX_TTL_SEC) {
    throw new Error(`buildCardProof: ttlSec ${ttlSec} exceeds the profile cap of ${MAX_TTL_SEC}s — mint a shorter-lived proof`);
  }
  const expires = created + ttlSec;
  const requestHash = await computeRequestHash(req);
  const jkt = ctx.cnfJkt ?? signer.jkt;

  const unsigned: CardProofMeta = {
    prf: PROOF_PROFILE_V1,
    alg: signer.alg ?? 'EdDSA',
    did: signer.did,
    kid: signer.kid,
    audience: ctx.audience,
    nonce: ctx.nonce,
    created,
    expires,
    requestHash,
    ...(jkt !== undefined ? { cnf: { jkt } } : {}),
    jws: '',
  };

  const jws = await signer.sign(canonicalPayloadBytes(unsigned));
  const signed: CardProofMeta = { ...unsigned, jws };

  // Dual carrier: when the signer exposes a raw-signature seam, ALSO sign the RFC 9421 base so the
  // HTTP Message Signature sibling is genuinely cross-verifiable against the DID key. Absent it,
  // the proof ships JWS-only and the sibling degrades away (never a failure).
  if (!signer.signRaw) return { [KYA_OS_CARD_PROOF_META_KEY]: signed };
  const httpSig = await signer.signRaw(httpSignatureBaseBytes(signed));
  return { [KYA_OS_CARD_PROOF_META_KEY]: { ...signed, httpSig } };
}
