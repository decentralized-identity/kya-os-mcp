/**
 * KYA-OS Entity Card proof — MINT (`buildCardProof`).
 *
 * Mint a stateless, sender-constrained `org.kya-os/proof.v1` for one request and return it under the
 * card proof's OWN `_meta` key ({@link KYA_OS_CARD_PROOF_META_KEY} = `org.kya-os/request-proof`), distinct
 * from the legacy session proof's `org.kya-os/proof` so the two coexist. The proof binds:
 * `requestHash` → THIS body (JCS), `audience` → THIS recipient, `nonce` + `created`/`expires` → NOW,
 * `kid` → the signing DID key, and (optionally) `cnf.jkt` → the token's RFC 9449 sender-constraint.
 * Its JWS protected header states the delegation the call presents (SPEC.md §7.8), which rides
 * beside the proof in `_meta` and outside `requestHash`.
 * Crypto is entirely inside the injected {@link ProofSigner}.
 */

import { statementParameters } from '../../delegation/stated-delegation.js';
import type { ToolRequest } from '../../proof/generator.js';
import { jwsProtectedHeader } from '../../utils/crypto-service.js';
import { webCryptoSha256 } from '../../utils/domain-digest.js';
import { isRecord } from '../../utils/guards.js';
import { warnOncePerProcess } from '../../utils/warn-once.js';
import { KYA_OS_DELEGATION_CHAIN_META_KEY } from '../carried-chain.js';
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

/** `Symbol.for` key, so every copy of the package a process loads warns once between them. */
const SIGNER_WROTE_NO_STATEMENT_WARNED = Symbol.for('kya-os.warned.card-proof-signer-wrote-no-delegation');

/**
 * The delegation `req` sends: the leaf of the chain in its `params._meta`, `undefined` when it holds
 * none, and whatever the member holds when that is not a chain with a leaf.
 */
function sentDelegation(req: ToolRequest): unknown {
  const meta = isRecord(req.params) ? req.params._meta : undefined;
  const chain = isRecord(meta) ? meta[KYA_OS_DELEGATION_CHAIN_META_KEY] : undefined;
  return Array.isArray(chain) && chain.length > 0 ? chain[chain.length - 1] : chain;
}

/** Whether the protected header of `jws` holds every one of `parameters`, as given. */
function wrote(jws: string, parameters: Readonly<Record<string, string>>): boolean {
  try {
    const header = jwsProtectedHeader(jws);
    return Object.entries(parameters).every(([name, value]) => Object.hasOwn(header, name) && header[name] === value);
  } catch {
    return false;
  }
}

/**
 * Mint an `org.kya-os/proof.v1` for `req`, signed by `signer`, bound to `ctx`. Returns the proof
 * keyed by {@link KYA_OS_CARD_PROOF_META_KEY} so it can be spread straight into an MCP request
 * `_meta`. The `cnf.jkt` is `ctx.cnfJkt` when given, else the signer's own key thumbprint, else
 * omitted (an L3-minus proof — still bound by request + audience + nonce + key).
 *
 * The proof states the delegation the call presents (SPEC.md §7.8): `ctx.delegation`, or else the
 * leaf of the chain `req` holds in `params._meta`, or `'none'`. A signer of the caller's own that
 * does not write the protected header parameters it is handed makes a proof that states nothing:
 * that throws when `ctx.delegation` asked for the statement, and warns once otherwise.
 *
 * @throws `NoSignedFormError` for a `ctx.delegation` with no signed form (SPEC.md §7.8)
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

  const stated = await statementParameters(ctx.delegation, sentDelegation(req), webCryptoSha256);
  const jws = await signer.sign(canonicalPayloadBytes(unsigned), stated);
  if (!wrote(jws, stated)) {
    const unwritten = 'the signer did not write the protected header parameters it was handed, so the proof does not state its delegation';
    if (ctx.delegation !== undefined) throw new Error(`buildCardProof: ${unwritten}`);
    warnOncePerProcess(
      SIGNER_WROTE_NO_STATEMENT_WARNED,
      `[kya-os] buildCardProof: ${unwritten} (SPEC.md §7.8). ` +
        'A ProofSigner now takes them as the second argument of sign(); a verifier that requires the statement refuses this proof.',
    );
  }
  const signed: CardProofMeta = { ...unsigned, jws };

  // Dual carrier: when the signer exposes a raw-signature seam, ALSO sign the RFC 9421 base so the
  // HTTP Message Signature sibling is genuinely cross-verifiable against the DID key. Absent it,
  // the proof ships JWS-only and the sibling degrades away (never a failure).
  if (!signer.signRaw) return { [KYA_OS_CARD_PROOF_META_KEY]: signed };
  const httpSig = await signer.signRaw(httpSignatureBaseBytes(signed));
  return { [KYA_OS_CARD_PROOF_META_KEY]: { ...signed, httpSig } };
}
