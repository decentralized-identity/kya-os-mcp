/**
 * KYA-OS Entity Card proof — the RFC 9421 HTTP Message Signature sibling (DUAL carrier).
 *
 * The stateless proof carries TWO signatures by ONE DID key over ONE semantic set: the detached
 * JWS in `_meta` (canonical, for JSON-RPC / stdio) and this RFC 9421 sibling for HTTP verifiers
 * that already ship (SEP-1960, Cloudflare Web Bot Auth). A JWS signature also covers its protected
 * header, so its bytes can NEVER satisfy a stock 9421 verifier reconstructing a bare signature
 * base — the two carriers therefore require two signatures. `httpSig` (minted by the signer's
 * `signRaw` seam) is a RAW EdDSA signature over exactly the base {@link httpSignatureBase} exposes,
 * so a stock 9421 verifier reconstructs that base and verifies `httpSig` against the resolved DID
 * key with zero new code. If a signer omits `signRaw`, the proof has no `httpSig` and the sibling
 * simply degrades away (the JWS carrier still verifies).
 *
 * Covered set (the full semantic binding): `content-digest` (the `requestHash`, itself SHA-256 of
 * `JCS({ method, params })` — so the request method+params are bound here), `kya-audience`,
 * `kya-nonce`, `kya-cnf` when a `cnf` is present, plus `created`/`expires`/`keyid`/`alg` in
 * `@signature-params`. Every covered value is reconstructable by a stock verifier from the message
 * headers + `Signature-Input`, which is what keeps the sibling independently verifiable.
 */

import { base64urlDecodeToBytes } from '../../utils/base64.js';
import { base64urlToBase64, ed25519VerifyRaw, es256VerifyRaw } from './canonical.js';
import type { ProofPublicJwk } from '../schema.js';
import type { CardProofMeta } from './types.js';

const encoder = new TextEncoder();

/** The signature label under which the KYA-OS covered components are grouped. */
export const HTTP_SIG_LABEL = 'kyaos';

/**
 * The RFC 9421 headers projected from a proof (a co-normative carrier, not a re-sign). Beyond the
 * `Signature-Input`/`Signature` pair, every NON-`@` covered component is emitted as its own HTTP
 * field so a stock verifier can resolve it from the message alone: `Content-Digest` (`content-digest`),
 * `Kya-Audience` (`kya-audience`), `Kya-Nonce` (`kya-nonce`), and `Kya-Cnf` (`kya-cnf`, only when the
 * proof carries a `cnf`). Each field value is BYTE-IDENTICAL to the corresponding {@link httpSignatureBase}
 * line so reconstruction from the wire yields the exact base `httpSig` was signed over.
 */
export interface HttpMessageSignature {
  'Content-Digest': string;
  'Kya-Audience': string;
  'Kya-Nonce': string;
  'Kya-Cnf'?: string;
  'Signature-Input': string;
  Signature: string;
}

/** The RFC 9421 covered-component list — includes `kya-cnf` only when the proof carries a `cnf`. */
function coveredComponents(proof: CardProofMeta): string {
  const comps = ['"content-digest"', '"kya-audience"', '"kya-nonce"'];
  if (proof.cnf) comps.push('"kya-cnf"');
  return `(${comps.join(' ')})`;
}

/** The `;created=…;expires=…;keyid=…;alg=…` parameter tail shared by input + signature base. The
 *  `alg` label is the RFC 9421 name for the proof's algorithm (`ed25519` or `ecdsa-p256-sha256`). */
function sigParams(proof: CardProofMeta): string {
  const label = proof.alg === 'ES256' ? 'ecdsa-p256-sha256' : 'ed25519';
  return `created=${proof.created};expires=${proof.expires};keyid="${proof.kid}";alg="${label}"`;
}

/**
 * The RFC 9421 signature base — the EXACT string a stock 9421 verifier reconstructs and the exact
 * bytes `httpSig` signs. Deterministic and self-contained from the proof, so both the minter and a
 * third-party verifier derive an identical base.
 */
export function httpSignatureBase(proof: CardProofMeta): string {
  const lines = [
    `"content-digest": ${proof.requestHash}`,
    `"kya-audience": ${proof.audience}`,
    `"kya-nonce": ${proof.nonce}`,
  ];
  if (proof.cnf) lines.push(`"kya-cnf": ${proof.cnf.jkt}`);
  lines.push(`"@signature-params": ${coveredComponents(proof)};${sigParams(proof)}`);
  return lines.join('\n');
}

/** The UTF-8 bytes of {@link httpSignatureBase} — the payload the `signRaw` seam signs at mint. */
export function httpSignatureBaseBytes(proof: CardProofMeta): Uint8Array {
  return encoder.encode(httpSignatureBase(proof));
}

/**
 * Project a minted `org.kya-os/proof.v1` into its RFC 9421 header set. Emits EVERY covered
 * component as a real HTTP field — `Content-Digest`/`Kya-Audience`/`Kya-Nonce` (and `Kya-Cnf`
 * when a `cnf` is present), each byte-identical to its {@link httpSignatureBase} line — plus
 * `Signature-Input` (the covered-component list + params) and `Signature` (the RAW `httpSig` as a
 * base64 byte sequence). Because the message now carries every field the base names, a stock 9421
 * verifier resolves and reconstructs the base from the wire alone. Throws when the proof has no
 * `httpSig` (minted without a `signRaw` seam): there is no cross-verifiable sibling to project, and
 * emitting the JWS bytes here would be silently unverifiable.
 */
export function toHttpMessageSignature(proof: CardProofMeta): HttpMessageSignature {
  if (!proof.httpSig) {
    throw new Error('card/proof: proof carries no httpSig; mint with a signRaw-capable signer');
  }
  const headers: HttpMessageSignature = {
    'Content-Digest': proof.requestHash,
    'Kya-Audience': proof.audience,
    'Kya-Nonce': proof.nonce,
    'Signature-Input': `${HTTP_SIG_LABEL}=${coveredComponents(proof)};${sigParams(proof)}`,
    Signature: `${HTTP_SIG_LABEL}=:${base64urlToBase64(proof.httpSig)}:`,
  };
  if (proof.cnf) headers['Kya-Cnf'] = proof.cnf.jkt;
  return headers;
}

/**
 * Verify the sibling exactly as a stock RFC 9421 verifier would: reconstruct {@link httpSignatureBase}
 * and check the RAW `httpSig` against `key` (the resolved DID verification key). Fail-closed —
 * returns `false` when the proof carries no `httpSig` or the signature does not verify.
 *
 * CONTRACT: dispatches on the KEY type (P-256 → `ecdsa-p256-sha256`, Ed25519 → `ed25519`), NOT on
 * `proof.alg`. It ASSUMES the caller has already bound `proof.alg` to the key type (the
 * `alg_key_mismatch` check in `verify.ts`); call it standalone only after that binding holds.
 */
export async function verifyHttpSignature(
  proof: CardProofMeta,
  key: ProofPublicJwk,
): Promise<boolean> {
  if (!proof.httpSig) return false;
  const sig = base64urlDecodeToBytes(proof.httpSig);
  const base = httpSignatureBaseBytes(proof);
  // Dispatch on the KEY type (authoritative): a P-256 key verifies the ecdsa-p256-sha256 sibling,
  // an Ed25519 key the ed25519 sibling. verify.ts has already bound proof.alg to this key type.
  return key.kty === 'EC' ? es256VerifyRaw(key, sig, base) : ed25519VerifyRaw(key, sig, base);
}
